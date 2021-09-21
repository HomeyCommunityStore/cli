import inquirer from 'inquirer';
import {cwd} from 'process';
import tar from 'tar';
import crypto from 'crypto';
import fs from 'fs-extra';
import AWS from 'aws-sdk';
import path from 'path';
import mime from 'mime-types';
import keytar from 'keytar';
import yargs from 'yargs';
import slash from 'slash';
import aws4 from 'aws4';
import axios from 'axios';
import {exec} from 'child_process';
import Amplify, {Auth, API} from 'aws-amplify';
import awsmobile from './aws-exports';
import {
  getHCSAccount,
  KEYTAR_SERVICES,
  setCredentials,
  getFiles,
  maxFileSizeExceeded,
  logoutHCSAccounts,
  log,
  cleanUp,
  error
} from './utils';
import homey from 'homey';
import NpmCommands from 'homey/lib/NpmCommands';
import {getAppLocales} from 'homey-lib';
import {CONSTANT} from './constants';

Amplify.configure(awsmobile);

function parseArgumentsIntoOptions() {
  return yargs
    .usage('Usage: hcs <command> [options]')
    .command('build', 'Create a tar.gz file for the app', (yargs) => {
      return yargs.option('latest', {
        type: 'boolean',
        description: 'Version will be replaced by \'latest\' instead of what is in the app.json. Do NOT use this unless you know what you are doing!'
      });
    }, build)
    .command('publish', 'Build the app and upload it to the Homey Community Store', (yargs) => {
      return yargs.option('force', {
        type: 'boolean',
        description: 'CAUTION: This will override the version if it already exists in the database!'
      }).option('keep', {
        type: 'boolean',
        description: 'Prevents removal of the tar.gz file.'
      }).option('key', {
        type: 'string',
        description: 'AWS key'
      }).option('secret', {
        type: 'string',
        description: 'AWS secret'
      });
    }, publish)
    .command('logout', 'Remove all credentials', (yargs) => {
      return yargs;
    }, logout)
    .command('login', 'Login to HCS', (yargs) => {
      return yargs;
    }, login)
    .command('upload', 'Publish app to HCS', (yargs) => {
      return yargs;
    }, upload)
    .help()
    .demandCommand(1, 'You need to enter at least one command')
    .argv;
}

async function promptForAccessKeyId() {
  const questions = [];
  questions.push({
    type: 'input',
    name: 'accessKeyId',
    message: 'Please provide your access key id'
  });
  const answers = await inquirer.prompt(questions);
  return answers.accessKeyId;
}

async function promptForAccessKeySecret() {
  const questions = [];
  questions.push({
    type: 'input',
    name: 'accessKeySecret',
    message: 'Please provide your access key secret'
  });
  const answers = await inquirer.prompt(questions);
  return answers.accessKeySecret;
}

function determineCategory(appInfo) {
  if (!appInfo.category) {
    return ['general'];
  }
  return Array.isArray(appInfo.category) ? appInfo.category : [appInfo.category];
}

function pruneDev() {
  return new Promise((resolve) => {
    log.debug('Pruning development dependencies');
    exec('npm prune --production', (err, stdout, stderr) => {
      log.debug('Finished pruning development dependencies');
      resolve();
    });
  });
}

async function listModules() {
  try {
    const {err, stdout} = await exec('npm list -prod', {cwd: cwd()});
    return true;
  } catch (err) {
    return false;
  }
}

function createTar(appInfo, argv) {
  log.debug('Process for creating the tar.gz file');
  return new Promise(async (resolve, reject) => {
    let version = `v${appInfo.version}`;
    if (argv.latest) {
      version = 'latest';
    }
    const tarFile = `${appInfo.id}-${version}.tar.gz`;
    log.debug(`Filename determined: '${tarFile}'`);
    await pruneDev();
    tar.c({
      gzip: true,
      file: tarFile,
      filter: (path, stats) => {
        if (!path.includes('node_modules')) {
          if (stats.isFile() && path.startsWith('.')) {
            return false;
          }
          if (stats.isFile() && path.includes(tarFile)) {
            return false;
          }
        }
        return true;
      }
    }, [`./`]).then((_result) => {
      const hash = crypto.createHash('sha1');
      const readStream = fs.createReadStream(`${cwd()}/${tarFile}`);
      readStream.on('error', reject);
      readStream.on('data', chunk => hash.update(chunk));
      readStream.on('end', () => resolve({hash: hash.digest('hex'), filename: tarFile}));
    }, (error) => {
      reject(error);
    });
  });
}

function getI18nDescriptions() {
  const lang = {};
  fs.readdirSync(`${cwd()}/`).forEach((path) => {
    if (path.toLowerCase() === 'readme.txt') {
      lang.en = fs.readFileSync(`${cwd()}/${path}`, 'utf8');
    } else if (path.toLowerCase().includes('readme') && path.toLowerCase().endsWith('.txt')) {
      const language = path.toLowerCase().split('.')[1];
      lang[language] = fs.readFileSync(`${cwd()}/${path}`, 'utf8');
    }
  });
  if (Object.keys(lang).length < 1) {
    fs.readdirSync(`${cwd()}/`).forEach((path) => {
      if (path.toLowerCase() === 'readme.md') {
        lang.en = fs.readFileSync(`${cwd()}/${path}`, 'utf8');
      } else if (path.toLowerCase().includes('readme') && path.toLowerCase().endsWith('.md')) {
        const language = path.toLowerCase().split('.')[1];
        lang[language] = fs.readFileSync(`${cwd()}/${path}`, 'utf8');
      }
    });
  }

  return lang;
}

export async function cli(args) {
  parseArgumentsIntoOptions(args);
}

async function uploadToS3(s3Path, bucketName, root) {
  return new Promise(async resolve => {
    log.debug('Upload assets to S3');
    let s3 = new AWS.S3();

    const overall = [];

    async function walkSync(currentDirPath, callback) {
      const promises = fs.readdirSync(currentDirPath).map((name) => {
        return new Promise(async (resolveMap) => {
          const filePath = path.join(currentDirPath, name);
          const stat = fs.statSync(filePath);
          if (stat.isFile()) {
            await callback(filePath, stat);
            resolveMap();
          } else if (stat.isDirectory()) {
            await walkSync(filePath, callback).catch(console.warn);
            resolveMap();
          }
        });
      });
      overall.push(...promises);
    }

    await walkSync(s3Path, (filePath, _stat) => {
      return new Promise(async (resolveWalk, rejectWalk) => {
        const bucketPath = filePath;
        const key = slash(root + bucketPath.split(s3Path)[1]).replace(/\\/g, '/');
        if (!['.svg', '.png', '.jpeg', '.jpg', '.gz'].includes(path.extname(filePath)) || filePath.includes('node_modules') || filePath.includes('.github')) {
          return resolveWalk();
        }
        const contentType = mime.contentType(path.extname(bucketPath));
        const params = {
          Bucket: bucketName,
          ACL: 'public-read',
          ContentType: contentType,
          Key: key,
          Body: fs.readFileSync(filePath)
        };
        const success = await s3.putObject(params).promise().catch(rejectWalk);
        if (!success) {
          return log.error(`Could not upload ${key}`);
        }
        log.debug('Successfully uploaded ' + bucketPath + ' to ' + bucketName + ' as ' + key);
        resolveWalk();
      });
    });

    resolve(overall);
  });
}

async function build(argv) {
  log.info('Building the app');
  let tar = {};
  let appInfo = {};
  try {
    log.debug(`Loading '${cwd()}/app.json'`);
    appInfo = require(`${cwd()}/app.json`);
    tar = await createTar(appInfo, argv);
    log.debug(`${tar.filename} created successfully`);
  } catch (e) {
    log.error(e);
  }
  log.success(`Build finished: ${cwd()}/${tar.filename}`);
}

function getCredentials(account, service = 'hcs-cli') {
  return new Promise((resolve, reject) => {
    keytar.getPassword(service, account).then((result) => {
      resolve(result ? result : false);
    }).catch(reject);
  });
}

async function logout(_argv) {
  // const allCreds = await keytar.findCredentials(KEYTAR_SERVICES.HCS_CLI);
  // const promises = allCreds.map(async creds => {
  //   await keytar.deletePassword('hcs-cli', creds.account);
  // });
  // await Promise.allSettled(promises);
  await logoutHCSAccounts();
  log.success('You have been signed out');
}

async function publish(argv) {
  log.info('Publishing the app');
  let appInfo = {};
  let tar = {};
  const force = !!argv.force;
  try {
    log.debug(`Loading '${cwd()}/app.json'`);
    appInfo = require(`${cwd()}/app.json`);
    tar = await createTar(appInfo, argv);
    log.debug(`${tar.filename} created successfully`);
  } catch (e) {
    log.error(e);
    return;
  }

  log.debug('Process the app.json');
  const timestamp = Date.now();
  let app = {
    id: appInfo.id,
    added: timestamp,
    modified: timestamp,
    versions: [{
      id: appInfo.id,
      summary: appInfo.description,
      hash: tar.hash,
      filename: tar.filename,
      added: timestamp,
      modified: timestamp,
      sdk: appInfo.sdk,
      version: appInfo.version,
      compatibility: appInfo.compatibility,
      name: appInfo.name,
      icon: appInfo.icon,
      brandColor: appInfo.brandColor || '#000000',
      tags: appInfo.tags,
      category: determineCategory(appInfo),
      author: appInfo.author,
      contributors: appInfo.contributors,
      source: appInfo.source,
      homepage: appInfo.homepage,
      support: appInfo.support,
      images: {
        small: appInfo.images ? appInfo.images.small : null,
        large: appInfo.images ? appInfo.images.large : null
      },
      permissions: appInfo.permissions,
      contributing: appInfo.contributing,
      bugs: appInfo.bugs,
      homeyCommunityTopicId: appInfo.homeyCommunityTopicId,
      signals: appInfo.signals,
      flow: appInfo.flow,
      discovery: appInfo.discovery,
      drivers: appInfo.drivers,
      description: getI18nDescriptions(),
      enabled: true
    }]
  };

  log.debug('Look for ./homeychangelog.json');
  if (fs.existsSync(`${cwd()}/.homeychangelog.json`)) {
    log.debug('Changelog found, adding it to the app');
    app.changelog = require(`${cwd()}/.homeychangelog.json`);
    app.versions[0].changelog = require(`${cwd()}/.homeychangelog.json`);
  }

  log.debug(`Processing locales`);
  const locales = {};
  const appVersion = app.versions[0];
  if (appVersion.name) {
    log.debug(`Processing locales from the name: ${Object.keys(appVersion.name).join(', ')}`);
    Object.keys(appVersion.name).forEach(lang => {
      locales[lang] = {name: appVersion.name[lang]};
    });
  }

  if (appVersion.summary) {
    log.debug(`Processing locales from the summary for the description: ${Object.keys(appVersion.name).join(', ')}`);
    Object.keys(appVersion.summary).forEach(lang => {
      locales[lang] = {
        ...locales[lang],
        description: appVersion.summary[lang]
      };
    });
  }

  if (appVersion.description) {
    log.debug(`Processing locales from the description for the description: ${Object.keys(appVersion.name).join(', ')}`);
    Object.keys(appVersion.description).forEach(lang => {
      locales[lang] = {
        ...locales[lang],
        description: appVersion.description[lang]
      };
    });
  }

  if (appVersion.tags) {
    log.debug(`Processing locales from the tags: ${Object.keys(appVersion.name).join(', ')}`);
    Object.keys(appVersion.tags).forEach(lang => {
      locales[lang] = {
        ...locales[lang],
        tags: appVersion.tags[lang]
      };
    });
  }

  if (appVersion.changelog) {
    Object.keys(appVersion.changelog).forEach(version => {
      log.debug(`Processing locales from the changelog ${version}: ${Object.keys(appVersion.changelog[version]).join(', ')}`);
      Object.keys(appVersion.changelog[version]).forEach(lang => {
        if (!locales[lang]) {
          locales[lang] = {};
        }
        if (!locales[lang].changelog) {
          locales[lang].changelog = {};
        }
        locales[lang].changelog[version] = appVersion.changelog[version][lang];
      });
    });
  }

  app.versions[0].locales = locales;

  log.debug('Looking for credentials');
  let creds = null;

  if (argv.key && argv.secret) {
    creds = [{account: argv.key, password: argv.secret}];
  } else {
    creds = await keytar.findCredentials('hcs-cli').catch(err => log.error(err));
  }

  let accessKeyId;
  let accessKeySecure;
  if (creds && creds.length === 1) {
    accessKeyId = creds[0].account;
    accessKeySecure = creds[0].password;
  } else {
    log.info('Credentials not found, please sign in');
    accessKeyId = await promptForAccessKeyId();
    accessKeySecure = await getCredentials(accessKeyId).catch(err => log.error(err));
  }

  if (accessKeySecure === false) {
    //ask for credentials;
    log.info('Password not found, please sign in');
    const accessKeySecret = await promptForAccessKeySecret();
    if (accessKeySecret) {
      const success = await setCredentials(accessKeyId, accessKeySecret).catch(err => log.error(err));
      if (!success) {
        log.error('Something went wrong storing your credentials');
        return;
      }
    } else {
      return;
    }
    accessKeySecure = accessKeySecret;
  }

  log.debug('Creating the AWS Config');
  AWS.config = new AWS.Config({
    region: 'eu-central-1',
    accessKeyId: accessKeyId,
    secretAccessKey: accessKeySecure
  });

  const request = {
    host: '4c23v5xwtc.execute-api.eu-central-1.amazonaws.com',
    method: 'POST',
    url: `https://4c23v5xwtc.execute-api.eu-central-1.amazonaws.com/production/apps/publish`,
    data: {app, force}, // object describing the foo
    body: JSON.stringify({app, force}), // aws4 looks for body; axios for data
    path: `/production/apps/publish`,
    headers: {
      'content-type': 'application/json'
    }
  };
  log.debug(`Preparing request to the API ${request.url}`);

  const signedRequest = aws4.sign(request,
    {
      secretAccessKey: AWS.config.credentials.secretAccessKey,
      accessKeyId: AWS.config.credentials.accessKeyId
    });

  delete signedRequest.headers['Host'];
  delete signedRequest.headers['Content-Length'];

  log.debug(`Send request to the API ${request.url}`);
  const response = await axios(signedRequest).catch(err => log.error(err));
  if (response && response.data && response.data.body) {
    const {success, msg} = response.data.body;
    if (!success) {
      log.error(msg);
      return;
    }
    log.debug(msg);

    const uploadPromise = uploadToS3(cwd(), 'homey-community-store', `${app.id}/${appInfo.version}`);
    const filePromises = await uploadPromise;
    if (filePromises) {
      let errors;
      await Promise.allSettled(filePromises).catch(err => errors = err);
      if (errors) {
        log.error('Failed to push an asset to the S3 storage. Failed to publish the app. Please contact the HCS admin');
      } else {
        if (!argv.keep) {
          log.debug('Cleaning up');
          fs.unlinkSync(`./${tar.filename}`);
        }
        log.success('Successfully published the app to the Homey Community Store.');
      }
    } else {
      log.error('FAILED TO PUBLISH');
    }

  } else {
    log.error('Failed pushing to the DB');
    if (response.data.errorMessage) {
      log.error(response.data.errorType);
      log.error(response.data.errorMessage);
      log.error(response.data.trace);
    }
  }
}

async function homeyCLI(homeyApp) {
  log.debug('Validate the app');

  try {
    await homeyApp.preprocess();
  } catch (e) {
    throw e;
  }

  if (await fs.pathExists(path.join(cwd(), 'package.json'))) {
    const hasAllModules = await listModules();
    if (!hasAllModules) {
      const continueOnError = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'value',
          default: false,
          message: `Not all node modules are installed. Are you sure you want to continue?`
        }
      ]);
      if (!continueOnError.value)
        throw new Error('✖ Please run "npm install" to install any missing node modules.');
    }
  }

  const valid = await homeyApp._validate({level: 'publish'});
  if (valid !== true) {
    throw new Error('The app is not valid, please fix the validation issues first.');
  }

  let {name, version} = homey.App.getManifest({appPath: cwd()});

  const versionCorrect = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'value',
      message: `Is '${version}' the correct version you want to publish?`
    }
  ]);

  if (!versionCorrect.value) {
    throw new Error('✖ Please update the app.json to the correct version number first.');
  }

  // Get or create changelog
  let updatedChangelog = false;
  const changelog = await Promise.resolve().then(async () => {
    const changelogJsonPath = path.join(cwd(), '.homeychangelog.json');
    const changelogJson = (await fs.pathExists(changelogJsonPath))
      ? await fs.readJson(changelogJsonPath)
      : {};

    if (!changelogJson[version] || !changelogJson[version]['en']) {
      const {text} = await inquirer.prompt([
        {
          type: 'input',
          name: 'text',
          message: `(Changelog) What's new in ${name.en} v${version}?`,
          validate: input => {
            return input.length > 3;
          }
        }
      ]);

      changelogJson[version] = changelogJson[version] || {};
      changelogJson[version]['en'] = text;
      await fs.writeJson(changelogJsonPath, changelogJson, {
        spaces: 2
      });

      log.debug(` — Changelog: ${text}`);

      // Mark as changed
      updatedChangelog = true;

      // // Make sure to commit changelog changes
      // commitFiles.push(changelogJsonPath);
    }

    return changelogJson[version];
  });

  // Get readme
  const en = await fs.readFile(path.join(cwd(), 'README.txt'))
    .then(buf => buf.toString())
    .catch(err => {
      throw new Error('Missing file `/README.txt`. Please provide a README for your app. The contents of this file will be visible in the App Store.');
    });

  const readme = {en};

  // Read files in app dir
  const files = await fs.readdir(cwd(), {withFileTypes: true});

  // Loop all paths to check for matching readme names
  for (const file of files) {
    if (Object.prototype.hasOwnProperty.call(file, 'name') && typeof file.name === 'string') {
      // Check for README.<code>.txt file name
      if (file.name.startsWith('README.') && file.name.endsWith('.txt')) {
        const languageCode = file.name.replace('README.', '').replace('.txt', '');

        // Check language code against homey-lib supported language codes
        if (getAppLocales().includes(languageCode)) {
          // Read contents of file into readme object
          readme[languageCode] = await fs.readFile(path.join(cwd(), file.name)).then(buf => buf.toString());
        }
      }
    }
  }

  return {
    changelog,
    readme
  };

}

async function upload(argv) {
  log.info('Publishing the app');

  const user = await login(argv);
  if (!user) {
    return;
  }

  let app = {};
  let tar = {};

  const homeyApp = new homey.App(cwd());

  let homeyResult = null;
  try {
    homeyResult = await homeyCLI(homeyApp);
  } catch (e) {
    return log.error(e);
  }

  try {
    log.debug(`Loading '${cwd()}/app.json'`);
    app = require(`${cwd()}/app.json`);
    tar = await createTar(app, argv);
    log.debug(`${tar.filename} created successfully`);
  } catch (e) {
    error(e);
    return;
  }

  log.debug('Gathering app files');
  const files = getFiles(cwd(), []);
  if (maxFileSizeExceeded(files)) {
    cleanUp({tar: tar.filename});
    return error('Could not upload the app as some files are larger than 10mb');
  }

  const body = {
    app,
    changelog: homeyResult.changelog,
    readme: homeyResult.readme
  };

  log.debug('Sending app to the Homey Community Store');
  const response = await API.post(CONSTANT.AWS.API.NAME, `${CONSTANT.AWS.API.ENV}/apps`, {
    body
  }).catch((err) => {
    return err.response;
  });

  if (!response || response.status !== 200) {
    cleanUp({tar: tar.filename});
    error(response);
    return log.error('Could not publish the app');
  }

  log.debug('Determine file upload urls');
  const urls = files.map(file => {
    const filename = file.path.replace(`${cwd()}${path.sep}`, '');
    const contentType = mime.contentType(path.extname(file.path));
    return API.post(CONSTANT.AWS.API.NAME, `${CONSTANT.AWS.API.ENV}/upload/url`, {
      body: {
        key: filename,
        contentType,
        app: {
          id: app.id,
          version: app.version
        }
      }
    });
  });

  let uploadUrls = await Promise.all(urls).catch(error);

  if (!uploadUrls) {
    cleanUp({tar: tar.filename});
    return error('Error uploading the files');
  }

  const puts = uploadUrls.map((item) => {
    if (!item.file || !item.url) {
      Promise.reject('No file/url found');
    }
    log.debug(`Upload ${item.file}`);
    const filePath = path.join(cwd(), item.file);
    const file = fs.readFileSync(filePath);
    const contentType = mime.contentType(path.extname(filePath));
    return axios.put(item.url, file, {
      headers: {
        'Content-Type': contentType
      }
    });
  });
  const result = await Promise.all(puts);
  if (!result) {
    cleanUp({tar: tar.filename});
    return error('Something went wrong while uploading the app files!');
  }
  let failedToUploadFiles = false;
  result.forEach(res => {
    if (res.status !== 200) {
      error(res);
      failedToUploadFiles = true;
    }
  });

  if (failedToUploadFiles) {
    cleanUp({tar: tar.filename});
    return error('Could not upload all files!');
  }
  cleanUp({tar: tar.filename});
  log.success('The app is successfully published to the Homey Community Store.');
}

async function login(_argv) {
  const credentials = await getHCSAccount();

  let user = null;
  try {
    user = await Auth.signIn(credentials.email, credentials.password);
    setCredentials(credentials.email, credentials.password, KEYTAR_SERVICES.HCS_ACCOUNT).then(() => {
      // don't care when it happens
    });
  } catch (err) {
    return error(err);
  }
  log.success(`You are logged in as ${credentials.email}`);

  // Initialize the Amazon Cognito credentials provider
  AWS.config.region = CONSTANT.AWS.REGION; // Region
  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: CONSTANT.AWS.IDENTITY_POOL
  });

  return user;
}



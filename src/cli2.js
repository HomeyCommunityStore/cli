import inquirer from 'inquirer';
import {cwd} from 'process';
import tar from 'tar';
import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';
import yargs from 'yargs';
import axios from 'axios';
import {exec} from 'child_process';
import {
  KEYTAR_SERVICES,
  setCredentials,
  getCredentials,
  logoutHCSAccounts,
  log,
  getAuth0Token,
  verifyAuth0Token,
  cleanup, exitHandler
} from './utils';
import homey from 'homey';
import {getAppLocales} from 'homey-lib';
import FormData from 'form-data';

const passport = require('passport');
const Auth0Strategy = require('passport-auth0');

const strategy = new Auth0Strategy(
  {
    domain: 'hcs.eu.auth0.com',
    clientID: 'fN41SbewuRz9J4DF4yb1HIVhOXS6wz1b',
    clientSecret: 'uguc1qj4OBOyAcBVVCNCyJBWX6LCibIZ7SsEX47bzClVG8bWA9C2oT9KqtVR18Zv',
    callbackURL: 'http://localhost:9812/auth'
  },
  function (accessToken, refreshToken, extraParams, profile, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    return done(null, profile);
  }
);

passport.use(strategy);

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
      return yargs;
    }, publish)
    .command('logout', 'Remove all credentials', (yargs) => {
      return yargs;
    }, logout)
    .command('login', 'Login to HCS', (yargs) => {
      return yargs;
    }, login)
    .help()
    .demandCommand(1, 'You need to enter at least one command')
    .argv;
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
    let version = `${appInfo.version}`;
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
      // const hashed = hash.digest('hex');
      const readStream = fs.createReadStream(`${cwd()}/${tarFile}`);
      readStream.on('error', reject);
      readStream.on('data', chunk => hash.update(chunk));
      readStream.on('end', () => resolve({filename: tarFile}));
    }, (error) => {
      reject(error);
    });
  });
}

export async function cli(args) {
  parseArgumentsIntoOptions(args);
}

function uploadFiles(cwd) {
  const overall = [];

  function walkSync(currentDirPath, callback) {
    fs.readdirSync(currentDirPath).forEach((name) => {
      const filePath = path.join(currentDirPath, name);
      const stat = fs.statSync(filePath);
      if (stat.isFile()) {
        callback(filePath, stat);
      } else if (stat.isDirectory()) {
        walkSync(filePath, callback);
      }
    });
  }

  walkSync(cwd, (filePath, stat) => {
    if (!['.txt'].includes(path.extname(filePath)) || filePath.includes('node_modules') || filePath.includes('.github')) {
      return;
    }
    const filename = filePath.split(path.sep).pop();
    if (!filename.toLowerCase().startsWith('readme.')) {
      return;
    }

    overall.push({file: filePath, key: filename.toLowerCase()});
  });
  return overall;
}

async function build(argv) {
  log.info('Building the app');
  let tar = {};
  let appInfo = {};
  try {
    log.debug(`Loading '${cwd()}${path.sep}app.json'`);
    appInfo = require(`${cwd()}${path.sep}app.json`);
    tar = await createTar(appInfo, argv);
    log.debug(`${tar.filename} created successfully`);
  } catch (e) {
    log.error(e);
  }
  log.success(`Build finished: ${cwd()}${path.sep}${tar.filename}`);
}

async function logout(_argv) {
  await logoutHCSAccounts(KEYTAR_SERVICES.HCS_AUTH0);
  log.success('You have been signed out');
}

async function publish(argv) {
  process.stdin.resume(); // so the cli will not close instantly

  log.info('Publishing the app');
  let app = null;
  let changelog = null;
  let tar = {};
  const formData = new FormData();

  const homeyApp = new homey.App(cwd());

  try {
    await homeyCLI(homeyApp, argv.y);
  } catch (e) {
    return log.error(e);
  }

  try {
    log.debug(`Loading '${cwd()}${path.sep}app.json'`);
    app = require(path.join(cwd(), 'app.json'));
    formData.append('app', JSON.stringify(app));
    tar = await createTar(app, argv);
    exitHandler(() => cleanup(tar.filename));
    formData.append('archive', fs.createReadStream(path.join(cwd(), tar.filename)));
    log.debug(`${tar.filename} created successfully`);
  } catch (e) {
    return log.error(e);
  }

  if (!app) {
    return log.error('app.json not found!');
  }

  log.debug('Looking for .homeychangelog.json');
  if (fs.existsSync(path.join(cwd(), '.homeychangelog.json'))) {
    log.debug('Changelog found, adding it to the app');
    changelog = require(path.join(cwd(), '.homeychangelog.json'));
    formData.append('changelog', JSON.stringify(changelog));
  }

  log.debug('Looking for existing credentials');
  let accessToken = await getCredentials('hcs-cli', KEYTAR_SERVICES.HCS_AUTH0);
  if (accessToken) {
    log.debug('Credentials found');
    log.debug('Verifying credentials');
    try {
      await verifyAuth0Token(accessToken);
    } catch (e) {
      log.debug(e);
      accessToken = false;
    }
  }
  if (!accessToken) {
    log.debug('Credentials not found or invalid');
    log.debug('Asking the user to authenticate the device');
    try {
      accessToken = await getAuth0Token();
      log.debug('Storing the credentials');
      await setCredentials('hcs-cli', accessToken, KEYTAR_SERVICES.HCS_AUTH0);
    } catch (e) {
      return log.error(e);
    }
    if (!accessToken) {
      log.error('Failed to authenticate');
      return process.exit();
    }
  }

  const meta = {
    icon: '/assets/icon.svg',
    image_sm: app.images.small,
    image_lg: app.images.large
  };

  formData.append('icon', fs.createReadStream(path.join(cwd(), 'assets', 'icon.svg')));
  formData.append('image_sm', fs.createReadStream(path.join(cwd(), app.images.small)));
  formData.append('image_lg', fs.createReadStream(path.join(cwd(), app.images.large)));
  if (app.images.xlarge) {
    formData.append('image_xl', fs.createReadStream(path.join(cwd(), app.images.xlarge)));
    meta.image_xl = app.images.xlarge;
  }

  if (app.drivers) {
    app.drivers.forEach((driver) => {
      formData.append(`driver_sm_${driver.id}`, fs.createReadStream(path.join(cwd(), driver.images.small)));
      formData.append(`driver_lg_${driver.id}`, fs.createReadStream(path.join(cwd(), driver.images.large)));
      meta[`driver_sm_${driver.id}`] = driver.images.small;
      meta[`driver_lg_${driver.id}`] = driver.images.large;
      if (driver.images.xlarge) {
        formData.append(`driver_xl_${driver.id}`, fs.createReadStream(path.join(cwd(), driver.images.xlarge)));
        meta[`driver_xl_${driver.id}`] = driver.images.xlarge;
      }
    });
  }

  const files = uploadFiles(cwd());
  files.forEach(({file, key}) => {
    formData.append(key, fs.createReadStream(file));
    meta[key] = null;
  });

  formData.append('meta', JSON.stringify(meta));

  const url = argv.dev ? 'http://localhost:4040/apps' : 'https://homey-commun-staging-pefdjbllo.herokuapp.com/apps';
  try {
    await axios.post(url, formData, {
      headers: {
        ...formData.getHeaders(),
        Authorization: `Bearer ${accessToken}`
      }
    });
    log.success('App published to the Homey Community Store!');
  } catch (e) {
    if (e && e.response && e.response.data) {
      log.error(JSON.stringify(e.response.data));
    } else {
      log.error(e);
    }
    log.error('Failed to publish the app to the Homey Community Store!');
  }
  process.exit();
}

async function homeyCLI(homeyApp, correctVersion = false) {
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

  if (!correctVersion) {
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
      if (file.name.toLowerCase().startsWith('README.') && file.name.toLowerCase().endsWith('.txt')) {
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

async function login(_argv) {
  // const credentials = await getHCSAccount();
  //
  // let user = null;
  // try {
  //   user = await Auth.signIn(credentials.email, credentials.password);
  //   setCredentials(credentials.email, credentials.password, KEYTAR_SERVICES.HCS_ACCOUNT).then(() => {
  //     // don't care when it happens
  //   });
  // } catch (err) {
  //   return error(err);
  // }
  // log.success(`You are logged in as ${credentials.email}`);
  //
  // // Initialize the Amazon Cognito credentials provider
  // AWS.config.region = CONSTANT.AWS.REGION; // Region
  // AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  //   IdentityPoolId: CONSTANT.AWS.IDENTITY_POOL
  // });
  //
  // return user;
}



import inquirer from 'inquirer';
import keytar from 'keytar';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import axios from 'axios';
import open from 'open';
import jwksClient from 'jwks-rsa';
import * as jwt from 'jsonwebtoken';

const {blue, green, gray, red} = chalk;

export const KEYTAR_SERVICES = {
  HCS_CLI: 'hcs-cli',
  HCS_ACCOUNT: 'hcs-account',
  HCS_AUTH0: 'hcs-auth0'
};


export const log = {
  info: (...args) => {
    console.log(blue(...args));
  },
  success: (...args) => {
    console.log(green(...args));
  },
  debug: (...args) => {
    console.log(gray(...args));
  },
  error: (...args) => {
    console.log(red(...args));
  },
  log: (...args) => (console.log(...args)),
  chalk
};

export function error(...args){
  console.error(...args);
}

export async function pollAuth0(device_code, interval) {
  let retry = 0;
  return new Promise((resolve, reject) => {
    async function poll() {
      retry++;
      if (retry > 10) {
        return reject('Failed to authenticate');
      }
      try {
        const response = await axios.post('https://hcs.eu.auth0.com/oauth/token', {
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
          client_id: 'fN41SbewuRz9J4DF4yb1HIVhOXS6wz1b'
        });
        return resolve(response.data);
      } catch (e) {
        log.debug('Waiting for user authentication');
        setTimeout(async () => {
          poll();
        }, interval * 1000);
      }
    }
    poll();
  });
}

export async function prompt(questions) {
  return await inquirer.prompt(questions);
}

export async function getAuth0Token() {
  const authDevice = await axios.post('https://hcs.eu.auth0.com/oauth/device/code', {
    client_id: 'fN41SbewuRz9J4DF4yb1HIVhOXS6wz1b',
    scope: 'openid email profile',
    audience: 'https://api.store.homey.community'
  });
  const {device_code, interval, verification_uri_complete} = authDevice.data;
  log.info(`Please open the url in your browser and login: ${verification_uri_complete}`);

  await open(verification_uri_complete);
  const auth0 = await pollAuth0(device_code, interval);
  return auth0.access_token;
}

export function verifyAuth0Token(token) {
  return new Promise((resolve, reject) => {
    const client = jwksClient({
      jwksUri: 'https://hcs.eu.auth0.com/.well-known/jwks.json'
    });
    jwt.verify(token, (header, callback) => {
      client.getSigningKey(header.kid, (err, key) => {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      });
    }, {}, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      resolve(token);
    });
  });
}

export function exitHandler(callback) {
  function handler() {
    callback();
    process.exit();
  }

  //do something when app is closing
  process.on('exit', handler);

//catches ctrl+c event
  process.on('SIGINT', handler);

// catches "kill pid" (for example: nodemon restart)
  process.on('SIGUSR1', handler);
  process.on('SIGUSR2', handler);

//catches uncaught exceptions
  process.on('uncaughtException', handler);

}

export function cleanup(filename) {
  log.debug('Cleaning up app folder');
  if (fs.existsSync(filename)) {
    fs.unlinkSync(filename);
  }
}

export function getCredentials(account, service = KEYTAR_SERVICES.HCS_CLI) {
  return new Promise((resolve, reject) => {
    keytar.getPassword(service, account).then((result) => {
      resolve(result ? result : false);
    }).catch(reject);
  });
}

export function setCredentials(account, password, service = KEYTAR_SERVICES.HCS_CLI) {
  return new Promise((resolve, reject) => {
    keytar.setPassword(service, account, password).then((_result) => {
      resolve(true);
    }).catch(reject);
  });
}

export async function logoutHCSAccounts(service = KEYTAR_SERVICES.HCS_ACCOUNT) {
  const accounts = await keytar.findCredentials(service);
  const promises = accounts.map(async ({account}) => {
    return keytar.deletePassword(service, account);
  });
  return await Promise.allSettled(promises);
}

export async function getHCSAccount(other = false) {
  const accounts = (await keytar.findCredentials(KEYTAR_SERVICES.HCS_ACCOUNT)).map(({account, password}) => {
    return {
      email: account,
      password
    };
  });

  if (other || !accounts || accounts.length < 1) {
    const questions = [{
      type: 'input',
      name: 'email',
      message: 'Please provide your e-mail address for your HCS account:'
    }, {
      type: 'password',
      name: 'password',
      message: 'Please provide your password for your HCS account:'
    }];
    return await prompt(questions);
  }

  if (accounts.length === 1) {
    return accounts[0];
  }

  accounts.sort((a, b) => {
    const mailA = a.email;
    const mailB = b.email;
    return mailA > mailB ? -1 : mailA < mailB ? 1 : 0;
  });
  accounts.push({email: 'Other', password: null});

  const selectAccount = [{
    type: 'list',
    name: 'email',
    message: 'Please select which account you would like to use?',
    choices: accounts.map(({email}) => email)
  }];
  const selected = await prompt(selectAccount);

  if (selected.email.toLowerCase() === 'other') {
    return getHCSAccount(true);
  }

  return accounts.find(({email}) => email === selected.email);
}

const excludeFolders = [
  'node_modules',
  '.github',
  '.git'
];

const includeFileTypes = [
  '.svg',
  '.png',
  '.jpg',
  '.jpeg',
  '.gz'
];

export function getFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    let cancel = false;
    excludeFolders.forEach((exc) => {
      if (file.toLowerCase().includes(exc.toLowerCase())) {
        cancel = true;
      }
    });
    if (cancel) {
      continue;
    }
    const stat = fs.statSync(path.join(dir, file));
    if (stat.isDirectory()) {
      fileList = getFiles(path.join(dir, file), fileList);
    } else {
      if (includeFileTypes.includes(path.extname(file))) {
        const mb = stat.size / (1024 * 1024);
        log.debug(`· Found ${file}`);
        fileList.push({path: path.join(dir, file), stat: {...stat, mb}});
      }
    }
  }
  return fileList;
}

export function maxFileSizeExceeded(files) {
  log.debug('Check if any file exceeds the 10mb maximum file size');
  const exceededSize = files.filter((file) => {
    return file.stat.mb >= 10;
  });

  if (exceededSize.length > 0) {
    exceededSize.forEach(file => {
      if (file.path.includes('.tar.gz')) {
        log.error(`\nWhen zipped the total app size exceeds the maximum of 10mb. Please reduce the size of the app!`);
        log.debug('See', file.path, `${Math.round(file.stat.mb)}mb\n`);
      } else {
        log.error('✖', file.path, `${Math.round(file.stat.mb)}mb`);
      }
    });
    return true;
  }
  return false;
}

export function cleanUp({tar}) {
  log.debug('Cleaning up');
  fs.unlinkSync(`.${path.sep}${tar}`);
}

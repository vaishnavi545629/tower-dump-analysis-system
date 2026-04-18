const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

let initialized = false;

function initFirebase() {
  if (initialized) return admin;

  let credential;

  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    // Hosted environments: JSON string in env var
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    credential = admin.credential.cert(serviceAccount);
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
    // Local dev: path to JSON file
    const configuredPath = path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
    const candidatePaths = [
      configuredPath,
      `${configuredPath}.json`,
      configuredPath.endsWith('.json') ? `${configuredPath}.json` : `${configuredPath}.json.json`,
    ];
    const resolvedPath = candidatePaths.find((candidate) => fs.existsSync(candidate));
    if (!resolvedPath) {
      throw new Error(`Firebase service account file not found at ${configuredPath}`);
    }
    const serviceAccount = require(resolvedPath);
    credential = admin.credential.cert(serviceAccount);
  } else {
    throw new Error(
      'Firebase credentials not configured. Set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_PATH in .env'
    );
  }

  admin.initializeApp({ credential });
  initialized = true;
  console.log('[Firebase] Admin SDK initialized');
  return admin;
}

function getFirestore() {
  return initFirebase().firestore();
}

function getAuth() {
  return initFirebase().auth();
}

module.exports = { initFirebase, getFirestore, getAuth };

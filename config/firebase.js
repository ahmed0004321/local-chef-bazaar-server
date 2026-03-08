const admin = require("firebase-admin");
require("dotenv").config();

const serviceAccountVar = process.env.FIREBASE_SERVICE_ACCOUNT;
let serviceAccount;

if (!serviceAccountVar) {
    try {
        serviceAccount = require("../local-chef-bazaar-client-firebase-adminsdk-fbsvc-cf7e3a980e.json");
        console.log("Initializing Firebase using local file");
    } catch (e) {
        console.error("FIREBASE_SERVICE_ACCOUNT not defined and local file not found.");
    }
} else if (serviceAccountVar.startsWith("{")) {
    try {
        console.log("Initializing Firebase using JSON string from environment variable");
        serviceAccount = JSON.parse(serviceAccountVar);
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
    } catch (e) {
        console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT as JSON:", e.message);
    }
} else {
    console.log("Initializing Firebase using file path:", serviceAccountVar);
    serviceAccount = require(serviceAccountVar);
}

if (serviceAccount) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
} else {
    console.warn("Firebase admin not initialized due to missing credentials.");
}

module.exports = admin;

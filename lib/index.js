'use strict';

const Crypto = require('crypto');

const B64 = require('@hapi/b64');
const Boom = require('@hapi/boom');
const Bourne = require('@hapi/bourne');
const Cryptiles = require('@hapi/cryptiles');
const Hoek = require('@hapi/hoek');


const internals = {};


exports.defaults = {
    encryption: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1,
        minPasswordlength: 32
    },

    integrity: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1,
        minPasswordlength: 32
    },

    purpose: 'iron',                                    // Explicit domain label binding a seal to its intended use
    acceptLegacy: true,                                 // Accept seals produced with the unlabeled macFormatVersion '2'
    ttl: 0,                                             // Milliseconds, 0 means forever
    timestampSkewSec: 60,                               // Seconds of permitted clock skew for incoming expirations
    localtimeOffsetMsec: 0                              // Local clock time offset express in a number of milliseconds (positive or negative)
};


// Algorithm configuration
// `type` is the explicit domain role each algorithm is allowed to serve. It prevents an
// encryption algorithm from being substituted for the integrity (MAC) role or vice versa.

exports.algorithms = {
    'aes-128-ctr': { keyBits: 128, ivBits: 128, type: 'encryption' },
    'aes-256-cbc': { keyBits: 256, ivBits: 128, type: 'encryption' },
    'sha256': { keyBits: 256, type: 'integrity' }
};


// MAC normalization format version

internals.macFormatVersion = '2';                       // Legacy, unlabeled format retained only for migration
exports.macFormatVersion = '3';                         // Explicitly labels purpose and both algorithms inside the authenticated MAC input

exports.macPrefix = 'Fe26.' + exports.macFormatVersion;

internals.legacyMacPrefix = 'Fe26.' + internals.macFormatVersion;


internals.defaultPurpose = 'iron';
internals.purposeRegex = /^[\w-]+$/;


// Returns the explicit domain role ('encryption' or 'integrity') of an algorithm, or throws.

internals.algorithmType = function (algorithm, role) {

    const config = exports.algorithms[algorithm];
    if (!config) {
        throw new Boom.Boom('Unknown algorithm: ' + algorithm);
    }

    if (config.type !== role) {
        throw new Boom.Boom('Algorithm ' + algorithm + ' cannot be used for ' + role);
    }

    return config.type;
};


// Reads the explicit domain identity carried by a seal without requiring any secret.
// Returns null when the input is not a recognizable iron token.

exports.identify = function (sealed) {

    if (typeof sealed !== 'string') {
        return null;
    }

    const parts = sealed.split('*');
    const prefix = parts[0];

    if (prefix === exports.macPrefix) {
        if (parts.length !== 11) {
            return null;
        }

        return {
            version: exports.macFormatVersion,
            purpose: parts[1],
            encryption: { algorithm: parts[2] },
            integrity: { algorithm: parts[3] },
            passwordId: parts[4]
        };
    }

    if (prefix === internals.legacyMacPrefix) {
        if (parts.length !== 8) {
            return null;
        }

        return {
            version: internals.macFormatVersion,
            purpose: null,
            encryption: { algorithm: null },
            integrity: { algorithm: null },
            passwordId: parts[1]
        };
    }

    return null;
};


// Generate a unique encryption key

/*
    const options =  {
        saltBits: 256,                                  // Ignored if salt is set
        salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
        algorithm: 'aes-128-ctr',
        iterations: 10000,
        iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg',          // Optional
        minPasswordlength: 32
    };
*/

exports.generateKey = async function (password, options) {

    if (!password) {
        throw new Boom.Boom('Empty password');
    }

    if (!options ||
        typeof options !== 'object') {

        throw new Boom.Boom('Bad options');
    }

    const algorithm = exports.algorithms[options.algorithm];
    if (!algorithm) {
        throw new Boom.Boom('Unknown algorithm: ' + options.algorithm);
    }

    const result = {};

    if (Buffer.isBuffer(password)) {
        if (password.length < algorithm.keyBits / 8) {
            throw new Boom.Boom('Key buffer (password) too small');
        }

        result.key = password;
        result.salt = '';
    }
    else {
        if (password.length < options.minPasswordlength) {
            throw new Boom.Boom('Password string too short (min ' + options.minPasswordlength + ' characters required)');
        }

        let salt = options.salt;
        if (!salt) {
            if (!options.saltBits) {
                throw new Boom.Boom('Missing salt and saltBits options');
            }

            const randomSalt = Cryptiles.randomBits(options.saltBits);
            salt = randomSalt.toString('hex');
        }

        const derivedKey = await internals.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, 'sha1');

        result.key = derivedKey;
        result.salt = salt;
    }

    if (options.iv) {
        result.iv = options.iv;
    }
    else if (algorithm.ivBits) {
        result.iv = Cryptiles.randomBits(algorithm.ivBits);
    }

    return result;
};


// Encrypt data
// options: see exports.generateKey()

exports.encrypt = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

    return { encrypted, key };
};


// Decrypt data
// options: see exports.generateKey()

exports.decrypt = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const decipher = Crypto.createDecipheriv(options.algorithm, key.key, key.iv);
    let dec = decipher.update(data, null, 'utf8');
    dec = dec + decipher.final('utf8');

    return dec;
};


// HMAC using a password
// options: see exports.generateKey()

exports.hmacWithPassword = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const hmac = Crypto.createHmac(options.algorithm, key.key).update(data);
    const digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    return {
        digest,
        salt: key.salt
    };
};


// Normalizes a password parameter into a { id, encryption, integrity } object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }

internals.normalizePassword = function (password) {

    if (password &&
        typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        return {
            id: password.id,
            encryption: password.secret ?? password.encryption,
            integrity: password.secret ?? password.integrity
        };
    }

    return {
        encryption: password,
        integrity: password
    };
};


// Encrypt and HMAC an object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }
// options: see exports.defaults

exports.seal = async function (object, password, options) {

    options = Object.assign({}, options);       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec ?? 0);                 // Measure now before any other processing

    // Serialize object

    const objectString = internals.stringify(object);

    // Obtain password

    let passwordId = '';
    password = internals.normalizePassword(password);
    if (password.id) {
        if (!/^\w+$/.test(password.id)) {
            throw new Boom.Boom('Invalid password id');
        }

        passwordId = password.id;
    }

    // Resolve and validate the explicit domain label and the role of each algorithm

    const purpose = options.purpose ?? internals.defaultPurpose;
    if (!internals.purposeRegex.test(purpose)) {
        throw new Boom.Boom('Invalid purpose');
    }

    // Encrypt object string

    if (options.encryption) {
        internals.algorithmType(options.encryption.algorithm, 'encryption');
    }

    const { encrypted, key } = await exports.encrypt(password.encryption, options.encryption, objectString);

    // Base64url the encrypted value

    const encryptedB64 = B64.base64urlEncode(encrypted);
    const iv = B64.base64urlEncode(key.iv);
    const expiration = (options.ttl ? now + options.ttl : '');

    // prefix*purpose*encryption-algorithm*integrity-algorithm*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]
    // The purpose and both algorithms are authenticated by the MAC so any substitution fails closed.

    const macBaseString = exports.macPrefix +
        '*' + purpose +
        '*' + options.encryption.algorithm +
        '*' + options.integrity.algorithm +
        '*' + passwordId +
        '*' + key.salt +
        '*' + iv +
        '*' + encryptedB64 +
        '*' + expiration;

    // Mac the combined values

    internals.algorithmType(options.integrity.algorithm, 'integrity');

    const mac = await exports.hmacWithPassword(password.integrity, options.integrity, macBaseString);

    // Put it all together

    // prefix*purpose*encryption-algorithm*integrity-algorithm*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac
    // Allowed URI query name/value characters: *-. \d \w

    const sealed = macBaseString + '*' + mac.salt + '*' + mac.digest;
    return sealed;
};


// Decrypt and validate sealed string
// password: string, buffer or object with { id: secret } or { id: { encryption, integrity } }
// options: see exports.defaults

exports.unseal = async function (sealed, password, options) {

    options = Object.assign({}, options);                                       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec ?? 0);                // Measure now before any other processing

    // Break string into components and select the matching format version

    const parts = sealed.split('*');
    const macPrefix = parts[0];

    let isLegacy = false;
    let purpose = null;
    let encryptionAlgorithm = null;
    let integrityAlgorithm = null;
    let passwordId;
    let encryptionSalt;
    let encryptionIv;
    let encryptedB64;
    let expiration;
    let hmacSalt;
    let hmac;
    let macBaseString;

    if (macPrefix === exports.macPrefix) {
        if (parts.length !== 11) {
            throw new Boom.Boom('Incorrect number of sealed components');
        }

        purpose = parts[1];
        encryptionAlgorithm = parts[2];
        integrityAlgorithm = parts[3];
        passwordId = parts[4];
        encryptionSalt = parts[5];
        encryptionIv = parts[6];
        encryptedB64 = parts[7];
        expiration = parts[8];
        hmacSalt = parts[9];
        hmac = parts[10];

        macBaseString = parts.slice(0, 9).join('*');
    }
    else if (macPrefix === internals.legacyMacPrefix) {
        if (options.acceptLegacy === false) {
            throw new Boom.Boom('Legacy seal format is disabled');
        }

        if (parts.length !== 8) {
            throw new Boom.Boom('Incorrect number of sealed components');
        }

        isLegacy = true;
        passwordId = parts[1];
        encryptionSalt = parts[2];
        encryptionIv = parts[3];
        encryptedB64 = parts[4];
        expiration = parts[5];
        hmacSalt = parts[6];
        hmac = parts[7];

        macBaseString = parts.slice(0, 6).join('*');
    }
    else {
        throw new Boom.Boom('Wrong mac prefix');
    }

    // Check expiration

    if (expiration) {
        if (!expiration.match(/^\d+$/)) {
            throw new Boom.Boom('Invalid expiration');
        }

        const exp = parseInt(expiration, 10);
        if (exp <= (now - (options.timestampSkewSec * 1000))) {
            throw new Boom.Boom('Expired seal');
        }
    }

    // Obtain password

    if (!password) {
        throw new Boom.Boom('Empty password');
    }

    if (typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        password = password[passwordId || 'default'];
        if (!password) {
            throw new Boom.Boom('Cannot find password: ' + passwordId);
        }
    }

    password = internals.normalizePassword(password);

    // Verify the explicit domain identity (current format only). Any mismatch fails closed.

    if (!isLegacy) {
        const expectedPurpose = options.purpose ?? internals.defaultPurpose;
        if (purpose !== expectedPurpose) {
            throw new Boom.Boom('Seal purpose mismatch');
        }

        internals.algorithmType(encryptionAlgorithm, 'encryption');
        internals.algorithmType(integrityAlgorithm, 'integrity');

        if (encryptionAlgorithm !== options.encryption.algorithm) {
            throw new Boom.Boom('Seal encryption algorithm mismatch');
        }

        if (integrityAlgorithm !== options.integrity.algorithm) {
            throw new Boom.Boom('Seal integrity algorithm mismatch');
        }
    }

    // Check hmac

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
    if (!isLegacy) {
        macOptions.algorithm = integrityAlgorithm;
    }

    const mac = await exports.hmacWithPassword(password.integrity, macOptions, macBaseString);

    if (!Cryptiles.fixedTimeComparison(mac.digest, hmac)) {
        throw new Boom.Boom('Bad hmac value');
    }

    // Decrypt

    try {
        var encrypted = B64.base64urlDecode(encryptedB64, 'buffer');
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decryptOptions = Hoek.clone(options.encryption);
    decryptOptions.salt = encryptionSalt;
    if (!isLegacy) {
        decryptOptions.algorithm = encryptionAlgorithm;
    }

    try {
        decryptOptions.iv = B64.base64urlDecode(encryptionIv, 'buffer');
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decrypted = await exports.decrypt(password.encryption, decryptOptions, encrypted);

    // Parse JSON

    try {
        return Bourne.parse(decrypted);
    }
    catch (err) {
        throw new Boom.Boom('Failed parsing sealed object JSON: ' + err.message);
    }
};


internals.stringify = function (object) {

    try {
        return JSON.stringify(object);
    }
    catch (err) {
        throw new Boom.Boom('Failed to stringify object: ' + err.message);
    }
};


internals.pbkdf2 = function (...args) {

    return new Promise((resolve, reject) => {

        const next = (err, result) => {

            if (err) {
                return reject(Boom.boomify(err));
            }

            resolve(result);
        };

        args.push(next);
        Crypto.pbkdf2(...args);
    });
};

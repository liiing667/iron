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

    ttl: 0,                                             // Milliseconds, 0 means forever
    timestampSkewSec: 60,                               // Seconds of permitted clock skew for incoming expirations
    localtimeOffsetMsec: 0                              // Local clock time offset express in a number of milliseconds (positive or negative)
};


// Algorithm configuration

exports.algorithms = {
    'aes-128-ctr': { keyBits: 128, ivBits: 128 },
    'aes-256-cbc': { keyBits: 256, ivBits: 128 },
    'sha256': { keyBits: 256 }
};


// MAC normalization format version

exports.macFormatVersion = '2';                         // Prevent comparison of mac values generated with different normalized string formats

exports.macPrefix = 'Fe26.' + exports.macFormatVersion;


// Components of a sealed string, in order:
// prefix*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac

internals.components = {
    prefix: 'prefix',
    passwordId: 'passwordId',
    encryptionSalt: 'encryptionSalt',
    encryptionIv: 'encryptionIv',
    encrypted: 'encrypted',
    expiration: 'expiration',
    hmacSalt: 'hmacSalt',
    hmac: 'hmac'
};


// Stages of the unseal() pipeline where an error can be reported

internals.stages = {
    parse: 'parse',
    validate: 'validate',
    integrity: 'integrity',
    decrypt: 'decrypt'
};


// One-way fingerprint of a password id. It is safe to log as it cannot be
// reversed into the id, and never contains any secret material.

exports.keyFingerprint = function (id) {

    if (!id) {
        return null;
    }

    return Crypto.createHash('sha256').update(id).digest('hex').slice(0, 12);
};


// Builds a Boom error whose message stays free of sealed components
// (ciphertext, salts, iv, hmac) and passwords. Diagnostics that are safe to
// log travel on `err.data`, with the raw sealed value attached only when the
// caller explicitly opts in via options.errorEcho (local troubleshooting).

internals.error = function (message, options) {

    const data = {
        stage: options.stage,
        component: options.component ?? null,
        keyFingerprint: exports.keyFingerprint(options.passwordId)
    };

    if (options.errorEcho) {
        data.echo = options.sealed;
    }

    const base = options.cause;
    if (base) {
        const err = Boom.boomify(base, { data });
        err.output.payload.message = message;
        err.message = message;
        return err;
    }

    return new Boom.Boom(message, { data });
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

    // Encrypt object string

    const { encrypted, key } = await exports.encrypt(password.encryption, options.encryption, objectString);

    // Base64url the encrypted value

    const encryptedB64 = B64.base64urlEncode(encrypted);
    const iv = B64.base64urlEncode(key.iv);
    const expiration = (options.ttl ? now + options.ttl : '');
    const macBaseString = exports.macPrefix + '*' + passwordId + '*' + key.salt + '*' + iv + '*' + encryptedB64 + '*' + expiration;

    // Mac the combined values

    const mac = await exports.hmacWithPassword(password.integrity, options.integrity, macBaseString);

    // Put it all together

    // prefix*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac
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

    const fail = (message, details = {}) => {

        return internals.error(message, {
            sealed,
            errorEcho: options.errorEcho,
            passwordId: details.passwordId,
            stage: details.stage,
            component: details.component,
            cause: details.cause
        });
    };

    // Break string into components

    const parts = sealed.split('*');
    if (parts.length !== 8) {
        throw fail('Incorrect number of sealed components', { stage: internals.stages.parse });
    }

    const macPrefix = parts[0];
    const passwordId = parts[1];
    const encryptionSalt = parts[2];
    const encryptionIv = parts[3];
    const encryptedB64 = parts[4];
    const expiration = parts[5];
    const hmacSalt = parts[6];
    const hmac = parts[7];
    const macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' + encryptedB64 + '*' + expiration;

    // Check prefix

    if (macPrefix !== exports.macPrefix) {
        throw fail('Wrong mac prefix', {
            passwordId,
            stage: internals.stages.parse,
            component: internals.components.prefix
        });
    }

    // Check expiration

    if (expiration) {
        if (!expiration.match(/^\d+$/)) {
            throw fail('Invalid expiration', {
                passwordId,
                stage: internals.stages.validate,
                component: internals.components.expiration
            });
        }

        const exp = parseInt(expiration, 10);
        if (exp <= (now - (options.timestampSkewSec * 1000))) {
            throw fail('Expired seal', {
                passwordId,
                stage: internals.stages.validate,
                component: internals.components.expiration
            });
        }
    }

    // Obtain password

    if (!password) {
        throw fail('Empty password', { passwordId, stage: internals.stages.validate });
    }

    if (typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        password = password[passwordId || 'default'];
        if (!password) {
            throw fail('Cannot find password', {
                passwordId,
                stage: internals.stages.validate,
                component: internals.components.passwordId
            });
        }
    }

    password = internals.normalizePassword(password);

    // Check hmac

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
    const mac = await exports.hmacWithPassword(password.integrity, macOptions, macBaseString);

    if (!Cryptiles.fixedTimeComparison(mac.digest, hmac)) {
        throw fail('Bad hmac value', {
            passwordId,
            stage: internals.stages.integrity,
            component: internals.components.hmac
        });
    }

    // Decrypt

    try {
        var encrypted = B64.base64urlDecode(encryptedB64, 'buffer');
    }
    catch (err) {
        throw fail(err.message, {
            passwordId,
            stage: internals.stages.decrypt,
            component: internals.components.encrypted,
            cause: err
        });
    }

    const decryptOptions = Hoek.clone(options.encryption);
    decryptOptions.salt = encryptionSalt;

    try {
        decryptOptions.iv = B64.base64urlDecode(encryptionIv, 'buffer');
    }
    catch (err) {
        throw fail(err.message, {
            passwordId,
            stage: internals.stages.decrypt,
            component: internals.components.encryptionIv,
            cause: err
        });
    }

    const decrypted = await exports.decrypt(password.encryption, decryptOptions, encrypted);

    // Parse JSON

    try {
        return Bourne.parse(decrypted);
    }
    catch (err) {
        throw fail('Failed parsing sealed object JSON: ' + err.message, {
            passwordId,
            stage: internals.stages.decrypt,
            cause: err
        });
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

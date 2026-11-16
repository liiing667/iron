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


// Builds a uniform error for every unauthenticated unseal failure so that
// malformed input, unknown key ids and forged MACs cannot be told apart by
// an attacker from the error message (a local code is kept on err.data for
// legitimate callers).

internals.invalidSeal = function (code) {

    return new Boom.Boom('Invalid seal', { statusCode: 400, data: { code } });
};


// Parses and validates the sealed string structure before any cryptographic
// work is performed. The split is bounded so a malformed input cannot force an
// unbounded number of allocations, and every component is restricted to the
// character set produced by seal().

internals.parseSealed = function (sealed) {

    if (typeof sealed !== 'string') {
        throw internals.invalidSeal('malformed');
    }

    const parts = sealed.split('*', 9);                 // A valid seal is made of exactly 8 components
    if (parts.length !== 8) {
        throw internals.invalidSeal('malformed');
    }

    const [macPrefix, passwordId, encryptionSalt, encryptionIv, encryptedB64, expiration, hmacSalt, hmac] = parts;
    const macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' + encryptedB64 + '*' + expiration;

    const b64url = /^[A-Za-z0-9\-_]*$/;
    const hex = /^[0-9a-f]*$/;

    if (macPrefix !== exports.macPrefix ||
        !/^\w*$/.test(passwordId) ||
        !hex.test(encryptionSalt) ||
        !b64url.test(encryptionIv) ||
        !b64url.test(encryptedB64) ||
        !/^$|^\d+$/.test(expiration) ||
        !hex.test(hmacSalt) ||
        !b64url.test(hmac)) {

        throw internals.invalidSeal('malformed');
    }

    return {
        macPrefix,
        passwordId,
        encryptionSalt,
        encryptionIv,
        encryptedB64,
        expiration,
        hmacSalt,
        hmac,
        macBaseString
    };
};


// Holds the current sealing password together with the historical passwords
// still accepted when unsealing, keyed by the id embedded in the seal.

exports.Keyring = class Keyring {

    constructor(passwords, current) {

        const map = new Map();

        const add = (id, value) => {

            if (id !== undefined &&
                !/^\w+$/.test(id)) {

                throw new Boom.Boom('Invalid password id');
            }

            const normalized = internals.normalizePassword(value);
            if (!normalized.encryption ||
                !normalized.integrity) {

                throw new Boom.Boom('Empty password');
            }

            map.set(id || 'default', normalized);
        };

        if (passwords &&
            typeof passwords === 'object' &&
            !Buffer.isBuffer(passwords) &&
            ['secret', 'encryption', 'integrity'].some((field) => Object.prototype.hasOwnProperty.call(passwords, field))) {

            add(passwords.id, passwords);
            current = passwords.id || 'default';
        }
        else if (passwords &&
            typeof passwords === 'object' &&
            !Buffer.isBuffer(passwords)) {

            for (const [id, value] of Object.entries(passwords)) {
                add(id, value);
            }
        }
        else {
            add(undefined, passwords);
        }

        if (current === undefined) {
            current = map.has('default') ? 'default' : map.keys().next().value;
        }
        else if (!map.has(current)) {
            throw new Boom.Boom('Unknown password id: ' + current);
        }

        this._passwords = map;
        this._current = current;
    }

    get id() {

        return this._current;
    }

    get current() {

        return this._passwords.get(this._current);
    }

    resolve(id) {

        const password = this._passwords.get(id || 'default');
        if (!password) {
            throw internals.invalidSeal('unknown_id');
        }

        return password;
    }
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
    if (password instanceof exports.Keyring) {
        passwordId = password.id === 'default' ? '' : password.id;
        password = password.current;
    }
    else {
        password = internals.normalizePassword(password);
        if (password.id) {
            if (!/^\w+$/.test(password.id)) {
                throw new Boom.Boom('Invalid password id');
            }

            passwordId = password.id;
        }
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

    // Validate structure and component character sets before any crypto work

    const parts = internals.parseSealed(sealed);

    // Obtain password: an explicit keyring selects the current or a historical
    // key based on the id embedded in the seal, and fails closed on unknown ids.

    if (!password) {
        throw new Boom.Boom('Empty password');
    }

    if (password instanceof exports.Keyring) {
        password = password.resolve(parts.passwordId);
    }
    else if (typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        password = password[parts.passwordId || 'default'];
        if (!password) {
            throw internals.invalidSeal('unknown_id');
        }
    }

    password = internals.normalizePassword(password);

    // Verify the MAC while the seal is still unauthenticated; every failure up
    // to this point reports the same error to avoid acting as an oracle.

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = parts.hmacSalt;
    const mac = await exports.hmacWithPassword(password.integrity, macOptions, parts.macBaseString);

    if (!Cryptiles.fixedTimeComparison(mac.digest, parts.hmac)) {
        throw internals.invalidSeal('bad_mac');
    }

    // The seal is now authenticated, so checking its expiration cannot leak
    // information about forged or malformed input.

    if (parts.expiration) {
        const exp = parseInt(parts.expiration, 10);
        if (exp <= (now - (options.timestampSkewSec * 1000))) {
            throw new Boom.Boom('Expired seal');
        }
    }

    // Decrypt

    const encrypted = B64.base64urlDecode(parts.encryptedB64, 'buffer');

    const decryptOptions = Hoek.clone(options.encryption);
    decryptOptions.salt = parts.encryptionSalt;

    decryptOptions.iv = B64.base64urlDecode(parts.encryptionIv, 'buffer');

    let decrypted;
    try {
        decrypted = await exports.decrypt(password.encryption, decryptOptions, encrypted);
    }
    catch (err) {
        throw internals.invalidSeal('bad_payload');
    }

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

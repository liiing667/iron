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

    // Break string into components

    const parts = sealed.split('*');
    if (parts.length !== 8) {
        throw new Boom.Boom('Incorrect number of sealed components');
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

    // Check hmac

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
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


// Key rotation with revocation barrier
//
// A keyring manages the lifecycle of password ids used with seal() / unseal():
//
//      const keyring = new Iron.Keyring({ gracePeriodMsec: 60000 });
//      keyring.rotate('v1', password1);            // First key becomes current
//      const sealed = await keyring.seal(obj, Iron.defaults);
//      keyring.rotate('v2', password2);            // v1 demoted to historical (unseal-only)
//      keyring.revoke('v1');                       // Accepted until the grace period elapses
//
// The barrier: a revoked id keeps unsealing during the legitimate transition
// window (gracePeriodMsec, while the revocation propagates) and is rejected
// once that window has elapsed. Historical keys unseal but never seal. The
// current key is the only one used for new seals.

exports.Keyring = class {

    constructor(options = {}) {

        this._gracePeriodMsec = options.gracePeriodMsec ?? 0;
        this._keys = new Map();                         // id -> { password, current, revokedAt }
        this._currentId = null;
    }

    get current() {

        return this._currentId;
    }

    publish(id, password) {

        this._add(id, password);
        return this;
    }

    rotate(id, password) {

        const key = this._add(id, password);
        if (this._currentId) {
            this._keys.get(this._currentId).current = false;
        }

        key.current = true;
        this._currentId = id;
        return this;
    }

    revoke(id, now = Date.now()) {

        const key = this._get(id);
        if (key.current) {
            throw new Boom.Boom('Cannot revoke current key: ' + id);
        }

        if (key.revokedAt !== null) {
            throw new Boom.Boom('Key already revoked: ' + id);
        }

        key.revokedAt = now;
        return this;
    }

    status(id, now = Date.now()) {

        const key = this._keys.get(id);
        if (!key) {
            return undefined;
        }

        if (key.current) {
            return 'current';
        }

        if (key.revokedAt === null) {
            return 'historical';
        }

        return (now < key.revokedAt + this._gracePeriodMsec ? 'revoked' : 'retired');
    }

    async seal(object, options) {

        if (!this._currentId) {
            throw new Boom.Boom('Cannot seal without a current key');
        }

        const key = this._keys.get(this._currentId);
        return await exports.seal(object, { id: this._currentId, secret: key.password }, options);
    }

    async unseal(sealed, options) {

        options = Object.assign({}, options);                                       // Shallow cloned to prevent changes during async operations

        const now = Date.now() + (options.localtimeOffsetMsec ?? 0);                // Same clock used for expiration checks

        // Break string into components (validated again by unseal)

        const parts = sealed.split('*');
        if (parts.length !== 8) {
            throw new Boom.Boom('Incorrect number of sealed components');
        }

        const id = parts[1] || 'default';
        const key = this._keys.get(id);
        if (key) {
            this._assertUsable(key, id, now);                                       // Barrier: retired keys never hit
            return await exports.unseal(sealed, key.password, options);
        }

        // Failure fallback: unknown id, try each usable key (current first)

        const usable = this._usable(now);
        if (!usable.length) {
            throw new Boom.Boom('Cannot find password: ' + id);
        }

        let error = null;
        for (const candidate of usable) {
            try {
                return await exports.unseal(sealed, candidate.password, options);
            }
            catch (err) {
                error = err;
            }
        }

        throw error;
    }

    _add(id, password) {

        if (!id ||
            typeof id !== 'string' ||
            !/^\w+$/.test(id)) {

            throw new Boom.Boom('Invalid key id');
        }

        if (!password ||
            (typeof password !== 'string' && !Buffer.isBuffer(password))) {

            throw new Boom.Boom('Password must be a string or buffer');
        }

        if (this._keys.has(id)) {
            throw new Boom.Boom('Duplicate key id: ' + id);
        }

        const key = { password, current: false, revokedAt: null };
        this._keys.set(id, key);
        return key;
    }

    _get(id) {

        const key = this._keys.get(id);
        if (!key) {
            throw new Boom.Boom('Unknown key id: ' + id);
        }

        return key;
    }

    _assertUsable(key, id, now) {

        if (key.revokedAt !== null &&
            now >= key.revokedAt + this._gracePeriodMsec) {

            throw new Boom.Boom('Cannot unseal with retired key: ' + id);
        }
    }

    _usable(now) {

        const keys = [];
        for (const [id, key] of this._keys) {
            try {
                this._assertUsable(key, id, now);
                keys.push(key);
            }
            catch (err) {
                continue;                   // Skip retired keys
            }
        }

        return keys.sort((a, b) => Number(b.current) - Number(a.current));
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

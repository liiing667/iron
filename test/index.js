'use strict';

const Crypto = require('crypto');

const B64 = require('@hapi/b64');
const Code = require('@hapi/code');
const Cryptiles = require('@hapi/cryptiles');
const Hoek = require('@hapi/hoek');
const Iron = require('..');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Iron', () => {

    const obj = {
        a: 1,
        b: 2,
        c: [3, 4, 5],
        d: {
            e: 'f'
        }
    };

    const password = 'some_not_random_password_that_is_also_long_enough';

    it('turns object into a ticket than parses the ticket successfully', async () => {

        const sealed = await Iron.seal(obj, password, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, { 'default': password }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('unseal and sealed object with expiration', async () => {

        const options = Hoek.clone(Iron.defaults);
        options.ttl = 200;
        const sealed = await Iron.seal(obj, password, options);
        const unsealed = await Iron.unseal(sealed, { 'default': password }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('unseal and sealed object with expiration and time offset', async () => {

        const options = Hoek.clone(Iron.defaults);
        options.ttl = 200;
        options.localtimeOffsetMsec = -100000;
        const sealed = await Iron.seal(obj, password, options);

        const options2 = Hoek.clone(Iron.defaults);
        options2.localtimeOffsetMsec = -100000;
        const unsealed = await Iron.unseal(sealed, { 'default': password }, options2);
        expect(unsealed).to.equal(obj);
    });

    it('unseal and sealed object without time offset', async () => {

        const options = Hoek.clone(Iron.defaults);
        options.ttl = 200;
        delete options.localtimeOffsetMsec;
        const sealed = await Iron.seal(obj, password, options);

        const options2 = Hoek.clone(Iron.defaults);
        delete options2.localtimeOffsetMsec;
        const unsealed = await Iron.unseal(sealed, { 'default': password }, options2);
        expect(unsealed).to.equal(obj);
    });

    it('turns object into a ticket than parses the ticket successfully (password buffer)', async () => {

        const key = Cryptiles.randomBits(256);
        const sealed = await Iron.seal(obj, key, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, key, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('turns object into a ticket than parses the ticket successfully (password buffer in object)', async () => {

        const key = Cryptiles.randomBits(256);
        const sealed = await Iron.seal(obj, key, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, { 'default': key }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('fails to turns object into a ticket (password buffer too short)', async () => {

        const key = Cryptiles.randomBits(128);
        const err = await expect(Iron.seal(obj, key, Iron.defaults)).to.reject('Key buffer (password) too small');
        expect(err.isBoom).to.be.true();
    });

    it('fails to turn object into a ticket (failed to stringify object)', async () => {

        const cyclic = [];
        cyclic[0] = cyclic;
        const key = Cryptiles.randomBits(128);
        const err = await expect(Iron.seal(cyclic, key, Iron.defaults)).to.reject(/Failed to stringify object: Converting circular structure to JSON/);
        expect(err.isBoom).to.be.true();
    });

    it('turns object into a ticket than parses the ticket successfully (password object)', async () => {

        const sealed = await Iron.seal(obj, { id: '1', secret: password }, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, { '1': password }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('handles separate password buffers (password object)', async () => {

        const key = {
            id: '1',
            encryption: Cryptiles.randomBits(256),
            integrity: Cryptiles.randomBits(256)
        };

        const sealed = await Iron.seal(obj, key, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, { '1': key }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('handles a common password buffer (password object)', async () => {

        const key = {
            id: '1',
            secret: Cryptiles.randomBits(256)
        };

        const sealed = await Iron.seal(obj, key, Iron.defaults);
        const unsealed = await Iron.unseal(sealed, { '1': key }, Iron.defaults);
        expect(unsealed).to.equal(obj);
    });

    it('fails to parse a sealed object when password not found', async () => {

        const sealed = await Iron.seal(obj, { id: '1', secret: password }, Iron.defaults);
        const err = await expect(Iron.unseal(sealed, { '2': password }, Iron.defaults)).to.reject('Cannot find password: 1');
        expect(err.isBoom).to.be.true();
    });

    describe('generateKey()', () => {

        it('returns an error when password is missing', async () => {

            const err = await expect(Iron.generateKey(null, null)).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when password is too short', async () => {

            const err = await expect(Iron.generateKey('password', Iron.defaults.encryption)).to.reject('Password string too short (min 32 characters required)');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when options are missing', async () => {

            const err = await expect(Iron.generateKey(password, null)).to.reject('Bad options');
            expect(err.isBoom).to.be.true();

            await expect(Iron.generateKey(password, 'abc')).to.reject('Bad options');
        });

        it('returns an error when an unknown algorithm is specified', async () => {

            const err = await expect(Iron.generateKey(password, { algorithm: 'unknown' })).to.reject('Unknown algorithm: unknown');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when no salt and no salt bits are provided', async () => {

            const options = {
                algorithm: 'sha256',
                iterations: 2
            };

            const err = await expect(Iron.generateKey(password, options)).to.reject('Missing salt and saltBits options');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when invalid salt bits are provided', async () => {

            const options = {
                saltBits: 99999999999999999999,
                algorithm: 'sha256',
                iterations: 2
            };

            const err = await expect(Iron.generateKey(password, options)).to.reject(/Failed generating random bits/);
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when Cryptiles.randomBits fails', async () => {

            const options = Hoek.clone(Iron.defaults.encryption);
            options.salt = 'abcdefg';
            options.algorithm = 'x';
            Iron.algorithms.x = { keyBits: 256, ivBits: -1 };

            const err = await expect(Iron.generateKey(password, options)).to.reject('Invalid random bits count');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when Crypto.pbkdf2 fails', async () => {

            const orig = Crypto.pbkdf2;
            Crypto.pbkdf2 = (...args) => args[args.length - 1](new Error('fake'));

            const err = await expect(Iron.generateKey(password, Iron.defaults.encryption)).to.reject('fake');
            Crypto.pbkdf2 = orig;
            expect(err.isBoom).to.be.true();
        });
    });

    describe('encrypt()', () => {

        it('returns an error when password is missing', async () => {

            const err = await expect(Iron.encrypt(null, null, 'data')).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });
    });

    describe('decrypt', () => {

        it('returns an error when password is missing', async () => {

            const err = await expect(Iron.decrypt(null, null, 'data')).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });
    });

    describe('hmacWithPassword()', () => {

        it('returns an error when password is missing', async () => {

            const err = await expect(Iron.hmacWithPassword(null, null, 'data')).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });

        it('produces the same mac when used with buffer password', async () => {

            const data = 'Not so random';
            const key = Cryptiles.randomBits(256);
            const hmac = Crypto.createHmac(Iron.defaults.integrity.algorithm, key).update(data);
            const digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

            const mac = await Iron.hmacWithPassword(key, Iron.defaults.integrity, data);
            expect(mac.digest).to.equal(digest);
        });
    });

    describe('seal()', () => {

        it('returns an error when password is missing', async () => {

            const err = await expect(Iron.seal('data', null, {})).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when integrity options are missing', async () => {

            const options = {
                encryption: {
                    saltBits: 256,
                    algorithm: 'aes-256-cbc',
                    iterations: 1
                },
                integrity: {}
            };

            const err = await expect(Iron.seal('data', password, options)).to.reject('Unknown algorithm: undefined');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when password.id is invalid', async () => {

            const err = await expect(Iron.seal('data', { id: 'asd$', secret: 'asd' }, {})).to.reject('Invalid password id');
            expect(err.isBoom).to.be.true();
        });
    });

    describe('unseal()', () => {

        it('unseals a ticket', async () => {

            const ticket = 'Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI';
            const unsealed = await Iron.unseal(ticket, password, Iron.defaults);
            expect(unsealed).to.equal(obj);
        });

        it('returns an error when number of sealed components is wrong', async () => {

            const ticket = 'x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Incorrect number of sealed components');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when password is missing', async () => {

            const ticket = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            const err = await expect(Iron.unseal(ticket, null, Iron.defaults)).to.reject('Empty password');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when mac prefix is wrong', async () => {

            const ticket = 'Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Wrong mac prefix');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when integrity check fails', async () => {

            const ticket = 'Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ';
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Bad hmac value');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when decryption fails', async () => {

            const macBaseString = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??*';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
            const mac = await Iron.hmacWithPassword(password, options, macBaseString);
            const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Invalid character');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when iv base64 decoding fails', async () => {

            const macBaseString = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M*';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
            const mac = await Iron.hmacWithPassword(password, options, macBaseString);
            const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Invalid character');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when decrypted object is invalid', async () => {

            const badJson = '{asdasd';
            const { encrypted, key } = await Iron.encrypt(password, Iron.defaults.encryption, badJson);
            const encryptedB64 = B64.base64urlEncode(encrypted);
            const iv = B64.base64urlEncode(key.iv);
            const macBaseString = Iron.macPrefix + '**' + key.salt + '*' + iv + '*' + encryptedB64 + '*';
            const mac = await Iron.hmacWithPassword(password, Iron.defaults.integrity, macBaseString);
            const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject(/Failed parsing sealed object JSON: Unexpected token a/);
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when expired', async () => {

            const macBaseString = 'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
            const mac = await Iron.hmacWithPassword(password, options, macBaseString);
            const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Expired seal');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when expiration NaN', async () => {

            const macBaseString = 'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
            const mac = await Iron.hmacWithPassword(password, options, macBaseString);
            const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
            const err = await expect(Iron.unseal(ticket, password, Iron.defaults)).to.reject('Invalid expiration');
            expect(err.isBoom).to.be.true();
        });
    });

    describe('Keyring', () => {

        const password2 = 'another_not_random_password_that_is_long_enough';

        it('starts empty without options', () => {

            const keyring = new Iron.Keyring();
            expect(keyring.current).to.be.null();
            expect(keyring.status('v1')).to.be.undefined();
        });

        it('starts empty with partial options', () => {

            const keyring = new Iron.Keyring({});
            expect(keyring.current).to.be.null();
        });

        it('rotates keys and tracks current and historical status', async () => {

            const keyring = new Iron.Keyring({ gracePeriodMsec: 1000 });
            keyring.rotate('v1', password);
            expect(keyring.current).to.equal('v1');
            expect(keyring.status('v1')).to.equal('current');

            keyring.rotate('v2', password2);
            expect(keyring.current).to.equal('v2');
            expect(keyring.status('v1')).to.equal('historical');
            expect(keyring.status('v2')).to.equal('current');

            const sealed1 = await keyring.unseal(await keyring.seal(obj, Iron.defaults), Iron.defaults);
            expect(sealed1).to.equal(obj);
        });

        it('publishes a key without promoting it', () => {

            const keyring = new Iron.Keyring();
            keyring.publish('v1', password);
            expect(keyring.current).to.be.null();
            expect(keyring.status('v1')).to.equal('historical');
        });

        it('returns an error when key id is invalid', () => {

            const keyring = new Iron.Keyring();
            expect(() => keyring.publish(null, password)).to.throw('Invalid key id');
            expect(() => keyring.publish(1, password)).to.throw('Invalid key id');
            expect(() => keyring.publish('a$b', password)).to.throw('Invalid key id');
        });

        it('returns an error when password is invalid', () => {

            const keyring = new Iron.Keyring();
            expect(() => keyring.publish('v1', null)).to.throw('Password must be a string or buffer');
            expect(() => keyring.publish('v1', { secret: password })).to.throw('Password must be a string or buffer');
        });

        it('returns an error when key id is a duplicate', () => {

            const keyring = new Iron.Keyring();
            keyring.publish('v1', password);
            expect(() => keyring.publish('v1', password)).to.throw('Duplicate key id: v1');
            expect(() => keyring.rotate('v1', password)).to.throw('Duplicate key id: v1');
        });

        it('supports buffer passwords', async () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', Cryptiles.randomBits(256));
            const sealed = await keyring.seal(obj, Iron.defaults);
            const unsealed = await keyring.unseal(sealed, Iron.defaults);
            expect(unsealed).to.equal(obj);
        });

        it('returns an error when revoking an unknown key', () => {

            const keyring = new Iron.Keyring();
            expect(() => keyring.revoke('v1')).to.throw('Unknown key id: v1');
        });

        it('returns an error when revoking the current key', () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', password);
            expect(() => keyring.revoke('v1')).to.throw('Cannot revoke current key: v1');
        });

        it('returns an error when revoking an already revoked key', () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', password);
            keyring.rotate('v2', password2);
            keyring.revoke('v1');
            expect(() => keyring.revoke('v1')).to.throw('Key already revoked: v1');
        });

        it('reports revoked and retired status around the grace boundary', () => {

            const keyring = new Iron.Keyring({ gracePeriodMsec: 1000 });
            keyring.rotate('v1', password);
            keyring.rotate('v2', password2);
            keyring.revoke('v1');

            expect(keyring.status('v1')).to.equal('revoked');
            expect(keyring.status('v1', Date.now() + 999)).to.equal('revoked');
            expect(keyring.status('v1', Date.now() + 1000)).to.equal('retired');
        });

        it('returns an error when sealing without a current key', async () => {

            const keyring = new Iron.Keyring();
            keyring.publish('v1', password);
            const err = await expect(keyring.seal(obj, Iron.defaults)).to.reject('Cannot seal without a current key');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when sealed components are wrong', async () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', password);
            const err = await expect(keyring.unseal('a*b*c', Iron.defaults)).to.reject('Incorrect number of sealed components');
            expect(err.isBoom).to.be.true();
        });

        it('unseals historical keys but seals only with the current key', async () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', password);
            const sealed1 = await keyring.seal(obj, Iron.defaults);

            keyring.rotate('v2', password2);
            const sealed2 = await keyring.seal(obj, Iron.defaults);

            expect(sealed1.split('*')[1]).to.equal('v1');
            expect(sealed2.split('*')[1]).to.equal('v2');
            expect(await keyring.unseal(sealed1, Iron.defaults)).to.equal(obj);
            expect(await keyring.unseal(sealed2, Iron.defaults)).to.equal(obj);
        });

        it('rejects retired keys after revocation propagates', async () => {

            const keyring = new Iron.Keyring();                                 // Zero grace period
            keyring.rotate('v1', password);
            const sealed = await keyring.seal(obj, Iron.defaults);
            keyring.rotate('v2', password2);
            keyring.revoke('v1');

            const options = Hoek.clone(Iron.defaults);
            delete options.localtimeOffsetMsec;
            const err = await expect(keyring.unseal(sealed, options)).to.reject('Cannot unseal with retired key: v1');
            expect(err.isBoom).to.be.true();
        });

        it('returns an error when id is unknown and no key is usable', async () => {

            const keyring = new Iron.Keyring();
            const sealed = await Iron.seal(obj, password, Iron.defaults);
            const err = await expect(keyring.unseal(sealed, Iron.defaults)).to.reject('Cannot find password: default');
            expect(err.isBoom).to.be.true();
        });

        it('skips retired keys when falling back', async () => {

            const keyring = new Iron.Keyring();                                 // Zero grace period
            keyring.rotate('v1', password);
            keyring.rotate('v2', password2);
            keyring.revoke('v1');

            const sealed = await Iron.seal(obj, { id: 'v9', secret: password }, Iron.defaults);
            const err = await expect(keyring.unseal(sealed, Iron.defaults)).to.reject('Bad hmac value');
            expect(err.isBoom).to.be.true();
        });

        it('falls back to usable keys when id is unknown', async () => {

            const keyring = new Iron.Keyring();
            keyring.rotate('v1', password);
            keyring.rotate('v2', password2);
            const sealed = await Iron.seal(obj, { id: 'v9', secret: password }, Iron.defaults);
            const unsealed = await keyring.unseal(sealed, Iron.defaults);
            expect(unsealed).to.equal(obj);
        });

        it('returns an error when id is unknown and every usable key is retired', async () => {

            const keyring = new Iron.Keyring();                                 // Zero grace period
            keyring.publish('v1', password);
            keyring.publish('v2', password2);
            keyring.revoke('v1');
            keyring.revoke('v2');

            const sealed = await Iron.seal(obj, { id: 'v9', secret: password }, Iron.defaults);
            const err = await expect(keyring.unseal(sealed, Iron.defaults)).to.reject('Cannot find password: v9');
            expect(err.isBoom).to.be.true();
        });

        it('enforces the rotation barrier across a fixed concurrency fixture', async () => {

            const keyring = new Iron.Keyring({ gracePeriodMsec: 1000 });

            // Generation 1: eight seals under v1

            keyring.rotate('v1', password);
            const generation1 = [];
            for (let i = 0; i < 8; ++i) {
                generation1.push(await keyring.seal(Object.assign({ n: i }, obj), Iron.defaults));
            }

            // Switch boundary: v2 becomes current, v1 revoked (propagates after grace period)

            keyring.rotate('v2', password2);
            const generation2 = await keyring.seal(obj, Iron.defaults);
            keyring.revoke('v1');

            // Transition window: concurrent unseals of both generations succeed

            const transition = await Promise.all([
                ...generation1.map((sealed) => keyring.unseal(sealed, Iron.defaults)),
                keyring.unseal(generation2, Iron.defaults)
            ]);

            expect(transition.length).to.equal(9);
            expect(transition[3].n).to.equal(3);

            // After propagation: concurrent unseals of generation 1 all hit the barrier

            const propagated = Hoek.clone(Iron.defaults);
            propagated.localtimeOffsetMsec = 1000;

            const settled = await Promise.all([
                ...generation1.map((sealed) => keyring.unseal(sealed, propagated).then((value) => value, (err) => err)),
                keyring.unseal(generation2, propagated)
            ]);

            for (let i = 0; i < 8; ++i) {
                expect(settled[i]).to.be.an.error('Cannot unseal with retired key: v1');
            }

            expect(settled[8]).to.equal(obj);

            // Final state: v1 retired, v2 the only usable key

            expect(keyring.status('v1', Date.now() + 1000)).to.equal('retired');
            expect(keyring.status('v2')).to.equal('current');
            expect(keyring.current).to.equal('v2');
        });
    });
});

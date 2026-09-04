import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const MD = certkit.md;
const PBKDF2 = certkit.pbkdf2;
const UTIL = certkit.util;
var CERTKIT = certkit;
describe('pbkdf2', function () {
  it('should derive a password with hmac-sha-1 c=1', (ctx) => {
    var dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 1, 20, 'sha1'));
    expect(dkHex).toBe('0c60c80f961f0e71f3a9b524af6012062fe037a6');
  });

  it('should derive a password with hmac-sha-1 c=2', (ctx) => {
    var dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 2, 20, 'sha1'));
    expect(dkHex).toBe('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
  });

  it('should derive a password with hmac-sha-1 c=5 keylen=8', (ctx) => {
    var salt = UTIL.hexToBytes('1234567878563412');
    var dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 5, 8, 'sha1'));
    expect(dkHex).toBe('d1daa78615f287e6');
  });

  it('should derive a utf8 password with hmac-sha-1 c=1 keylen=16', (ctx) => {
    var dkHex = UTIL.bytesToHex(PBKDF2('中', 'salt', 1, 16, 'sha1'));
    expect(dkHex).toBe('5f719aa196edc4df6b1556de503faaf3');
  });

  it('should derive a password with hmac-sha-1 c=4096', (ctx) => {
    // Note: might be too slow on old browsers
    var dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 4096, 20, 'sha1'));
    expect(dkHex).toBe('4b007901b765489abead49d926f721d065a429c1');
  });

  /*
    it('should derive a password with hmac-sha-1 c=16777216', (ctx) => {
      // Note: too slow
      var dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 16777216, 20));
      expect(dkHex).toBe('eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
    });*/

  it('should derive a password with hmac-sha-256 c=1000', (ctx) => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var md = MD.sha256.create();
    var dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, md));
    expect(dkHex).toBe(
      '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2'
    );
  });

  it('should derive a password with hmac-sha-256 (passed as an algorithm identifier) c=1000', (ctx) => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, 'sha256'));
    expect(dkHex).toBe(
      '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2'
    );
  });

  it('should derive a password with hmac-sha-512 c=1000', (ctx) => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var md = MD.sha512.create();
    var dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, md));
    expect(dkHex).toBe(
      '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3'
    );
  });

  it('should derive a password with hmac-sha-512 (passed as an algorithm identifier) c=1000', (ctx) => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, 'sha512'));
    expect(dkHex).toBe(
      '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3'
    );
  });

  it('should asynchronously derive a password with hmac-sha-1 c=1', async () => {
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', 'salt', 1, 20, 'sha1', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe('0c60c80f961f0e71f3a9b524af6012062fe037a6');

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-1 c=2', async () => {
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', 'salt', 2, 20, 'sha1', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-1 c=5 keylen=8', async () => {
    var salt = UTIL.hexToBytes('1234567878563412');
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', salt, 5, 8, 'sha1', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe('d1daa78615f287e6');

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-1 c=4096', async () => {
    // Note: might be too slow on old browsers
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', 'salt', 4096, 20, 'sha1', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe('4b007901b765489abead49d926f721d065a429c1');

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  /*
    it('should asynchronously derive a password with hmac-sha-1 c=16777216', async () => {
      // Note: too slow
      await new Promise<void>((resolve, reject) => {
        PBKDF2('password', 'salt', 16777216, 20, function(err, dk) {
          try {

        expect(err).toBeFalsy();
        var dkHex = UTIL.bytesToHex(dk);
        expect(dkHex).toBe('eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
        
            resolve();
          } catch (e) {
            reject(e);
          }
        });
      });
    });*/

  it('should asynchronously derive a password with hmac-sha-256 c=1000', async () => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var md = MD.sha256.create();
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', salt, 1000, 48, md, function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe(
            '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2'
          );

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-256 (passed as an algorithm identifier) c=1000', async () => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', salt, 1000, 48, 'sha256', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe(
            '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2'
          );

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-512 c=1000', async () => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    var md = MD.sha512.create();
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', salt, 1000, 48, md, function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe(
            '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3'
          );

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should asynchronously derive a password with hmac-sha-512 (passed as an algorithm identifier) c=1000', async () => {
    // Note: might be too slow on old browsers
    var salt = '4bcda0d1c689fe465c5b8a817f0ddf3d';
    await new Promise<void>((resolve, reject) => {
      PBKDF2('password', salt, 1000, 48, 'sha512', function (err, dk) {
        try {
          expect(err).toBeFalsy();
          var dkHex = UTIL.bytesToHex(dk!);
          expect(dkHex).toBe(
            '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3'
          );

          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should derive a password with "usePureJavaScript"', (ctx) => {
    // save
    var purejs = CERTKIT.options.usePureJavaScript;
    // test possible native mode
    CERTKIT.options.usePureJavaScript = false;
    var dkHex0 = UTIL.bytesToHex(PBKDF2('password', 'salt', 1024, 20, 'sha1'));
    // test pure mode
    CERTKIT.options.usePureJavaScript = true;
    var dkHex1 = UTIL.bytesToHex(PBKDF2('password', 'salt', 1024, 20, 'sha1'));
    // check
    expect(dkHex0).toBe('f9d39c571d66a03c2a71a81535b0c2d0396b500a');
    expect(dkHex0).toBe(dkHex1);
    // restore
    CERTKIT.options.usePureJavaScript = purejs;
  });
});

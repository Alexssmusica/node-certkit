import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const CIPHER = certkit.cipher;
const DES = certkit.des;
const UTIL = certkit.util;
describe('des', () => {
  // OpenSSL equivalent:
  // openssl enc -des-ecb -K a1c06b381adf3651 -nosalt
  it('should des-ecb encrypt: foobar', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));

    const cipher = CIPHER.createCipher('DES-ECB', key);
    cipher.start();
    cipher.update(UTIL.createBuffer('foobar'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('b705ffcf3dff06b3');
  });

  // OpenSSL equivalent:
  // openssl enc -d -des-ecb -K a1c06b381adf3651 -nosalt
  it('should des-ecb decrypt: b705ffcf3dff06b3', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));

    const decipher = CIPHER.createDecipher('DES-ECB', key);
    decipher.start();
    decipher.update(UTIL.createBuffer(UTIL.hexToBytes('b705ffcf3dff06b3')));
    decipher.finish();
    expect(decipher.output!.getBytes()).toBe('foobar');
  });

  it('should check des-cbc short IV', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc596'));

    let error = null;
    try {
      const cipher = CIPHER.createCipher('DES-CBC', key);
      cipher.start({ iv: iv });
    } catch (e) {
      error = e;
    }
    expect(error, 'blocksize check should have failed').toBeTruthy();
  });

  // OpenSSL equivalent:
  // openssl enc -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
  it('should des-cbc encrypt: foobar', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const cipher = CIPHER.createCipher('DES-CBC', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer('foobar'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('3261e5839a990454');
  });

  // OpenSSL equivalent:
  // openssl enc -d -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
  it('should des-cbc decrypt: 3261e5839a990454', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const decipher = CIPHER.createDecipher('DES-CBC', key);
    decipher.start({ iv: iv });
    decipher.update(UTIL.createBuffer(UTIL.hexToBytes('3261e5839a990454')));
    decipher.finish();
    expect(decipher.output!.getBytes()).toBe('foobar');
  });

  // play.golang.org/p/LX_dP0cFuEt
  it('should des-ctr encrypt: foobar', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const cipher = CIPHER.createCipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer('foobar'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('3a97fa79e631');
  });

  // play.golang.org/p/6_MQBYzn04c
  it('should des-ctr decrypt: foobar', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('beefdeadbeefdead'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('deadbeefdeadbeef'));

    const cipher = CIPHER.createDecipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer(UTIL.hexToBytes('6df74b7b4437')));
    cipher.finish();
    expect(cipher.output!.getBytes()).toBe('foobar');
  });

  // play.golang.org/p/i892aR7YsGK
  it('should des-ctr encrypt: dead parrot', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const cipher = CIPHER.createCipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer('dead parrot'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('389df47fa733dcf4b99b7c');
  });

  // play.golang.org/p/6L0LqPS9ARt
  it('should des-ctr decrypt: 79f1527c5737f774f85c1a9399755d895ae7', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('beefdeadbeefdead'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('deadbeefdeadbeef'));

    const cipher = CIPHER.createDecipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer(UTIL.hexToBytes('79f1527c5737f774f85c1a9399755d895ae7')));
    cipher.finish();
    expect(cipher.output!.getBytes()).toBe('riverrun, past Eve');
  });

  // play.golang.org/p/WsSx6BXJniU
  it('should des-ctr encrypt: 69742773206e6f742073696c6c7920656e6f756768', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf3651'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const cipher = CIPHER.createCipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer(UTIL.hexToBytes('69742773206e6f742073696c6c7920656e6f756768')));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('358cb268a72dd2f2eb87615060bd3a490e85136873');
  });

  // play.golang.org/p/y01inAlMCEM
  it('should des-ctr decrypt: 0a80bd81a4dc1303a62f', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('beefdeadbeefdead'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('deadbeefdeadbeef'));

    const cipher = CIPHER.createDecipher('DES-CTR', key);
    cipher.start({ iv: iv });
    cipher.update(UTIL.createBuffer(UTIL.hexToBytes('0a80bd81a4dc1303a62f')));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('01189998819991197253');
  });

  // OpenSSL equivalent:
  // openssl enc -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt
  it('should 3des-ecb encrypt: foobar', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));

    const cipher = CIPHER.createCipher('3DES-ECB', key);
    cipher.start();
    cipher.update(UTIL.createBuffer('foobar'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('fce8b1ee8c6440d1');
  });

  // OpenSSL equivalent:
  // openssl enc -d -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt
  it('should 3des-ecb decrypt: fce8b1ee8c6440d1', (ctx) => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));

    const decipher = CIPHER.createDecipher('3DES-ECB', key);
    decipher.start();
    decipher.update(UTIL.createBuffer(UTIL.hexToBytes('fce8b1ee8c6440d1')));
    decipher.finish();
    expect(decipher.output!.getBytes()).toBe('foobar');
  });

  // OpenSSL equivalent:
  // openssl enc -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
  it('should 3des-cbc encrypt "foobar", restart, and encrypt "foobar,,"', () => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const cipher = CIPHER.createCipher('3DES-CBC', key);
    cipher.start({ iv: iv.copy() });
    cipher.update(UTIL.createBuffer('foobar'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('209225f7687ca0b2');

    cipher.start({ iv: iv.copy() });
    cipher.update(UTIL.createBuffer('foobar,,'));
    cipher.finish();
    expect(cipher.output!.toHex()).toBe('57156174c48dfc37293831bf192a6742');
  });

  // OpenSSL equivalent:
  // openssl enc -d -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
  it('should 3des-cbc decrypt "209225f7687ca0b2", restart, and decrypt "57156174c48dfc37293831bf192a6742,,"', () => {
    const key = UTIL.createBuffer(UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));
    const iv = UTIL.createBuffer(UTIL.hexToBytes('818bcf76efc59662'));

    const decipher = CIPHER.createDecipher('3DES-CBC', key);
    decipher.start({ iv: iv.copy() });
    decipher.update(UTIL.createBuffer(UTIL.hexToBytes('209225f7687ca0b2')));
    decipher.finish();
    expect(decipher.output!.getBytes()).toBe('foobar');

    decipher.start({ iv: iv.copy() });
    decipher.update(UTIL.createBuffer(UTIL.hexToBytes('57156174c48dfc37293831bf192a6742')));
    decipher.finish();
    expect(decipher.output!.getBytes()).toBe('foobar,,');
  });
});

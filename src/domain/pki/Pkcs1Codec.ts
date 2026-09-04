import { Sha1 } from '../digest/Sha1.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import type { MessageDigest } from './Mgf1.js';

export type RsaOaepKey = {
  n: { bitLength(): number };
};

export type RsaOaepOptions = {
  label?: string;
  seed?: string;
  md?: MessageDigest;
  mgf1?: { md?: MessageDigest };
};

function rsaMgf1(seed: string, maskLength: number, hash?: MessageDigest): string {
  if (!hash) {
    hash = Sha1.create();
  }
  let t = '';
  const count = Math.ceil(maskLength / hash.digestLength);
  for (let i = 0; i < count; ++i) {
    const c = String.fromCharCode((i >> 24) & 0xff, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
    hash.start();
    hash.update(seed + c);
    t += hash.digest().getBytes();
  }
  return t.substring(0, maskLength);
}

export class Pkcs1Codec {
  static encodeRsaOaep(
    key: RsaOaepKey,
    message: string,
    options?: RsaOaepOptions | string,
    seedArg?: string,
    mdArg?: MessageDigest,
    getRandomBytes?: (count: number) => string
  ): string {
    let label: string | undefined;
    let seed: string | undefined;
    let md: MessageDigest | undefined;
    let mgf1Md: MessageDigest | undefined;

    if (typeof options === 'string') {
      label = options;
      seed = seedArg;
      md = mdArg;
    } else if (options) {
      label = options.label;
      seed = options.seed;
      md = options.md;
      if (options.mgf1?.md) {
        mgf1Md = options.mgf1.md;
      }
    }

    if (!md) {
      md = Sha1.create();
    } else {
      md.start();
    }

    if (!mgf1Md) {
      mgf1Md = md;
    }

    const keyLength = Math.ceil(key.n.bitLength() / 8);
    const maxLength = keyLength - 2 * md.digestLength - 2;
    if (message.length > maxLength) {
      const error = new Error('RSAES-OAEP input message length is too long.') as Error & {
        length?: number;
        maxLength?: number;
      };
      error.length = message.length;
      error.maxLength = maxLength;
      throw error;
    }

    if (!label) {
      label = '';
    }
    md.update(label);
    const lHash = md.digest();

    const PS_length = maxLength - message.length;
    const PS = UtilNamespace.fillString('\x00', PS_length);
    const DB = lHash.getBytes() + PS + '\x01' + message;

    if (!seed) {
      if (!getRandomBytes) {
        throw new Error('Random byte source required for OAEP encoding');
      }
      seed = getRandomBytes(md.digestLength);
    } else if (seed.length !== md.digestLength) {
      const error = new Error('Invalid RSAES-OAEP seed. The seed length must match the digest length.') as Error & {
        seedLength?: number;
        digestLength?: number;
      };
      error.seedLength = seed.length;
      error.digestLength = md.digestLength;
      throw error;
    }

    const dbMask = rsaMgf1(seed, keyLength - md.digestLength - 1, mgf1Md);
    const maskedDB = UtilNamespace.xorBytes(DB, dbMask, DB.length);
    const seedMask = rsaMgf1(maskedDB, md.digestLength, mgf1Md);
    const maskedSeed = UtilNamespace.xorBytes(seed, seedMask, seed.length);

    return '\x00' + maskedSeed + maskedDB;
  }

  static decodeRsaOaep(key: RsaOaepKey, em: string, options?: RsaOaepOptions | string, mdArg?: MessageDigest): string {
    let label: string | undefined;
    let md: MessageDigest | undefined;
    let mgf1Md: MessageDigest | undefined;

    if (typeof options === 'string') {
      label = options;
      md = mdArg;
    } else if (options) {
      label = options.label;
      md = options.md;
      if (options.mgf1?.md) {
        mgf1Md = options.mgf1.md;
      }
    }

    const keyLength = Math.ceil(key.n.bitLength() / 8);

    if (em.length !== keyLength) {
      const error = new Error('RSAES-OAEP encoded message length is invalid.') as Error & {
        length?: number;
        expectedLength?: number;
      };
      error.length = em.length;
      error.expectedLength = keyLength;
      throw error;
    }

    if (md === undefined) {
      md = Sha1.create();
    } else {
      md.start();
    }

    if (!mgf1Md) {
      mgf1Md = md;
    }

    if (keyLength < 2 * md.digestLength + 2) {
      throw new Error('RSAES-OAEP key is too short for the hash function.');
    }

    if (!label) {
      label = '';
    }
    md.update(label);
    const lHash = md.digest().getBytes();

    const y = em.charAt(0);
    const maskedSeed = em.substring(1, md.digestLength + 1);
    const maskedDB = em.substring(1 + md.digestLength);

    const seedMask = rsaMgf1(maskedDB, md.digestLength, mgf1Md);
    const seed = UtilNamespace.xorBytes(maskedSeed, seedMask, maskedSeed.length);
    const dbMask = rsaMgf1(seed, keyLength - md.digestLength - 1, mgf1Md);
    const db = UtilNamespace.xorBytes(maskedDB, dbMask, maskedDB.length);
    const lHashPrime = db.substring(0, md.digestLength);

    let error: number = y !== '\x00' ? 1 : 0;

    for (let i = 0; i < md.digestLength; ++i) {
      error |= lHash.charAt(i) !== lHashPrime.charAt(i) ? 1 : 0;
    }

    let in_ps = 1;
    let index = md.digestLength;
    for (let j = md.digestLength; j < db.length; j++) {
      const code = db.charCodeAt(j);
      const is_0 = (code & 0x1) ^ 0x1;
      const error_mask = in_ps ? 0xfffe : 0x0000;
      error |= code & error_mask ? 1 : 0;
      in_ps = in_ps & is_0;
      index += in_ps;
    }

    if (error || db.charCodeAt(index) !== 0x1) {
      throw new Error('Invalid RSAES-OAEP padding.');
    }

    return db.substring(index + 1);
  }

  static createCertkitNamespace(getRandomBytes: (count: number) => string): {
    encode_rsa_oaep: (key: RsaOaepKey, message: string, options?: RsaOaepOptions | string) => string;
    decode_rsa_oaep: (key: RsaOaepKey, em: string, options?: RsaOaepOptions | string) => string;
  } {
    return {
      encode_rsa_oaep(key, message, options) {
        return Pkcs1Codec.encodeRsaOaep(key, message, options, undefined, undefined, getRandomBytes);
      },
      decode_rsa_oaep(key, em, options) {
        return Pkcs1Codec.decodeRsaOaep(key, em, options);
      }
    };
  }
}

export default Pkcs1Codec;

import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { constantTimeEquals } from '../util/constantTimeEquals.js';
import type { MessageDigest } from './Mgf1.js';

export type MgfObject = {
  generate: (seed: string, maskLen: number) => string;
};

export type PssCreateOptions = {
  md: MessageDigest;
  mgf: MgfObject;
  saltLength?: number;
  prng?: { getBytesSync(count: number): string };
  salt?: string | ByteStringBuffer;
};

export type PssObject = {
  encode: (md: MessageDigest, modBits: number) => string;
  verify: (mHash: string, em: string, modBits: number) => boolean;
};

export class PssScheme {
  static create(options: PssCreateOptions): PssObject {
    const hash = options.md;
    const mgf = options.mgf;
    const hLen = hash.digestLength;

    let salt_ = options.salt ?? null;
    if (typeof salt_ === 'string') {
      salt_ = new ByteStringBuffer(salt_);
    }

    let sLen: number;
    if ('saltLength' in options && options.saltLength !== undefined) {
      sLen = options.saltLength;
    } else if (salt_ !== null) {
      sLen = salt_.length();
    } else {
      throw new Error('Salt length not specified or specific salt not given.');
    }

    if (salt_ !== null && salt_.length() !== sLen) {
      throw new Error('Given salt length does not match length of given salt.');
    }

    const prng = options.prng;

    return {
      encode(md: MessageDigest, modBits: number): string {
        const emBits = modBits - 1;
        const emLen = Math.ceil(emBits / 8);
        const mHash = md.digest().getBytes();

        if (emLen < hLen + sLen + 2) {
          throw new Error('Message is too long to encrypt.');
        }

        let salt: string;
        if (salt_ === null) {
          if (!prng) {
            throw new Error('PRNG required to generate PSS salt');
          }
          salt = prng.getBytesSync(sLen);
        } else {
          salt = salt_.bytes();
        }

        const m_ = new ByteStringBuffer();
        m_.fillWithByte(0, 8);
        m_.putBytes(mHash);
        m_.putBytes(salt);

        hash.start();
        hash.update(m_.getBytes());
        const h = hash.digest().getBytes();

        const ps = new ByteStringBuffer();
        ps.fillWithByte(0, emLen - sLen - hLen - 2);
        ps.putByte(0x01);
        ps.putBytes(salt);
        const db = ps.getBytes();

        const maskLen = emLen - hLen - 1;
        const dbMask = mgf.generate(h, maskLen);

        let maskedDB = '';
        for (let i = 0; i < maskLen; i++) {
          maskedDB += String.fromCharCode(db.charCodeAt(i) ^ dbMask.charCodeAt(i));
        }

        const mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
        maskedDB = String.fromCharCode(maskedDB.charCodeAt(0) & ~mask) + maskedDB.substr(1);

        return maskedDB + h + String.fromCharCode(0xbc);
      },

      verify(mHash: string, em: string, modBits: number): boolean {
        const emBits = modBits - 1;
        const emLen = Math.ceil(emBits / 8);

        em = em.substr(-emLen);

        if (emLen < hLen + sLen + 2) {
          throw new Error('Inconsistent parameters to PSS signature verification.');
        }

        if (em.charCodeAt(emLen - 1) !== 0xbc) {
          throw new Error('Encoded message does not end in 0xBC.');
        }

        const maskLen = emLen - hLen - 1;
        const maskedDB = em.substr(0, maskLen);
        const h = em.substr(maskLen, hLen);

        const mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
        if ((maskedDB.charCodeAt(0) & mask) !== 0) {
          throw new Error('Bits beyond keysize not zero as expected.');
        }

        const dbMask = mgf.generate(h, maskLen);

        let db = '';
        for (let i = 0; i < maskLen; i++) {
          db += String.fromCharCode(maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i));
        }

        db = String.fromCharCode(db.charCodeAt(0) & ~mask) + db.substr(1);

        const checkLen = emLen - hLen - sLen - 2;
        for (let i = 0; i < checkLen; i++) {
          if (db.charCodeAt(i) !== 0x00) {
            throw new Error('Leftmost octets not zero as expected');
          }
        }

        if (db.charCodeAt(checkLen) !== 0x01) {
          throw new Error('Inconsistent PSS signature, 0x01 marker not found');
        }

        const salt = db.substr(-sLen);

        const m_ = new ByteStringBuffer();
        m_.fillWithByte(0, 8);
        m_.putBytes(mHash);
        m_.putBytes(salt);

        hash.start();
        hash.update(m_.getBytes());
        const h_ = hash.digest().getBytes();

        return constantTimeEquals(h, h_);
      }
    };
  }

  static createCertkitNamespace(getRandomBytes: (count: number) => string): {
    create: (options?: PssCreateOptions) => PssObject;
  } {
    return {
      create: function (options?: PssCreateOptions) {
        if (arguments.length === 3) {
          options = {
            md: arguments[0] as MessageDigest,
            mgf: arguments[1] as MgfObject,
            saltLength: arguments[2] as number
          };
        }
        if (!options!.prng) {
          options = { ...options!, prng: { getBytesSync: getRandomBytes } };
        }
        return PssScheme.create(options!);
      }
    };
  }
}

export default PssScheme;

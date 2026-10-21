import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { constantTimeEquals } from '../util/constantTimeEquals.js';
import type { MessageDigest } from './MgfTypes.js';
import type { MgfObject, PssCreateOptions, PssObject } from './PssTypes.js';

/**
 * RSASSA-PSS encoding and verification (RFC 8017 section 9.1).
 *
 * Spec notation preserved: `mHash`, `M'`, `H`, `PS`, `DB`, `em`, `emBits`, `emLen`, `salt`.
 */
export class PssScheme {
  static create(options: PssCreateOptions): PssObject {
    const hash = options.md;
    const mgf = options.mgf;
    const hLen = hash.digestLength;

    let configuredSalt = options.salt ?? null;
    if (typeof configuredSalt === 'string') {
      configuredSalt = new ByteStringBuffer(configuredSalt);
    }

    let saltLength: number;
    if ('saltLength' in options && options.saltLength !== undefined) {
      saltLength = options.saltLength;
    } else if (configuredSalt !== null) {
      saltLength = configuredSalt.length();
    } else {
      throw new Error('Salt length not specified or specific salt not given.');
    }

    if (configuredSalt !== null && configuredSalt.length() !== saltLength) {
      throw new Error('Given salt length does not match length of given salt.');
    }

    const prng = options.prng;

    return {
      encode(messageDigest: MessageDigest, modBits: number): string {
        const emBits = modBits - 1;
        const emLen = Math.ceil(emBits / 8);
        const mHash = messageDigest.digest().getBytes();

        if (emLen < hLen + saltLength + 2) {
          throw new Error('Message is too long to encrypt.');
        }

        let salt: string;
        if (configuredSalt === null) {
          if (!prng) {
            throw new Error('PRNG required to generate PSS salt');
          }
          salt = prng.getBytesSync(saltLength);
        } else {
          salt = configuredSalt.bytes();
        }

        const paddedMessage = new ByteStringBuffer();
        paddedMessage.fillWithByte(0, 8);
        paddedMessage.putBytes(mHash);
        paddedMessage.putBytes(salt);

        hash.start();
        hash.update(paddedMessage.getBytes());
        const hashOctets = hash.digest().getBytes();

        const paddingBlock = new ByteStringBuffer();
        paddingBlock.fillWithByte(0, emLen - saltLength - hLen - 2);
        paddingBlock.putByte(0x01);
        paddingBlock.putBytes(salt);
        const dataBlock = paddingBlock.getBytes();

        const maskLen = emLen - hLen - 1;
        const dbMask = mgf.generate(hashOctets, maskLen);

        let maskedDB = '';
        for (let index = 0; index < maskLen; index++) {
          maskedDB += String.fromCharCode(dataBlock.charCodeAt(index) ^ dbMask.charCodeAt(index));
        }

        const mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
        maskedDB = String.fromCharCode(maskedDB.charCodeAt(0) & ~mask) + maskedDB.substr(1);

        return maskedDB + hashOctets + String.fromCharCode(0xbc);
      },

      verify(mHash: string, encodedMessage: string, modBits: number): boolean {
        const emBits = modBits - 1;
        const emLen = Math.ceil(emBits / 8);

        encodedMessage = encodedMessage.substr(-emLen);

        if (emLen < hLen + saltLength + 2) {
          throw new Error('Inconsistent parameters to PSS signature verification.');
        }

        if (encodedMessage.charCodeAt(emLen - 1) !== 0xbc) {
          throw new Error('Encoded message does not end in 0xBC.');
        }

        const maskLen = emLen - hLen - 1;
        const maskedDB = encodedMessage.substr(0, maskLen);
        const encodedHashOctets = encodedMessage.substr(maskLen, hLen);

        const mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
        if ((maskedDB.charCodeAt(0) & mask) !== 0) {
          throw new Error('Bits beyond keysize not zero as expected.');
        }

        const dbMask = mgf.generate(encodedHashOctets, maskLen);

        let dataBlock = '';
        for (let index = 0; index < maskLen; index++) {
          dataBlock += String.fromCharCode(maskedDB.charCodeAt(index) ^ dbMask.charCodeAt(index));
        }

        dataBlock = String.fromCharCode(dataBlock.charCodeAt(0) & ~mask) + dataBlock.substr(1);

        const checkLen = emLen - hLen - saltLength - 2;
        for (let index = 0; index < checkLen; index++) {
          if (dataBlock.charCodeAt(index) !== 0x00) {
            throw new Error('Leftmost octets not zero as expected');
          }
        }

        if (dataBlock.charCodeAt(checkLen) !== 0x01) {
          throw new Error('Inconsistent PSS signature, 0x01 marker not found');
        }

        const salt = dataBlock.substr(-saltLength);

        const paddedMessage = new ByteStringBuffer();
        paddedMessage.fillWithByte(0, 8);
        paddedMessage.putBytes(mHash);
        paddedMessage.putBytes(salt);

        hash.start();
        hash.update(paddedMessage.getBytes());
        const recoveredHashOctets = hash.digest().getBytes();

        return constantTimeEquals(encodedHashOctets, recoveredHashOctets);
      }
    };
  }

  static createCertkitNamespace(getRandomBytes: (count: number) => string): {
    create: (options?: PssCreateOptions) => PssObject;
  } {
    const create = (...args: [PssCreateOptions?] | [MessageDigest, MgfObject, number]) => {
      let options: PssCreateOptions | undefined;
      if (args.length === 3) {
        options = {
          md: args[0],
          mgf: args[1],
          saltLength: args[2]
        };
      } else {
        options = args[0];
      }
      if (!options!.prng) {
        options = { ...options!, prng: { getBytesSync: getRandomBytes } };
      }
      return PssScheme.create(options!);
    };
    Object.defineProperty(create, 'length', { value: 1 });
    return { create };
  }
}

export default PssScheme;

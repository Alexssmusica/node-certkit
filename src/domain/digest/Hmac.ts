import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';
import type { BlockDigest, DigestAlgorithmRegistry, HmacContext } from './DigestTypes.js';

/**
 * Hash-based Message Authentication Code implementation.
 */
class HmacEngine {
  #key: ByteStringBuffer | null = null;
  #messageDigest: BlockDigest | null = null;
  #ipadding: string | null = null;
  #opadding: string | null = null;

  start(messageDigest: string | BlockDigest | null, key: unknown, algorithms: DigestAlgorithmRegistry): void {
    if (messageDigest !== null) {
      if (typeof messageDigest === 'string') {
        const name = messageDigest.toLowerCase();
        if (!(name in algorithms)) {
          throw new Error('Unknown hash algorithm "' + messageDigest + '"');
        }
        this.#messageDigest = algorithms[name].create();
      } else {
        this.#messageDigest = messageDigest;
      }
    }

    let keyBuffer: ByteStringBuffer;
    if (key === null) {
      keyBuffer = this.#key!;
    } else if (typeof key === 'string') {
      keyBuffer = new ByteStringBuffer(key);
    } else if (isArray(key)) {
      keyBuffer = new ByteStringBuffer();
      const keyBytes = key as number[];
      for (let index = 0; index < keyBytes.length; ++index) {
        keyBuffer.putByte(keyBytes[index]);
      }
    } else {
      keyBuffer = key as ByteStringBuffer;
    }

    let keylen = keyBuffer.length();
    if (keylen > this.#messageDigest!.blockLength) {
      this.#messageDigest!.start();
      this.#messageDigest!.update(keyBuffer.bytes());
      keyBuffer = this.#messageDigest!.digest();
    }

    const ipadding = new ByteStringBuffer();
    const opadding = new ByteStringBuffer();
    keylen = keyBuffer.length();
    for (let index = 0; index < keylen; ++index) {
      const keyByte = keyBuffer.at(index);
      ipadding.putByte(0x36 ^ keyByte);
      opadding.putByte(0x5c ^ keyByte);
    }

    if (keylen < this.#messageDigest!.blockLength) {
      const pad = this.#messageDigest!.blockLength - keylen;
      for (let index = 0; index < pad; ++index) {
        ipadding.putByte(0x36);
        opadding.putByte(0x5c);
      }
    }
    this.#key = keyBuffer;
    this.#ipadding = ipadding.bytes();
    this.#opadding = opadding.bytes();

    this.#messageDigest!.start();
    this.#messageDigest!.update(this.#ipadding);
  }

  update(bytes: string): void {
    this.#messageDigest!.update(bytes);
  }

  getMac(): ByteStringBuffer {
    const inner = this.#messageDigest!.digest().bytes();
    this.#messageDigest!.start();
    this.#messageDigest!.update(this.#opadding!);
    this.#messageDigest!.update(inner);
    return this.#messageDigest!.digest();
  }
}

export class Hmac {
  static create(algorithms: DigestAlgorithmRegistry): HmacContext {
    const engine = new HmacEngine();
    const ctx: HmacContext = {
      start: (messageDigest, key) => engine.start(messageDigest, key, algorithms),
      update: (bytes) => engine.update(bytes),
      getMac: () => engine.getMac(),
      digest: () => engine.getMac()
    };
    return ctx;
  }
}

export default Hmac;

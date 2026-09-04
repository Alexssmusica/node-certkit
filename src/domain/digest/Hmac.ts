import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';

interface BlockDigest {
  blockLength: number;
  start: () => unknown;
  update: (msg: string, encoding?: string) => unknown;
  digest: () => ByteStringBuffer;
}

export type DigestAlgorithmRegistry = Record<string, { create: () => BlockDigest }>;

export interface HmacContext {
  start: (md: string | BlockDigest | null, key: unknown) => void;
  update: (bytes: string) => void;
  getMac: () => ByteStringBuffer;
  digest: () => ByteStringBuffer;
}

/**
 * Hash-based Message Authentication Code implementation.
 */
class HmacEngine {
  #key: ByteStringBuffer | null = null;
  #md: BlockDigest | null = null;
  #ipadding: string | null = null;
  #opadding: string | null = null;

  start(md: string | BlockDigest | null, key: unknown, algorithms: DigestAlgorithmRegistry): void {
    if (md !== null) {
      if (typeof md === 'string') {
        const name = md.toLowerCase();
        if (!(name in algorithms)) {
          throw new Error('Unknown hash algorithm "' + md + '"');
        }
        this.#md = algorithms[name]!.create();
      } else {
        this.#md = md;
      }
    }

    let keyBuffer: ByteStringBuffer;
    if (key === null) {
      keyBuffer = this.#key!;
    } else if (typeof key === 'string') {
      keyBuffer = new ByteStringBuffer(key);
    } else if (isArray(key)) {
      keyBuffer = new ByteStringBuffer();
      const tmp = key as number[];
      for (let i = 0; i < tmp.length; ++i) {
        keyBuffer.putByte(tmp[i]!);
      }
    } else {
      keyBuffer = key as ByteStringBuffer;
    }

    let keylen = keyBuffer.length();
    if (keylen > this.#md!.blockLength) {
      this.#md!.start();
      this.#md!.update(keyBuffer.bytes());
      keyBuffer = this.#md!.digest();
    }

    const ipadding = new ByteStringBuffer();
    const opadding = new ByteStringBuffer();
    keylen = keyBuffer.length();
    for (let i = 0; i < keylen; ++i) {
      const tmp = keyBuffer.at(i);
      ipadding.putByte(0x36 ^ tmp);
      opadding.putByte(0x5c ^ tmp);
    }

    if (keylen < this.#md!.blockLength) {
      const pad = this.#md!.blockLength - keylen;
      for (let i = 0; i < pad; ++i) {
        ipadding.putByte(0x36);
        opadding.putByte(0x5c);
      }
    }
    this.#key = keyBuffer;
    this.#ipadding = ipadding.bytes();
    this.#opadding = opadding.bytes();

    this.#md!.start();
    this.#md!.update(this.#ipadding);
  }

  update(bytes: string): void {
    this.#md!.update(bytes);
  }

  getMac(): ByteStringBuffer {
    const inner = this.#md!.digest().bytes();
    this.#md!.start();
    this.#md!.update(this.#opadding!);
    this.#md!.update(inner);
    return this.#md!.digest();
  }
}

export class Hmac {
  static create(algorithms: DigestAlgorithmRegistry): HmacContext {
    const engine = new HmacEngine();
    const ctx: HmacContext = {
      start: (md, key) => engine.start(md, key, algorithms),
      update: (bytes) => engine.update(bytes),
      getMac: () => engine.getMac(),
      digest: () => engine.getMac()
    };
    return ctx;
  }
}

export default Hmac;

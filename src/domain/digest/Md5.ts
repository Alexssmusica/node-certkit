import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';

interface Md5State {
  h0: number;
  h1: number;
  h2: number;
  h3: number;
}

export interface Md5Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Md5Digest;
  update: (msg: string, encoding?: string) => Md5Digest;
  digest: () => ByteStringBuffer;
}

/**
 * Message Digest Algorithm 5 with 128-bit digest (MD5) implementation.
 */
export class Md5 {
  static #padding: string | null = null;
  static #g: number[] | null = null;
  static #r: number[] | null = null;
  static #k: number[] | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Md5.#initialized) {
      return;
    }
    Md5.#padding = String.fromCharCode(128);
    Md5.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 64);
    Md5.#g = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8,
      11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
    ];
    Md5.#r = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
      20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
      10, 15, 21
    ];
    Md5.#k = new Array<number>(64);
    for (let i = 0; i < 64; ++i) {
      Md5.#k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
    }
    Md5.#initialized = true;
  }

  #state: Md5State | null = null;
  #input = new ByteStringBuffer();
  readonly #w = new Array<number>(16);

  static create(): Md5Digest {
    Md5.#ensureInit();
    const engine = new Md5();
    const md: Md5Digest = {
      algorithm: 'md5',
      blockLength: 64,
      digestLength: 16,
      messageLength: 0,
      fullMessageLength: null,
      messageLength64: null,
      messageLengthSize: 8,
      start: () => engine.#start(md),
      update: (msg, encoding) => engine.#update(md, msg, encoding),
      digest: () => engine.#digest(md)
    };
    md.start();
    return md;
  }

  #start(md: Md5Digest): Md5Digest {
    md.messageLength = 0;
    md.fullMessageLength = md.messageLength64 = [];
    const int32s = md.messageLengthSize / 4;
    for (let i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0);
    }
    this.#input = new ByteStringBuffer();
    this.#state = {
      h0: 0x67452301,
      h1: 0xefcdab89,
      h2: 0x98badcfe,
      h3: 0x10325476
    };
    return md;
  }

  #update(md: Md5Digest, msg: string, encoding?: string): Md5Digest {
    if (encoding === 'utf8') {
      msg = encodeUtf8(msg);
    }

    const len = msg.length;
    md.messageLength += len;
    const lenParts = [(len / 0x100000000) >>> 0, len >>> 0];
    const fullMessageLength = md.fullMessageLength!;
    for (let i = fullMessageLength.length - 1; i >= 0; --i) {
      fullMessageLength[i] += lenParts[1]!;
      lenParts[1] = lenParts[0]! + ((fullMessageLength[i]! / 0x100000000) >>> 0);
      fullMessageLength[i] = fullMessageLength[i]! >>> 0;
      lenParts[0] = (lenParts[1]! / 0x100000000) >>> 0;
    }

    this.#input.putBytes(msg);
    Md5.#updateState(this.#state!, this.#w, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Md5Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining = md.fullMessageLength![md.fullMessageLength!.length - 1]! + md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Md5.#padding!.substr(0, md.blockLength - overflow));

    let bits: number;
    let carry = 0;
    for (let i = md.fullMessageLength!.length - 1; i >= 0; --i) {
      bits = md.fullMessageLength![i]! * 8 + carry;
      carry = (bits / 0x100000000) >>> 0;
      finalBlock.putInt32Le(bits >>> 0);
    }

    const s2 = {
      h0: this.#state!.h0,
      h1: this.#state!.h1,
      h2: this.#state!.h2,
      h3: this.#state!.h3
    };
    Md5.#updateState(s2, this.#w, finalBlock);
    const rval = new ByteStringBuffer();
    rval.putInt32Le(s2.h0);
    rval.putInt32Le(s2.h1);
    rval.putInt32Le(s2.h2);
    rval.putInt32Le(s2.h3);
    return rval;
  }

  static #updateState(s: Md5State, w: number[], bytes: ByteStringBuffer): void {
    const g = Md5.#g!;
    const r = Md5.#r!;
    const k = Md5.#k!;
    let t: number;
    let a: number;
    let b: number;
    let c: number;
    let d: number;
    let f: number;
    let ri: number;
    let i: number;
    let len = bytes.length();
    while (len >= 64) {
      a = s.h0;
      b = s.h1;
      c = s.h2;
      d = s.h3;

      for (i = 0; i < 16; ++i) {
        w[i] = bytes.getInt32Le();
        f = d ^ (b & (c ^ d));
        t = a + f + k[i]! + w[i]!;
        ri = r[i]!;
        a = d;
        d = c;
        c = b;
        b += (t << ri) | (t >>> (32 - ri));
      }
      for (; i < 32; ++i) {
        f = c ^ (d & (b ^ c));
        t = a + f + k[i]! + w[g[i]!]!;
        ri = r[i]!;
        a = d;
        d = c;
        c = b;
        b += (t << ri) | (t >>> (32 - ri));
      }
      for (; i < 48; ++i) {
        f = b ^ c ^ d;
        t = a + f + k[i]! + w[g[i]!]!;
        ri = r[i]!;
        a = d;
        d = c;
        c = b;
        b += (t << ri) | (t >>> (32 - ri));
      }
      for (; i < 64; ++i) {
        f = c ^ (b | ~d);
        t = a + f + k[i]! + w[g[i]!]!;
        ri = r[i]!;
        a = d;
        d = c;
        c = b;
        b += (t << ri) | (t >>> (32 - ri));
      }

      s.h0 = (s.h0 + a) | 0;
      s.h1 = (s.h1 + b) | 0;
      s.h2 = (s.h2 + c) | 0;
      s.h3 = (s.h3 + d) | 0;

      len -= 64;
    }
  }
}

export default Md5;

import {ByteStringBuffer} from '../buffer/ByteStringBuffer.js';
import {encodeUtf8} from '../encoding/Utf8Codec.js';
import {UtilNamespace} from '../util/UtilNamespace.js';

interface Sha1State {
  h0: number;
  h1: number;
  h2: number;
  h3: number;
  h4: number;
}

export interface Sha1Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Sha1Digest;
  update: (msg: string, encoding?: string) => Sha1Digest;
  digest: () => ByteStringBuffer;
}

/**
 * Secure Hash Algorithm with 160-bit digest (SHA-1) implementation.
 */
export class Sha1 {
  static #padding: string | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Sha1.#initialized) {
      return;
    }
    Sha1.#padding = String.fromCharCode(128);
    Sha1.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 64);
    Sha1.#initialized = true;
  }

  #state: Sha1State | null = null;
  #input = new ByteStringBuffer();
  readonly #w = new Array<number>(80);

  static create(): Sha1Digest {
    Sha1.#ensureInit();
    const engine = new Sha1();
    const md: Sha1Digest = {
      algorithm: 'sha1',
      blockLength: 64,
      digestLength: 20,
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

  #start(md: Sha1Digest): Sha1Digest {
    md.messageLength = 0;
    md.fullMessageLength = md.messageLength64 = [];
    const int32s = md.messageLengthSize / 4;
    for (let i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0);
    }
    this.#input = new ByteStringBuffer();
    this.#state = {
      h0: 0x67452301,
      h1: 0xEFCDAB89,
      h2: 0x98BADCFE,
      h3: 0x10325476,
      h4: 0xC3D2E1F0
    };
    return md;
  }

  #update(md: Sha1Digest, msg: string, encoding?: string): Sha1Digest {
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
      lenParts[0] = ((lenParts[1]! / 0x100000000) >>> 0);
    }

    this.#input.putBytes(msg);
    Sha1.#updateState(this.#state!, this.#w, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Sha1Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining =
      md.fullMessageLength![md.fullMessageLength!.length - 1]! +
      md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Sha1.#padding!.substr(0, md.blockLength - overflow));

    let next: number;
    let carry: number;
    let bits = md.fullMessageLength![0]! * 8;
    for (let i = 0; i < md.fullMessageLength!.length - 1; ++i) {
      next = md.fullMessageLength![i + 1]! * 8;
      carry = (next / 0x100000000) >>> 0;
      bits += carry;
      finalBlock.putInt32(bits >>> 0);
      bits = next >>> 0;
    }
    finalBlock.putInt32(bits);

    const s2 = {
      h0: this.#state!.h0,
      h1: this.#state!.h1,
      h2: this.#state!.h2,
      h3: this.#state!.h3,
      h4: this.#state!.h4
    };
    Sha1.#updateState(s2, this.#w, finalBlock);
    const rval = new ByteStringBuffer();
    rval.putInt32(s2.h0);
    rval.putInt32(s2.h1);
    rval.putInt32(s2.h2);
    rval.putInt32(s2.h3);
    rval.putInt32(s2.h4);
    return rval;
  }

  static #updateState(s: Sha1State, w: number[], bytes: ByteStringBuffer): void {
    let t: number;
    let a: number;
    let b: number;
    let c: number;
    let d: number;
    let e: number;
    let f: number;
    let i: number;
    let len = bytes.length();
    while (len >= 64) {
      a = s.h0;
      b = s.h1;
      c = s.h2;
      d = s.h3;
      e = s.h4;

      for (i = 0; i < 16; ++i) {
        t = bytes.getInt32();
        w[i] = t;
        f = d ^ (b & (c ^ d));
        t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }
      for (; i < 20; ++i) {
        t = (w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!);
        t = (t << 1) | (t >>> 31);
        w[i] = t;
        f = d ^ (b & (c ^ d));
        t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }
      for (; i < 32; ++i) {
        t = (w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!);
        t = (t << 1) | (t >>> 31);
        w[i] = t;
        f = b ^ c ^ d;
        t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }
      for (; i < 40; ++i) {
        t = (w[i - 6]! ^ w[i - 16]! ^ w[i - 28]! ^ w[i - 32]!);
        t = (t << 2) | (t >>> 30);
        w[i] = t;
        f = b ^ c ^ d;
        t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }
      for (; i < 60; ++i) {
        t = (w[i - 6]! ^ w[i - 16]! ^ w[i - 28]! ^ w[i - 32]!);
        t = (t << 2) | (t >>> 30);
        w[i] = t;
        f = (b & c) | (d & (b ^ c));
        t = ((a << 5) | (a >>> 27)) + f + e + 0x8F1BBCDC + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }
      for (; i < 80; ++i) {
        t = (w[i - 6]! ^ w[i - 16]! ^ w[i - 28]! ^ w[i - 32]!);
        t = (t << 2) | (t >>> 30);
        w[i] = t;
        f = b ^ c ^ d;
        t = ((a << 5) | (a >>> 27)) + f + e + 0xCA62C1D6 + t;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = t;
      }

      s.h0 = (s.h0 + a) | 0;
      s.h1 = (s.h1 + b) | 0;
      s.h2 = (s.h2 + c) | 0;
      s.h3 = (s.h3 + d) | 0;
      s.h4 = (s.h4 + e) | 0;

      len -= 64;
    }
  }
}

export default Sha1;

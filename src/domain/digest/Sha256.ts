import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';

interface Sha256State {
  h0: number;
  h1: number;
  h2: number;
  h3: number;
  h4: number;
  h5: number;
  h6: number;
  h7: number;
}

export interface Sha256Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Sha256Digest;
  update: (msg: string, encoding?: string) => Sha256Digest;
  digest: () => ByteStringBuffer;
}

/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 */
export class Sha256 {
  static #padding: string | null = null;
  static #k: number[] | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Sha256.#initialized) {
      return;
    }
    Sha256.#padding = String.fromCharCode(128);
    Sha256.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 64);
    Sha256.#k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
      0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
      0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
      0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    Sha256.#initialized = true;
  }

  #state: Sha256State | null = null;
  #input = new ByteStringBuffer();
  readonly #w = new Array<number>(64);

  static create(): Sha256Digest {
    Sha256.#ensureInit();
    const engine = new Sha256();
    const md: Sha256Digest = {
      algorithm: 'sha256',
      blockLength: 64,
      digestLength: 32,
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

  #start(md: Sha256Digest): Sha256Digest {
    md.messageLength = 0;
    md.fullMessageLength = md.messageLength64 = [];
    const int32s = md.messageLengthSize / 4;
    for (let i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0);
    }
    this.#input = new ByteStringBuffer();
    this.#state = {
      h0: 0x6a09e667,
      h1: 0xbb67ae85,
      h2: 0x3c6ef372,
      h3: 0xa54ff53a,
      h4: 0x510e527f,
      h5: 0x9b05688c,
      h6: 0x1f83d9ab,
      h7: 0x5be0cd19
    };
    return md;
  }

  #update(md: Sha256Digest, msg: string, encoding?: string): Sha256Digest {
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
    Sha256.#updateState(this.#state!, this.#w, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Sha256Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining = md.fullMessageLength![md.fullMessageLength!.length - 1]! + md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Sha256.#padding!.substr(0, md.blockLength - overflow));

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
      h4: this.#state!.h4,
      h5: this.#state!.h5,
      h6: this.#state!.h6,
      h7: this.#state!.h7
    };
    Sha256.#updateState(s2, this.#w, finalBlock);
    const rval = new ByteStringBuffer();
    rval.putInt32(s2.h0);
    rval.putInt32(s2.h1);
    rval.putInt32(s2.h2);
    rval.putInt32(s2.h3);
    rval.putInt32(s2.h4);
    rval.putInt32(s2.h5);
    rval.putInt32(s2.h6);
    rval.putInt32(s2.h7);
    return rval;
  }

  static #updateState(s: Sha256State, w: number[], bytes: ByteStringBuffer): void {
    const k = Sha256.#k!;
    let t1: number;
    let t2: number;
    let s0: number;
    let s1: number;
    let ch: number;
    let maj: number;
    let i: number;
    let a: number;
    let b: number;
    let c: number;
    let d: number;
    let e: number;
    let f: number;
    let g: number;
    let h: number;
    let len = bytes.length();
    while (len >= 64) {
      for (i = 0; i < 16; ++i) {
        w[i] = bytes.getInt32();
      }
      for (; i < 64; ++i) {
        t1 = w[i - 2]!;
        t1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
        t2 = w[i - 15]!;
        t2 = ((t2 >>> 7) | (t2 << 25)) ^ ((t2 >>> 18) | (t2 << 14)) ^ (t2 >>> 3);
        w[i] = (t1 + w[i - 7]! + t2 + w[i - 16]!) | 0;
      }

      a = s.h0;
      b = s.h1;
      c = s.h2;
      d = s.h3;
      e = s.h4;
      f = s.h5;
      g = s.h6;
      h = s.h7;

      for (i = 0; i < 64; ++i) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = g ^ (e & (f ^ g));
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) | (c & (a ^ b));

        t1 = h + s1 + ch + k[i]! + w[i]!;
        t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + t1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) >>> 0;
      }

      s.h0 = (s.h0 + a) | 0;
      s.h1 = (s.h1 + b) | 0;
      s.h2 = (s.h2 + c) | 0;
      s.h3 = (s.h3 + d) | 0;
      s.h4 = (s.h4 + e) | 0;
      s.h5 = (s.h5 + f) | 0;
      s.h6 = (s.h6 + g) | 0;
      s.h7 = (s.h7 + h) | 0;
      len -= 64;
    }
  }
}

export default Sha256;

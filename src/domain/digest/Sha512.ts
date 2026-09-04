import {ByteStringBuffer} from '../buffer/ByteStringBuffer.js';
import {encodeUtf8} from '../encoding/Utf8Codec.js';
import {UtilNamespace} from '../util/UtilNamespace.js';

type Sha512Algorithm = 'SHA-512' | 'SHA-384' | 'SHA-512/256' | 'SHA-512/224';
type Sha512StateWord = [number, number];
type Sha512State = Sha512StateWord[];

export interface Sha512Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength128: number[] | null;
  messageLengthSize: number;
  start: () => Sha512Digest;
  update: (msg: string, encoding?: string) => Sha512Digest;
  digest: () => ByteStringBuffer;
}

/**
 * Secure Hash Algorithm with a 1024-bit block size implementation.
 */
export class Sha512 {
  static #padding: string | null = null;
  static #k: Sha512StateWord[] | null = null;
  static #states: Record<string, Sha512State> | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Sha512.#initialized) {
      return;
    }
    Sha512.#padding = String.fromCharCode(128);
    Sha512.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 128);
    Sha512.#k = [
      [0x428a2f98, 0xd728ae22], [0x71374491, 0x23ef65cd],
      [0xb5c0fbcf, 0xec4d3b2f], [0xe9b5dba5, 0x8189dbbc],
      [0x3956c25b, 0xf348b538], [0x59f111f1, 0xb605d019],
      [0x923f82a4, 0xaf194f9b], [0xab1c5ed5, 0xda6d8118],
      [0xd807aa98, 0xa3030242], [0x12835b01, 0x45706fbe],
      [0x243185be, 0x4ee4b28c], [0x550c7dc3, 0xd5ffb4e2],
      [0x72be5d74, 0xf27b896f], [0x80deb1fe, 0x3b1696b1],
      [0x9bdc06a7, 0x25c71235], [0xc19bf174, 0xcf692694],
      [0xe49b69c1, 0x9ef14ad2], [0xefbe4786, 0x384f25e3],
      [0x0fc19dc6, 0x8b8cd5b5], [0x240ca1cc, 0x77ac9c65],
      [0x2de92c6f, 0x592b0275], [0x4a7484aa, 0x6ea6e483],
      [0x5cb0a9dc, 0xbd41fbd4], [0x76f988da, 0x831153b5],
      [0x983e5152, 0xee66dfab], [0xa831c66d, 0x2db43210],
      [0xb00327c8, 0x98fb213f], [0xbf597fc7, 0xbeef0ee4],
      [0xc6e00bf3, 0x3da88fc2], [0xd5a79147, 0x930aa725],
      [0x06ca6351, 0xe003826f], [0x14292967, 0x0a0e6e70],
      [0x27b70a85, 0x46d22ffc], [0x2e1b2138, 0x5c26c926],
      [0x4d2c6dfc, 0x5ac42aed], [0x53380d13, 0x9d95b3df],
      [0x650a7354, 0x8baf63de], [0x766a0abb, 0x3c77b2a8],
      [0x81c2c92e, 0x47edaee6], [0x92722c85, 0x1482353b],
      [0xa2bfe8a1, 0x4cf10364], [0xa81a664b, 0xbc423001],
      [0xc24b8b70, 0xd0f89791], [0xc76c51a3, 0x0654be30],
      [0xd192e819, 0xd6ef5218], [0xd6990624, 0x5565a910],
      [0xf40e3585, 0x5771202a], [0x106aa070, 0x32bbd1b8],
      [0x19a4c116, 0xb8d2d0c8], [0x1e376c08, 0x5141ab53],
      [0x2748774c, 0xdf8eeb99], [0x34b0bcb5, 0xe19b48a8],
      [0x391c0cb3, 0xc5c95a63], [0x4ed8aa4a, 0xe3418acb],
      [0x5b9cca4f, 0x7763e373], [0x682e6ff3, 0xd6b2b8a3],
      [0x748f82ee, 0x5defb2fc], [0x78a5636f, 0x43172f60],
      [0x84c87814, 0xa1f0ab72], [0x8cc70208, 0x1a6439ec],
      [0x90befffa, 0x23631e28], [0xa4506ceb, 0xde82bde9],
      [0xbef9a3f7, 0xb2c67915], [0xc67178f2, 0xe372532b],
      [0xca273ece, 0xea26619c], [0xd186b8c7, 0x21c0c207],
      [0xeada7dd6, 0xcde0eb1e], [0xf57d4f7f, 0xee6ed178],
      [0x06f067aa, 0x72176fba], [0x0a637dc5, 0xa2c898a6],
      [0x113f9804, 0xbef90dae], [0x1b710b35, 0x131c471b],
      [0x28db77f5, 0x23047d84], [0x32caab7b, 0x40c72493],
      [0x3c9ebe0a, 0x15c9bebc], [0x431d67c4, 0x9c100d4c],
      [0x4cc5d4be, 0xcb3e42b6], [0x597f299c, 0xfc657e2a],
      [0x5fcb6fab, 0x3ad6faec], [0x6c44198c, 0x4a475817]
    ];
    Sha512.#states = {
      'SHA-512': [
        [0x6a09e667, 0xf3bcc908],
        [0xbb67ae85, 0x84caa73b],
        [0x3c6ef372, 0xfe94f82b],
        [0xa54ff53a, 0x5f1d36f1],
        [0x510e527f, 0xade682d1],
        [0x9b05688c, 0x2b3e6c1f],
        [0x1f83d9ab, 0xfb41bd6b],
        [0x5be0cd19, 0x137e2179]
      ],
      'SHA-384': [
        [0xcbbb9d5d, 0xc1059ed8],
        [0x629a292a, 0x367cd507],
        [0x9159015a, 0x3070dd17],
        [0x152fecd8, 0xf70e5939],
        [0x67332667, 0xffc00b31],
        [0x8eb44a87, 0x68581511],
        [0xdb0c2e0d, 0x64f98fa7],
        [0x47b5481d, 0xbefa4fa4]
      ],
      'SHA-512/256': [
        [0x22312194, 0xFC2BF72C],
        [0x9F555FA3, 0xC84C64C2],
        [0x2393B86B, 0x6F53B151],
        [0x96387719, 0x5940EABD],
        [0x96283EE2, 0xA88EFFE3],
        [0xBE5E1E25, 0x53863992],
        [0x2B0199FC, 0x2C85B8AA],
        [0x0EB72DDC, 0x81C52CA2]
      ],
      'SHA-512/224': [
        [0x8C3D37C8, 0x19544DA2],
        [0x73E19966, 0x89DCD4D6],
        [0x1DFAB7AE, 0x32FF9C82],
        [0x679DD514, 0x582F9FCF],
        [0x0F6D2B69, 0x7BD44DA8],
        [0x77E36F73, 0x04C48942],
        [0x3F9D85A8, 0x6A1D36C8],
        [0x1112E6AD, 0x91D692A1]
      ]
    };
    Sha512.#initialized = true;
  }

  readonly #algorithm: Sha512Algorithm;
  readonly #initialState: Sha512State;
  #h: Sha512State | null = null;
  #input = new ByteStringBuffer();
  readonly #w: Sha512StateWord[] = Array.from({length: 80}, () => [0, 0]);
  readonly #digestLength: number;

  constructor(algorithm: Sha512Algorithm) {
    this.#algorithm = algorithm;
    this.#initialState = Sha512.#states![algorithm]!;
    switch (algorithm) {
      case 'SHA-384':
        this.#digestLength = 48;
        break;
      case 'SHA-512/256':
        this.#digestLength = 32;
        break;
      case 'SHA-512/224':
        this.#digestLength = 28;
        break;
      default:
        this.#digestLength = 64;
    }
  }

  static create(algorithm?: string): Sha512Digest {
    Sha512.#ensureInit();
    const resolved = (algorithm ?? 'SHA-512') as Sha512Algorithm;
    if (!(resolved in Sha512.#states!)) {
      throw new Error('Invalid SHA-512 algorithm: ' + resolved);
    }
    const engine = new Sha512(resolved);
    const md: Sha512Digest = {
      algorithm: resolved.replace('-', '').toLowerCase(),
      blockLength: 128,
      digestLength: engine.#digestLength,
      messageLength: 0,
      fullMessageLength: null,
      messageLength128: null,
      messageLengthSize: 16,
      start: () => engine.#start(md),
      update: (msg, encoding) => engine.#update(md, msg, encoding),
      digest: () => engine.#digest(md)
    };
    md.start();
    return md;
  }

  #start(md: Sha512Digest): Sha512Digest {
    md.messageLength = 0;
    md.fullMessageLength = md.messageLength128 = [];
    const int32s = md.messageLengthSize / 4;
    for (let i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0);
    }
    this.#input = new ByteStringBuffer();
    this.#h = this.#initialState.map((word) => word.slice(0) as Sha512StateWord);
    return md;
  }

  #update(md: Sha512Digest, msg: string, encoding?: string): Sha512Digest {
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
    Sha512.#updateState(this.#h!, this.#w, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Sha512Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining =
      md.fullMessageLength![md.fullMessageLength!.length - 1]! +
      md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Sha512.#padding!.substr(0, md.blockLength - overflow));

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

    const h = this.#h!.map((word) => word.slice(0) as Sha512StateWord);
    Sha512.#updateState(h, this.#w, finalBlock);
    const rval = new ByteStringBuffer();
    let hlen: number;
    if (this.#algorithm === 'SHA-512') {
      hlen = h.length;
    } else if (this.#algorithm === 'SHA-384') {
      hlen = h.length - 2;
    } else {
      hlen = h.length - 4;
    }
    for (let i = 0; i < hlen; ++i) {
      rval.putInt32(h[i]![0]!);
      if (i !== hlen - 1 || this.#algorithm !== 'SHA-512/224') {
        rval.putInt32(h[i]![1]!);
      }
    }
    return rval;
  }

  static #updateState(s: Sha512State, w: Sha512StateWord[], bytes: ByteStringBuffer): void {
    const k = Sha512.#k!;
    let t1Hi: number;
    let t1Lo: number;
    let t2Hi: number;
    let t2Lo: number;
    let s0Hi: number;
    let s0Lo: number;
    let s1Hi: number;
    let s1Lo: number;
    let chHi: number;
    let chLo: number;
    let majHi: number;
    let majLo: number;
    let aHi: number;
    let aLo: number;
    let bHi: number;
    let bLo: number;
    let cHi: number;
    let cLo: number;
    let dHi: number;
    let dLo: number;
    let eHi: number;
    let eLo: number;
    let fHi: number;
    let fLo: number;
    let gHi: number;
    let gLo: number;
    let hHi: number;
    let hLo: number;
    let i: number;
    let hi: number;
    let lo: number;
    let w2: Sha512StateWord;
    let w7: Sha512StateWord;
    let w15: Sha512StateWord;
    let w16: Sha512StateWord;
    let len = bytes.length();
    while (len >= 128) {
      for (i = 0; i < 16; ++i) {
        w[i]![0] = bytes.getInt32() >>> 0;
        w[i]![1] = bytes.getInt32() >>> 0;
      }
      for (; i < 80; ++i) {
        w2 = w[i - 2]!;
        hi = w2[0]!;
        lo = w2[1]!;

        t1Hi = (
          ((hi >>> 19) | (lo << 13)) ^
          ((lo >>> 29) | (hi << 3)) ^
          (hi >>> 6)) >>> 0;
        t1Lo = (
          ((hi << 13) | (lo >>> 19)) ^
          ((lo << 3) | (hi >>> 29)) ^
          ((hi << 26) | (lo >>> 6))) >>> 0;

        w15 = w[i - 15]!;
        hi = w15[0]!;
        lo = w15[1]!;

        t2Hi = (
          ((hi >>> 1) | (lo << 31)) ^
          ((hi >>> 8) | (lo << 24)) ^
          (hi >>> 7)) >>> 0;
        t2Lo = (
          ((hi << 31) | (lo >>> 1)) ^
          ((hi << 24) | (lo >>> 8)) ^
          ((hi << 25) | (lo >>> 7))) >>> 0;

        w7 = w[i - 7]!;
        w16 = w[i - 16]!;
        lo = (t1Lo + w7[1]! + t2Lo + w16[1]!);
        w[i]![0] = (t1Hi + w7[0]! + t2Hi + w16[0]! +
          ((lo / 0x100000000) >>> 0)) >>> 0;
        w[i]![1] = lo >>> 0;
      }

      aHi = s[0]![0]!;
      aLo = s[0]![1]!;
      bHi = s[1]![0]!;
      bLo = s[1]![1]!;
      cHi = s[2]![0]!;
      cLo = s[2]![1]!;
      dHi = s[3]![0]!;
      dLo = s[3]![1]!;
      eHi = s[4]![0]!;
      eLo = s[4]![1]!;
      fHi = s[5]![0]!;
      fLo = s[5]![1]!;
      gHi = s[6]![0]!;
      gLo = s[6]![1]!;
      hHi = s[7]![0]!;
      hLo = s[7]![1]!;

      for (i = 0; i < 80; ++i) {
        s1Hi = (
          ((eHi >>> 14) | (eLo << 18)) ^
          ((eHi >>> 18) | (eLo << 14)) ^
          ((eLo >>> 9) | (eHi << 23))) >>> 0;
        s1Lo = (
          ((eHi << 18) | (eLo >>> 14)) ^
          ((eHi << 14) | (eLo >>> 18)) ^
          ((eLo << 23) | (eHi >>> 9))) >>> 0;

        chHi = (gHi ^ (eHi & (fHi ^ gHi))) >>> 0;
        chLo = (gLo ^ (eLo & (fLo ^ gLo))) >>> 0;

        s0Hi = (
          ((aHi >>> 28) | (aLo << 4)) ^
          ((aLo >>> 2) | (aHi << 30)) ^
          ((aLo >>> 7) | (aHi << 25))) >>> 0;
        s0Lo = (
          ((aHi << 4) | (aLo >>> 28)) ^
          ((aLo << 30) | (aHi >>> 2)) ^
          ((aLo << 25) | (aHi >>> 7))) >>> 0;

        majHi = ((aHi & bHi) | (cHi & (aHi ^ bHi))) >>> 0;
        majLo = ((aLo & bLo) | (cLo & (aLo ^ bLo))) >>> 0;

        lo = (hLo + s1Lo + chLo + k[i]![1]! + w[i]![1]!);
        t1Hi = (hHi + s1Hi + chHi + k[i]![0]! + w[i]![0]! +
          ((lo / 0x100000000) >>> 0)) >>> 0;
        t1Lo = lo >>> 0;

        lo = s0Lo + majLo;
        t2Hi = (s0Hi + majHi + ((lo / 0x100000000) >>> 0)) >>> 0;
        t2Lo = lo >>> 0;

        hHi = gHi;
        hLo = gLo;

        gHi = fHi;
        gLo = fLo;

        fHi = eHi;
        fLo = eLo;

        lo = dLo + t1Lo;
        eHi = (dHi + t1Hi + ((lo / 0x100000000) >>> 0)) >>> 0;
        eLo = lo >>> 0;

        dHi = cHi;
        dLo = cLo;

        cHi = bHi;
        cLo = bLo;

        bHi = aHi;
        bLo = aLo;

        lo = t1Lo + t2Lo;
        aHi = (t1Hi + t2Hi + ((lo / 0x100000000) >>> 0)) >>> 0;
        aLo = lo >>> 0;
      }

      lo = s[0]![1]! + aLo;
      s[0]![0] = (s[0]![0]! + aHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[0]![1] = lo >>> 0;

      lo = s[1]![1]! + bLo;
      s[1]![0] = (s[1]![0]! + bHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[1]![1] = lo >>> 0;

      lo = s[2]![1]! + cLo;
      s[2]![0] = (s[2]![0]! + cHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[2]![1] = lo >>> 0;

      lo = s[3]![1]! + dLo;
      s[3]![0] = (s[3]![0]! + dHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[3]![1] = lo >>> 0;

      lo = s[4]![1]! + eLo;
      s[4]![0] = (s[4]![0]! + eHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[4]![1] = lo >>> 0;

      lo = s[5]![1]! + fLo;
      s[5]![0] = (s[5]![0]! + fHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[5]![1] = lo >>> 0;

      lo = s[6]![1]! + gLo;
      s[6]![0] = (s[6]![0]! + gHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[6]![1] = lo >>> 0;

      lo = s[7]![1]! + hLo;
      s[7]![0] = (s[7]![0]! + hHi + ((lo / 0x100000000) >>> 0)) >>> 0;
      s[7]![1] = lo >>> 0;

      len -= 128;
    }
  }
}

export default Sha512;

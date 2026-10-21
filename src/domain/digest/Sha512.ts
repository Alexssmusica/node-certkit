import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import type { Sha512Digest } from './DigestTypes.js';

type Sha512Algorithm = 'SHA-512' | 'SHA-384' | 'SHA-512/256' | 'SHA-512/224';
type Sha512StateWord = [number, number];
type Sha512State = Sha512StateWord[];

/**
 * Secure Hash Algorithm with a 1024-bit block size implementation.
 */
export class Sha512 {
  static #padding: string | null = null;
  static #roundConstants: Sha512StateWord[] | null = null;
  static #states: Record<string, Sha512State> | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Sha512.#initialized) {
      return;
    }
    Sha512.#padding = String.fromCharCode(128);
    Sha512.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 128);
    Sha512.#roundConstants = [
      [0x428a2f98, 0xd728ae22],
      [0x71374491, 0x23ef65cd],
      [0xb5c0fbcf, 0xec4d3b2f],
      [0xe9b5dba5, 0x8189dbbc],
      [0x3956c25b, 0xf348b538],
      [0x59f111f1, 0xb605d019],
      [0x923f82a4, 0xaf194f9b],
      [0xab1c5ed5, 0xda6d8118],
      [0xd807aa98, 0xa3030242],
      [0x12835b01, 0x45706fbe],
      [0x243185be, 0x4ee4b28c],
      [0x550c7dc3, 0xd5ffb4e2],
      [0x72be5d74, 0xf27b896f],
      [0x80deb1fe, 0x3b1696b1],
      [0x9bdc06a7, 0x25c71235],
      [0xc19bf174, 0xcf692694],
      [0xe49b69c1, 0x9ef14ad2],
      [0xefbe4786, 0x384f25e3],
      [0x0fc19dc6, 0x8b8cd5b5],
      [0x240ca1cc, 0x77ac9c65],
      [0x2de92c6f, 0x592b0275],
      [0x4a7484aa, 0x6ea6e483],
      [0x5cb0a9dc, 0xbd41fbd4],
      [0x76f988da, 0x831153b5],
      [0x983e5152, 0xee66dfab],
      [0xa831c66d, 0x2db43210],
      [0xb00327c8, 0x98fb213f],
      [0xbf597fc7, 0xbeef0ee4],
      [0xc6e00bf3, 0x3da88fc2],
      [0xd5a79147, 0x930aa725],
      [0x06ca6351, 0xe003826f],
      [0x14292967, 0x0a0e6e70],
      [0x27b70a85, 0x46d22ffc],
      [0x2e1b2138, 0x5c26c926],
      [0x4d2c6dfc, 0x5ac42aed],
      [0x53380d13, 0x9d95b3df],
      [0x650a7354, 0x8baf63de],
      [0x766a0abb, 0x3c77b2a8],
      [0x81c2c92e, 0x47edaee6],
      [0x92722c85, 0x1482353b],
      [0xa2bfe8a1, 0x4cf10364],
      [0xa81a664b, 0xbc423001],
      [0xc24b8b70, 0xd0f89791],
      [0xc76c51a3, 0x0654be30],
      [0xd192e819, 0xd6ef5218],
      [0xd6990624, 0x5565a910],
      [0xf40e3585, 0x5771202a],
      [0x106aa070, 0x32bbd1b8],
      [0x19a4c116, 0xb8d2d0c8],
      [0x1e376c08, 0x5141ab53],
      [0x2748774c, 0xdf8eeb99],
      [0x34b0bcb5, 0xe19b48a8],
      [0x391c0cb3, 0xc5c95a63],
      [0x4ed8aa4a, 0xe3418acb],
      [0x5b9cca4f, 0x7763e373],
      [0x682e6ff3, 0xd6b2b8a3],
      [0x748f82ee, 0x5defb2fc],
      [0x78a5636f, 0x43172f60],
      [0x84c87814, 0xa1f0ab72],
      [0x8cc70208, 0x1a6439ec],
      [0x90befffa, 0x23631e28],
      [0xa4506ceb, 0xde82bde9],
      [0xbef9a3f7, 0xb2c67915],
      [0xc67178f2, 0xe372532b],
      [0xca273ece, 0xea26619c],
      [0xd186b8c7, 0x21c0c207],
      [0xeada7dd6, 0xcde0eb1e],
      [0xf57d4f7f, 0xee6ed178],
      [0x06f067aa, 0x72176fba],
      [0x0a637dc5, 0xa2c898a6],
      [0x113f9804, 0xbef90dae],
      [0x1b710b35, 0x131c471b],
      [0x28db77f5, 0x23047d84],
      [0x32caab7b, 0x40c72493],
      [0x3c9ebe0a, 0x15c9bebc],
      [0x431d67c4, 0x9c100d4c],
      [0x4cc5d4be, 0xcb3e42b6],
      [0x597f299c, 0xfc657e2a],
      [0x5fcb6fab, 0x3ad6faec],
      [0x6c44198c, 0x4a475817]
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
        [0x22312194, 0xfc2bf72c],
        [0x9f555fa3, 0xc84c64c2],
        [0x2393b86b, 0x6f53b151],
        [0x96387719, 0x5940eabd],
        [0x96283ee2, 0xa88effe3],
        [0xbe5e1e25, 0x53863992],
        [0x2b0199fc, 0x2c85b8aa],
        [0x0eb72ddc, 0x81c52ca2]
      ],
      'SHA-512/224': [
        [0x8c3d37c8, 0x19544da2],
        [0x73e19966, 0x89dcd4d6],
        [0x1dfab7ae, 0x32ff9c82],
        [0x679dd514, 0x582f9fcf],
        [0x0f6d2b69, 0x7bd44da8],
        [0x77e36f73, 0x04c48942],
        [0x3f9d85a8, 0x6a1d36c8],
        [0x1112e6ad, 0x91d692a1]
      ]
    };
    Sha512.#initialized = true;
  }

  readonly #algorithm: Sha512Algorithm;
  readonly #initialState: Sha512State;
  #hashStateWords: Sha512State | null = null;
  #input = new ByteStringBuffer();
  readonly #messageSchedule: Sha512StateWord[] = Array.from({ length: 80 }, () => [0, 0]);
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
    const messageDigest: Sha512Digest = {
      algorithm: resolved.replace('-', '').toLowerCase(),
      blockLength: 128,
      digestLength: engine.#digestLength,
      messageLength: 0,
      fullMessageLength: null,
      messageLength128: null,
      messageLengthSize: 16,
      start: () => engine.#start(messageDigest),
      update: (input, encoding) => engine.#update(messageDigest, input, encoding),
      digest: () => engine.#digest(messageDigest)
    };
    messageDigest.start();
    return messageDigest;
  }

  #start(messageDigest: Sha512Digest): Sha512Digest {
    messageDigest.messageLength = 0;
    messageDigest.fullMessageLength = messageDigest.messageLength128 = [];
    const int32s = messageDigest.messageLengthSize / 4;
    for (let index = 0; index < int32s; ++index) {
      messageDigest.fullMessageLength.push(0);
    }
    this.#input = new ByteStringBuffer();
    this.#hashStateWords = this.#initialState.map((word) => word.slice(0) as Sha512StateWord);
    return messageDigest;
  }

  #update(messageDigest: Sha512Digest, message: string, encoding?: string): Sha512Digest {
    if (encoding === 'utf8') {
      message = encodeUtf8(message);
    }

    const messageByteLength = message.length;
    messageDigest.messageLength += messageByteLength;
    const lengthCarry = [(messageByteLength / 0x100000000) >>> 0, messageByteLength >>> 0];
    const fullMessageLength = messageDigest.fullMessageLength!;
    for (let index = fullMessageLength.length - 1; index >= 0; --index) {
      fullMessageLength[index] += lengthCarry[1];
      lengthCarry[1] = lengthCarry[0] + ((fullMessageLength[index] / 0x100000000) >>> 0);
      fullMessageLength[index] = fullMessageLength[index] >>> 0;
      lengthCarry[0] = (lengthCarry[1] / 0x100000000) >>> 0;
    }

    this.#input.putBytes(message);
    Sha512.#updateState(this.#hashStateWords!, this.#messageSchedule, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return messageDigest;
  }

  #digest(messageDigest: Sha512Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining =
      messageDigest.fullMessageLength![messageDigest.fullMessageLength!.length - 1] + messageDigest.messageLengthSize;

    const overflow = remaining & (messageDigest.blockLength - 1);
    finalBlock.putBytes(Sha512.#padding!.substr(0, messageDigest.blockLength - overflow));

    let nextLengthBits: number;
    let carryBits: number;
    let bits = messageDigest.fullMessageLength![0] * 8;
    for (let index = 0; index < messageDigest.fullMessageLength!.length - 1; ++index) {
      nextLengthBits = messageDigest.fullMessageLength![index + 1] * 8;
      carryBits = (nextLengthBits / 0x100000000) >>> 0;
      bits += carryBits;
      finalBlock.putInt32(bits >>> 0);
      bits = nextLengthBits >>> 0;
    }
    finalBlock.putInt32(bits);

    const finalHashState = this.#hashStateWords!.map((word) => word.slice(0) as Sha512StateWord);
    Sha512.#updateState(finalHashState, this.#messageSchedule, finalBlock);
    const digestBuffer = new ByteStringBuffer();
    let outputWordPairCount: number;
    if (this.#algorithm === 'SHA-512') {
      outputWordPairCount = finalHashState.length;
    } else if (this.#algorithm === 'SHA-384') {
      outputWordPairCount = finalHashState.length - 2;
    } else {
      outputWordPairCount = finalHashState.length - 4;
    }
    for (let index = 0; index < outputWordPairCount; ++index) {
      digestBuffer.putInt32(finalHashState[index][0]);
      if (index !== outputWordPairCount - 1 || this.#algorithm !== 'SHA-512/224') {
        digestBuffer.putInt32(finalHashState[index][1]);
      }
    }
    return digestBuffer;
  }

  static #updateState(hashState: Sha512State, messageSchedule: Sha512StateWord[], bytes: ByteStringBuffer): void {
    const roundConstants = Sha512.#roundConstants!;
    let roundSum1Hi: number;
    let roundSum1Lo: number;
    let roundSum2Hi: number;
    let roundSum2Lo: number;
    let sigma0UpperHi: number;
    let sigma0UpperLo: number;
    let sigma1UpperHi: number;
    let sigma1UpperLo: number;
    let chooseHi: number;
    let chooseLo: number;
    let majorityHi: number;
    let majorityLo: number;
    let workAHi: number;
    let workALo: number;
    let workBHi: number;
    let workBLo: number;
    let workCHi: number;
    let workCLo: number;
    let workDHi: number;
    let workDLo: number;
    let workEHi: number;
    let workELo: number;
    let workFHi: number;
    let workFLo: number;
    let workGHi: number;
    let workGLo: number;
    let workHHi: number;
    let workHLo: number;
    let roundIndex: number;
    let wordHigh: number;
    let wordLow: number;
    let scheduleWordMinus2: Sha512StateWord;
    let scheduleWordMinus7: Sha512StateWord;
    let scheduleWordMinus15: Sha512StateWord;
    let scheduleWordMinus16: Sha512StateWord;
    let remainingBytes = bytes.length();
    while (remainingBytes >= 128) {
      for (roundIndex = 0; roundIndex < 16; ++roundIndex) {
        messageSchedule[roundIndex][0] = bytes.getInt32() >>> 0;
        messageSchedule[roundIndex][1] = bytes.getInt32() >>> 0;
      }
      for (; roundIndex < 80; ++roundIndex) {
        scheduleWordMinus2 = messageSchedule[roundIndex - 2]!;
        wordHigh = scheduleWordMinus2[0]!;
        wordLow = scheduleWordMinus2[1]!;

        roundSum1Hi =
          (((wordHigh >>> 19) | (wordLow << 13)) ^ ((wordLow >>> 29) | (wordHigh << 3)) ^ (wordHigh >>> 6)) >>> 0;
        roundSum1Lo =
          (((wordHigh << 13) | (wordLow >>> 19)) ^
            ((wordLow << 3) | (wordHigh >>> 29)) ^
            ((wordHigh << 26) | (wordLow >>> 6))) >>>
          0;

        scheduleWordMinus15 = messageSchedule[roundIndex - 15]!;
        wordHigh = scheduleWordMinus15[0]!;
        wordLow = scheduleWordMinus15[1]!;

        roundSum2Hi =
          (((wordHigh >>> 1) | (wordLow << 31)) ^ ((wordHigh >>> 8) | (wordLow << 24)) ^ (wordHigh >>> 7)) >>> 0;
        roundSum2Lo =
          (((wordHigh << 31) | (wordLow >>> 1)) ^
            ((wordHigh << 24) | (wordLow >>> 8)) ^
            ((wordHigh << 25) | (wordLow >>> 7))) >>>
          0;

        scheduleWordMinus7 = messageSchedule[roundIndex - 7]!;
        scheduleWordMinus16 = messageSchedule[roundIndex - 16]!;
        wordLow = roundSum1Lo + scheduleWordMinus7[1] + roundSum2Lo + scheduleWordMinus16[1];
        messageSchedule[roundIndex][0] =
          (roundSum1Hi +
            scheduleWordMinus7[0] +
            roundSum2Hi +
            scheduleWordMinus16[0] +
            ((wordLow / 0x100000000) >>> 0)) >>>
          0;
        messageSchedule[roundIndex][1] = wordLow >>> 0;
      }

      workAHi = hashState[0][0]!;
      workALo = hashState[0][1]!;
      workBHi = hashState[1][0]!;
      workBLo = hashState[1][1]!;
      workCHi = hashState[2][0]!;
      workCLo = hashState[2][1]!;
      workDHi = hashState[3][0]!;
      workDLo = hashState[3][1]!;
      workEHi = hashState[4][0]!;
      workELo = hashState[4][1]!;
      workFHi = hashState[5][0]!;
      workFLo = hashState[5][1]!;
      workGHi = hashState[6][0]!;
      workGLo = hashState[6][1]!;
      workHHi = hashState[7][0]!;
      workHLo = hashState[7][1]!;

      for (roundIndex = 0; roundIndex < 80; ++roundIndex) {
        sigma1UpperHi =
          (((workEHi >>> 14) | (workELo << 18)) ^
            ((workEHi >>> 18) | (workELo << 14)) ^
            ((workELo >>> 9) | (workEHi << 23))) >>>
          0;
        sigma1UpperLo =
          (((workEHi << 18) | (workELo >>> 14)) ^
            ((workEHi << 14) | (workELo >>> 18)) ^
            ((workELo << 23) | (workEHi >>> 9))) >>>
          0;

        chooseHi = (workGHi ^ (workEHi & (workFHi ^ workGHi))) >>> 0;
        chooseLo = (workGLo ^ (workELo & (workFLo ^ workGLo))) >>> 0;

        sigma0UpperHi =
          (((workAHi >>> 28) | (workALo << 4)) ^
            ((workALo >>> 2) | (workAHi << 30)) ^
            ((workALo >>> 7) | (workAHi << 25))) >>>
          0;
        sigma0UpperLo =
          (((workAHi << 4) | (workALo >>> 28)) ^
            ((workALo << 30) | (workAHi >>> 2)) ^
            ((workALo << 25) | (workAHi >>> 7))) >>>
          0;

        majorityHi = ((workAHi & workBHi) | (workCHi & (workAHi ^ workBHi))) >>> 0;
        majorityLo = ((workALo & workBLo) | (workCLo & (workALo ^ workBLo))) >>> 0;

        wordLow = workHLo + sigma1UpperLo + chooseLo + roundConstants[roundIndex][1] + messageSchedule[roundIndex][1];
        roundSum1Hi =
          (workHHi +
            sigma1UpperHi +
            chooseHi +
            roundConstants[roundIndex][0] +
            messageSchedule[roundIndex][0] +
            ((wordLow / 0x100000000) >>> 0)) >>>
          0;
        roundSum1Lo = wordLow >>> 0;

        wordLow = sigma0UpperLo + majorityLo;
        roundSum2Hi = (sigma0UpperHi + majorityHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
        roundSum2Lo = wordLow >>> 0;

        workHHi = workGHi;
        workHLo = workGLo;

        workGHi = workFHi;
        workGLo = workFLo;

        workFHi = workEHi;
        workFLo = workELo;

        wordLow = workDLo + roundSum1Lo;
        workEHi = (workDHi + roundSum1Hi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
        workELo = wordLow >>> 0;

        workDHi = workCHi;
        workDLo = workCLo;

        workCHi = workBHi;
        workCLo = workBLo;

        workBHi = workAHi;
        workBLo = workALo;

        wordLow = roundSum1Lo + roundSum2Lo;
        workAHi = (roundSum1Hi + roundSum2Hi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
        workALo = wordLow >>> 0;
      }

      wordLow = hashState[0][1] + workALo;
      hashState[0][0] = (hashState[0][0] + workAHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[0][1] = wordLow >>> 0;

      wordLow = hashState[1][1] + workBLo;
      hashState[1][0] = (hashState[1][0] + workBHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[1][1] = wordLow >>> 0;

      wordLow = hashState[2][1] + workCLo;
      hashState[2][0] = (hashState[2][0] + workCHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[2][1] = wordLow >>> 0;

      wordLow = hashState[3][1] + workDLo;
      hashState[3][0] = (hashState[3][0] + workDHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[3][1] = wordLow >>> 0;

      wordLow = hashState[4][1] + workELo;
      hashState[4][0] = (hashState[4][0] + workEHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[4][1] = wordLow >>> 0;

      wordLow = hashState[5][1] + workFLo;
      hashState[5][0] = (hashState[5][0] + workFHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[5][1] = wordLow >>> 0;

      wordLow = hashState[6][1] + workGLo;
      hashState[6][0] = (hashState[6][0] + workGHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[6][1] = wordLow >>> 0;

      wordLow = hashState[7][1] + workHLo;
      hashState[7][0] = (hashState[7][0] + workHHi + ((wordLow / 0x100000000) >>> 0)) >>> 0;
      hashState[7][1] = wordLow >>> 0;

      remainingBytes -= 128;
    }
  }
}

export default Sha512;

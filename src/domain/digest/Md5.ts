import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import type { Md5Digest } from './DigestTypes.js';

interface Md5State {
  hashWord0: number;
  hashWord1: number;
  hashWord2: number;
  hashWord3: number;
}

/**
 * Message Digest Algorithm 5 with 128-bit digest (MD5) implementation.
 */
export class Md5 {
  static #padding: string | null = null;
  static #messageIndexPermutation: number[] | null = null;
  static #rotateShiftAmounts: number[] | null = null;
  static #sineConstants: number[] | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Md5.#initialized) {
      return;
    }
    Md5.#padding = String.fromCharCode(128);
    Md5.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 64);
    Md5.#messageIndexPermutation = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8,
      11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
    ];
    Md5.#rotateShiftAmounts = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
      20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
      10, 15, 21
    ];
    Md5.#sineConstants = new Array<number>(64);
    for (let i = 0; i < 64; ++i) {
      Md5.#sineConstants[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
    }
    Md5.#initialized = true;
  }

  #state: Md5State | null = null;
  #input = new ByteStringBuffer();
  readonly #messageBlock = new Array<number>(16);

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
      update: (input, encoding) => engine.#update(md, input, encoding),
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
      hashWord0: 0x67452301,
      hashWord1: 0xefcdab89,
      hashWord2: 0x98badcfe,
      hashWord3: 0x10325476
    };
    return md;
  }

  #update(md: Md5Digest, message: string, encoding?: string): Md5Digest {
    if (encoding === 'utf8') {
      message = encodeUtf8(message);
    }

    const messageByteLength = message.length;
    md.messageLength += messageByteLength;
    const lengthCarry = [(messageByteLength / 0x100000000) >>> 0, messageByteLength >>> 0];
    const fullMessageLength = md.fullMessageLength!;
    for (let i = fullMessageLength.length - 1; i >= 0; --i) {
      fullMessageLength[i] += lengthCarry[1];
      lengthCarry[1] = lengthCarry[0] + ((fullMessageLength[i] / 0x100000000) >>> 0);
      fullMessageLength[i] = fullMessageLength[i] >>> 0;
      lengthCarry[0] = (lengthCarry[1] / 0x100000000) >>> 0;
    }

    this.#input.putBytes(message);
    Md5.#updateState(this.#state!, this.#messageBlock, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Md5Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining = md.fullMessageLength![md.fullMessageLength!.length - 1] + md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Md5.#padding!.substr(0, md.blockLength - overflow));

    let lengthBits: number;
    let carryBits = 0;
    for (let i = md.fullMessageLength!.length - 1; i >= 0; --i) {
      lengthBits = md.fullMessageLength![i] * 8 + carryBits;
      carryBits = (lengthBits / 0x100000000) >>> 0;
      finalBlock.putInt32Le(lengthBits >>> 0);
    }

    const finalState = {
      hashWord0: this.#state!.hashWord0,
      hashWord1: this.#state!.hashWord1,
      hashWord2: this.#state!.hashWord2,
      hashWord3: this.#state!.hashWord3
    };
    Md5.#updateState(finalState, this.#messageBlock, finalBlock);
    const digestBuffer = new ByteStringBuffer();
    digestBuffer.putInt32Le(finalState.hashWord0);
    digestBuffer.putInt32Le(finalState.hashWord1);
    digestBuffer.putInt32Le(finalState.hashWord2);
    digestBuffer.putInt32Le(finalState.hashWord3);
    return digestBuffer;
  }

  static #updateState(state: Md5State, messageBlock: number[], bytes: ByteStringBuffer): void {
    const messageIndexPermutation = Md5.#messageIndexPermutation!;
    const rotateShiftAmounts = Md5.#rotateShiftAmounts!;
    const sineConstants = Md5.#sineConstants!;
    let roundAccumulator: number;
    let workA: number;
    let workB: number;
    let workC: number;
    let workD: number;
    let mixFunction: number;
    let rotateAmount: number;
    let roundIndex: number;
    let remainingBytes = bytes.length();
    while (remainingBytes >= 64) {
      workA = state.hashWord0;
      workB = state.hashWord1;
      workC = state.hashWord2;
      workD = state.hashWord3;

      for (roundIndex = 0; roundIndex < 16; ++roundIndex) {
        messageBlock[roundIndex] = bytes.getInt32Le();
        mixFunction = workD ^ (workB & (workC ^ workD));
        roundAccumulator = workA + mixFunction + sineConstants[roundIndex] + messageBlock[roundIndex];
        rotateAmount = rotateShiftAmounts[roundIndex]!;
        workA = workD;
        workD = workC;
        workC = workB;
        workB += (roundAccumulator << rotateAmount) | (roundAccumulator >>> (32 - rotateAmount));
      }
      for (; roundIndex < 32; ++roundIndex) {
        mixFunction = workC ^ (workD & (workB ^ workC));
        roundAccumulator =
          workA + mixFunction + sineConstants[roundIndex] + messageBlock[messageIndexPermutation[roundIndex]];
        rotateAmount = rotateShiftAmounts[roundIndex]!;
        workA = workD;
        workD = workC;
        workC = workB;
        workB += (roundAccumulator << rotateAmount) | (roundAccumulator >>> (32 - rotateAmount));
      }
      for (; roundIndex < 48; ++roundIndex) {
        mixFunction = workB ^ workC ^ workD;
        roundAccumulator =
          workA + mixFunction + sineConstants[roundIndex] + messageBlock[messageIndexPermutation[roundIndex]];
        rotateAmount = rotateShiftAmounts[roundIndex]!;
        workA = workD;
        workD = workC;
        workC = workB;
        workB += (roundAccumulator << rotateAmount) | (roundAccumulator >>> (32 - rotateAmount));
      }
      for (; roundIndex < 64; ++roundIndex) {
        mixFunction = workC ^ (workB | ~workD);
        roundAccumulator =
          workA + mixFunction + sineConstants[roundIndex] + messageBlock[messageIndexPermutation[roundIndex]];
        rotateAmount = rotateShiftAmounts[roundIndex]!;
        workA = workD;
        workD = workC;
        workC = workB;
        workB += (roundAccumulator << rotateAmount) | (roundAccumulator >>> (32 - rotateAmount));
      }

      state.hashWord0 = (state.hashWord0 + workA) | 0;
      state.hashWord1 = (state.hashWord1 + workB) | 0;
      state.hashWord2 = (state.hashWord2 + workC) | 0;
      state.hashWord3 = (state.hashWord3 + workD) | 0;

      remainingBytes -= 64;
    }
  }
}

export default Md5;

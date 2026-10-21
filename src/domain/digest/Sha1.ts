import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import type { Sha1Digest } from './DigestTypes.js';

interface Sha1State {
  hashWord0: number;
  hashWord1: number;
  hashWord2: number;
  hashWord3: number;
  hashWord4: number;
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
  readonly #messageSchedule = new Array<number>(80);

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
      update: (input, encoding) => engine.#update(md, input, encoding),
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
      hashWord0: 0x67452301,
      hashWord1: 0xefcdab89,
      hashWord2: 0x98badcfe,
      hashWord3: 0x10325476,
      hashWord4: 0xc3d2e1f0
    };
    return md;
  }

  #update(md: Sha1Digest, message: string, encoding?: string): Sha1Digest {
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
    Sha1.#updateState(this.#state!, this.#messageSchedule, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Sha1Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining = md.fullMessageLength![md.fullMessageLength!.length - 1] + md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Sha1.#padding!.substr(0, md.blockLength - overflow));

    let nextLengthBits: number;
    let carryBits: number;
    let bits = md.fullMessageLength![0] * 8;
    for (let i = 0; i < md.fullMessageLength!.length - 1; ++i) {
      nextLengthBits = md.fullMessageLength![i + 1] * 8;
      carryBits = (nextLengthBits / 0x100000000) >>> 0;
      bits += carryBits;
      finalBlock.putInt32(bits >>> 0);
      bits = nextLengthBits >>> 0;
    }
    finalBlock.putInt32(bits);

    const finalState = {
      hashWord0: this.#state!.hashWord0,
      hashWord1: this.#state!.hashWord1,
      hashWord2: this.#state!.hashWord2,
      hashWord3: this.#state!.hashWord3,
      hashWord4: this.#state!.hashWord4
    };
    Sha1.#updateState(finalState, this.#messageSchedule, finalBlock);
    const digestBuffer = new ByteStringBuffer();
    digestBuffer.putInt32(finalState.hashWord0);
    digestBuffer.putInt32(finalState.hashWord1);
    digestBuffer.putInt32(finalState.hashWord2);
    digestBuffer.putInt32(finalState.hashWord3);
    digestBuffer.putInt32(finalState.hashWord4);
    return digestBuffer;
  }

  static #updateState(state: Sha1State, messageSchedule: number[], bytes: ByteStringBuffer): void {
    let roundTemp: number;
    let workA: number;
    let workB: number;
    let workC: number;
    let workD: number;
    let workE: number;
    let mixFunction: number;
    let roundIndex: number;
    let remainingBytes = bytes.length();
    while (remainingBytes >= 64) {
      workA = state.hashWord0;
      workB = state.hashWord1;
      workC = state.hashWord2;
      workD = state.hashWord3;
      workE = state.hashWord4;

      for (roundIndex = 0; roundIndex < 16; ++roundIndex) {
        roundTemp = bytes.getInt32();
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = workD ^ (workB & (workC ^ workD));
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0x5a827999 + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }
      for (; roundIndex < 20; ++roundIndex) {
        roundTemp =
          messageSchedule[roundIndex - 3] ^
          messageSchedule[roundIndex - 8] ^
          messageSchedule[roundIndex - 14] ^
          messageSchedule[roundIndex - 16];
        roundTemp = (roundTemp << 1) | (roundTemp >>> 31);
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = workD ^ (workB & (workC ^ workD));
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0x5a827999 + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }
      for (; roundIndex < 32; ++roundIndex) {
        roundTemp =
          messageSchedule[roundIndex - 3] ^
          messageSchedule[roundIndex - 8] ^
          messageSchedule[roundIndex - 14] ^
          messageSchedule[roundIndex - 16];
        roundTemp = (roundTemp << 1) | (roundTemp >>> 31);
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = workB ^ workC ^ workD;
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0x6ed9eba1 + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }
      for (; roundIndex < 40; ++roundIndex) {
        roundTemp =
          messageSchedule[roundIndex - 6] ^
          messageSchedule[roundIndex - 16] ^
          messageSchedule[roundIndex - 28] ^
          messageSchedule[roundIndex - 32];
        roundTemp = (roundTemp << 2) | (roundTemp >>> 30);
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = workB ^ workC ^ workD;
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0x6ed9eba1 + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }
      for (; roundIndex < 60; ++roundIndex) {
        roundTemp =
          messageSchedule[roundIndex - 6] ^
          messageSchedule[roundIndex - 16] ^
          messageSchedule[roundIndex - 28] ^
          messageSchedule[roundIndex - 32];
        roundTemp = (roundTemp << 2) | (roundTemp >>> 30);
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = (workB & workC) | (workD & (workB ^ workC));
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0x8f1bbcdc + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }
      for (; roundIndex < 80; ++roundIndex) {
        roundTemp =
          messageSchedule[roundIndex - 6] ^
          messageSchedule[roundIndex - 16] ^
          messageSchedule[roundIndex - 28] ^
          messageSchedule[roundIndex - 32];
        roundTemp = (roundTemp << 2) | (roundTemp >>> 30);
        messageSchedule[roundIndex] = roundTemp;
        mixFunction = workB ^ workC ^ workD;
        roundTemp = ((workA << 5) | (workA >>> 27)) + mixFunction + workE + 0xca62c1d6 + roundTemp;
        workE = workD;
        workD = workC;
        workC = ((workB << 30) | (workB >>> 2)) >>> 0;
        workB = workA;
        workA = roundTemp;
      }

      state.hashWord0 = (state.hashWord0 + workA) | 0;
      state.hashWord1 = (state.hashWord1 + workB) | 0;
      state.hashWord2 = (state.hashWord2 + workC) | 0;
      state.hashWord3 = (state.hashWord3 + workD) | 0;
      state.hashWord4 = (state.hashWord4 + workE) | 0;

      remainingBytes -= 64;
    }
  }
}

export default Sha1;

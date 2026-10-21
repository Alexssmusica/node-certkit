import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { encodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import type { Sha256Digest } from './DigestTypes.js';

interface Sha256State {
  hashWord0: number;
  hashWord1: number;
  hashWord2: number;
  hashWord3: number;
  hashWord4: number;
  hashWord5: number;
  hashWord6: number;
  hashWord7: number;
}

/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 */
export class Sha256 {
  static #padding: string | null = null;
  static #roundConstants: number[] | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (Sha256.#initialized) {
      return;
    }
    Sha256.#padding = String.fromCharCode(128);
    Sha256.#padding += UtilNamespace.fillString(String.fromCharCode(0x00), 64);
    Sha256.#roundConstants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
      0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
      0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2
    ];
    Sha256.#initialized = true;
  }

  #state: Sha256State | null = null;
  #input = new ByteStringBuffer();
  readonly #messageSchedule = new Array<number>(64);

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
      update: (input, encoding) => engine.#update(md, input, encoding),
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
      hashWord0: 0x6a09e667,
      hashWord1: 0xbb67ae85,
      hashWord2: 0x3c6ef372,
      hashWord3: 0xa54ff53a,
      hashWord4: 0x510e527f,
      hashWord5: 0x9b05688c,
      hashWord6: 0x1f83d9ab,
      hashWord7: 0x5be0cd19
    };
    return md;
  }

  #update(md: Sha256Digest, message: string, encoding?: string): Sha256Digest {
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
    Sha256.#updateState(this.#state!, this.#messageSchedule, this.#input);

    if (this.#input.read > 2048 || this.#input.length() === 0) {
      this.#input.compact();
    }

    return md;
  }

  #digest(md: Sha256Digest): ByteStringBuffer {
    const finalBlock = new ByteStringBuffer();
    finalBlock.putBytes(this.#input.bytes());

    const remaining = md.fullMessageLength![md.fullMessageLength!.length - 1] + md.messageLengthSize;

    const overflow = remaining & (md.blockLength - 1);
    finalBlock.putBytes(Sha256.#padding!.substr(0, md.blockLength - overflow));

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
      hashWord4: this.#state!.hashWord4,
      hashWord5: this.#state!.hashWord5,
      hashWord6: this.#state!.hashWord6,
      hashWord7: this.#state!.hashWord7
    };
    Sha256.#updateState(finalState, this.#messageSchedule, finalBlock);
    const digestBuffer = new ByteStringBuffer();
    digestBuffer.putInt32(finalState.hashWord0);
    digestBuffer.putInt32(finalState.hashWord1);
    digestBuffer.putInt32(finalState.hashWord2);
    digestBuffer.putInt32(finalState.hashWord3);
    digestBuffer.putInt32(finalState.hashWord4);
    digestBuffer.putInt32(finalState.hashWord5);
    digestBuffer.putInt32(finalState.hashWord6);
    digestBuffer.putInt32(finalState.hashWord7);
    return digestBuffer;
  }

  static #updateState(state: Sha256State, messageSchedule: number[], bytes: ByteStringBuffer): void {
    const roundConstants = Sha256.#roundConstants!;
    let roundSum1: number;
    let roundSum2: number;
    let sigma0Upper: number;
    let sigma1Upper: number;
    let choose: number;
    let majority: number;
    let roundIndex: number;
    let workA: number;
    let workB: number;
    let workC: number;
    let workD: number;
    let workE: number;
    let workF: number;
    let workG: number;
    let workH: number;
    let remainingBytes = bytes.length();
    while (remainingBytes >= 64) {
      for (roundIndex = 0; roundIndex < 16; ++roundIndex) {
        messageSchedule[roundIndex] = bytes.getInt32();
      }
      for (; roundIndex < 64; ++roundIndex) {
        roundSum1 = messageSchedule[roundIndex - 2]!;
        roundSum1 =
          ((roundSum1 >>> 17) | (roundSum1 << 15)) ^ ((roundSum1 >>> 19) | (roundSum1 << 13)) ^ (roundSum1 >>> 10);
        roundSum2 = messageSchedule[roundIndex - 15]!;
        roundSum2 =
          ((roundSum2 >>> 7) | (roundSum2 << 25)) ^ ((roundSum2 >>> 18) | (roundSum2 << 14)) ^ (roundSum2 >>> 3);
        messageSchedule[roundIndex] =
          (roundSum1 + messageSchedule[roundIndex - 7] + roundSum2 + messageSchedule[roundIndex - 16]) | 0;
      }

      workA = state.hashWord0;
      workB = state.hashWord1;
      workC = state.hashWord2;
      workD = state.hashWord3;
      workE = state.hashWord4;
      workF = state.hashWord5;
      workG = state.hashWord6;
      workH = state.hashWord7;

      for (roundIndex = 0; roundIndex < 64; ++roundIndex) {
        sigma1Upper =
          ((workE >>> 6) | (workE << 26)) ^ ((workE >>> 11) | (workE << 21)) ^ ((workE >>> 25) | (workE << 7));
        choose = workG ^ (workE & (workF ^ workG));
        sigma0Upper =
          ((workA >>> 2) | (workA << 30)) ^ ((workA >>> 13) | (workA << 19)) ^ ((workA >>> 22) | (workA << 10));
        majority = (workA & workB) | (workC & (workA ^ workB));

        roundSum1 = workH + sigma1Upper + choose + roundConstants[roundIndex] + messageSchedule[roundIndex];
        roundSum2 = sigma0Upper + majority;
        workH = workG;
        workG = workF;
        workF = workE;
        workE = (workD + roundSum1) >>> 0;
        workD = workC;
        workC = workB;
        workB = workA;
        workA = (roundSum1 + roundSum2) >>> 0;
      }

      state.hashWord0 = (state.hashWord0 + workA) | 0;
      state.hashWord1 = (state.hashWord1 + workB) | 0;
      state.hashWord2 = (state.hashWord2 + workC) | 0;
      state.hashWord3 = (state.hashWord3 + workD) | 0;
      state.hashWord4 = (state.hashWord4 + workE) | 0;
      state.hashWord5 = (state.hashWord5 + workF) | 0;
      state.hashWord6 = (state.hashWord6 + workG) | 0;
      state.hashWord7 = (state.hashWord7 + workH) | 0;
      remainingBytes -= 64;
    }
  }
}

export default Sha256;

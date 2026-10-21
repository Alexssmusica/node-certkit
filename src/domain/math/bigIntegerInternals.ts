import type { BigInteger } from './BigInteger.js';
import type { BigIntegerRandomSource } from './BigIntegerTypes.js';

export const dbits = 28;
export const BI_FP = 52;
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
const BI_RC: number[] = new Array<number>();
let radixWriteIndex: number;
let digitValue: number;
radixWriteIndex = '0'.charCodeAt(0);
for (digitValue = 0; digitValue <= 9; ++digitValue) BI_RC[radixWriteIndex++] = digitValue;
radixWriteIndex = 'a'.charCodeAt(0);
for (digitValue = 10; digitValue < 36; ++digitValue) BI_RC[radixWriteIndex++] = digitValue;
radixWriteIndex = 'A'.charCodeAt(0);
for (digitValue = 10; digitValue < 36; ++digitValue) BI_RC[radixWriteIndex++] = digitValue;

export const lowprimes = [
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
  113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
  241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
  383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
  523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
  673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
  829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
];
export const lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

export function int2char(digit: number): string {
  return BI_RM.charAt(digit);
}
export function intAt(string: string, index: number): number {
  const code = BI_RC[string.charCodeAt(index)];
  return code == null ? -1 : code;
}

export function nbits(word: number): number {
  let bitCount = 1;
  let shifted: number;
  if ((shifted = word >>> 16) != 0) {
    word = shifted;
    bitCount += 16;
  }
  if ((shifted = word >> 8) != 0) {
    word = shifted;
    bitCount += 8;
  }
  if ((shifted = word >> 4) != 0) {
    word = shifted;
    bitCount += 4;
  }
  if ((shifted = word >> 2) != 0) {
    word = shifted;
    bitCount += 2;
  }
  if (word >> 1 != 0) {
    bitCount += 1;
  }
  return bitCount;
}

export function lbit(word: number): number {
  if (word == 0) return -1;
  let trailingZeros = 0;
  if ((word & 0xffff) == 0) {
    word >>= 16;
    trailingZeros += 16;
  }
  if ((word & 0xff) == 0) {
    word >>= 8;
    trailingZeros += 8;
  }
  if ((word & 0xf) == 0) {
    word >>= 4;
    trailingZeros += 4;
  }
  if ((word & 3) == 0) {
    word >>= 2;
    trailingZeros += 2;
  }
  if ((word & 1) == 0) ++trailingZeros;
  return trailingZeros;
}

export function cbit(word: number): number {
  let setBits = 0;
  while (word != 0) {
    word &= word - 1;
    ++setBits;
  }
  return setBits;
}

export function opAnd(leftWord: number, rightWord: number): number {
  return leftWord & rightWord;
}
export function opOr(leftWord: number, rightWord: number): number {
  return leftWord | rightWord;
}
export function opXor(leftWord: number, rightWord: number): number {
  return leftWord ^ rightWord;
}
export function opAndNot(leftWord: number, rightWord: number): number {
  return leftWord & ~rightWord;
}

export function bnGetPrng(): BigIntegerRandomSource {
  return {
    nextBytes(bytes: number[]): void {
      for (let i = 0; i < bytes.length; ++i) {
        bytes[i] = Math.floor(Math.random() * 0x0100);
      }
    }
  };
}

export function am3(
  this: BigInteger,
  limbIndex: number,
  operand: number,
  accumulator: BigInteger,
  outIndex: number,
  carry: number,
  limbCount: number
): number {
  const operandLow = operand & 0x3fff;
  const operandHigh = operand >> 14;
  while (--limbCount >= 0) {
    let limbLow = this.data[limbIndex] & 0x3fff;
    const limbHigh = this.data[limbIndex++] >> 14;
    const crossTerm = operandHigh * limbLow + limbHigh * operandLow;
    limbLow = operandLow * limbLow + ((crossTerm & 0x3fff) << 14) + accumulator.data[outIndex] + carry;
    carry = (limbLow >> 28) + (crossTerm >> 14) + operandHigh * limbHigh;
    accumulator.data[outIndex++] = limbLow & 0xfffffff;
  }
  return carry;
}

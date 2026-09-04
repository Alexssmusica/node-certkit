import type { BigInteger } from './BigInteger.js';
import type { BigIntegerRandomSource } from './BigIntegerTypes.js';

export const dbits = 28;
export const BI_FP = 52;
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
const BI_RC: number[] = new Array<number>();
let rr: number;
let vv: number;
rr = '0'.charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = 'a'.charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = 'A'.charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

export const lowprimes = [
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
  139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
  283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
  457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
  631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
];
export const lplim = (1 << 26) / lowprimes[lowprimes.length - 1]!;

export function int2char(n: number): string {
  return BI_RM.charAt(n);
}
export function intAt(s: string, i: number): number {
  const c = BI_RC[s.charCodeAt(i)];
  return c == null ? -1 : c;
}

export function nbits(x: number): number {
  let r = 1,
    t: number;
  if ((t = x >>> 16) != 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    r += 1;
  }
  return r;
}

export function lbit(x: number): number {
  if (x == 0) return -1;
  let r = 0;
  if ((x & 0xffff) == 0) {
    x >>= 16;
    r += 16;
  }
  if ((x & 0xff) == 0) {
    x >>= 8;
    r += 8;
  }
  if ((x & 0xf) == 0) {
    x >>= 4;
    r += 4;
  }
  if ((x & 3) == 0) {
    x >>= 2;
    r += 2;
  }
  if ((x & 1) == 0) ++r;
  return r;
}

export function cbit(x: number): number {
  let r = 0;
  while (x != 0) {
    x &= x - 1;
    ++r;
  }
  return r;
}

export function op_and(x: number, y: number): number {
  return x & y;
}
export function op_or(x: number, y: number): number {
  return x | y;
}
export function op_xor(x: number, y: number): number {
  return x ^ y;
}
export function op_andnot(x: number, y: number): number {
  return x & ~y;
}

export function bnGetPrng(): BigIntegerRandomSource {
  return {
    nextBytes(x: number[]): void {
      for (let i = 0; i < x.length; ++i) {
        x[i] = Math.floor(Math.random() * 0x0100);
      }
    }
  };
}

export function am3(this: BigInteger, i: number, x: number, w: BigInteger, j: number, c: number, n: number): number {
  const xl = x & 0x3fff,
    xh = x >> 14;
  while (--n >= 0) {
    let l = this.data[i]! & 0x3fff;
    const h = this.data[i++]! >> 14;
    const m = xh * l + h * xl;
    l = xl * l + ((m & 0x3fff) << 14) + w.data[j]! + c;
    c = (l >> 28) + (m >> 14) + xh * h;
    w.data[j++] = l & 0xfffffff;
  }
  return c;
}

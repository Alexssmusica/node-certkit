/* Migrated from lib/jsbn.js */
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

import type { BigIntegerRandomSource, BigIntegerReduction, BitwiseWordOp } from './BigIntegerTypes.js';
export type { BigIntegerRandomSource, BigIntegerReduction, BitwiseWordOp } from './BigIntegerTypes.js';
import {
  dbits,
  BI_FP,
  int2char,
  intAt,
  nbits,
  lbit,
  cbit,
  op_and,
  op_or,
  op_xor,
  op_andnot,
  bnGetPrng,
  am3,
  lowprimes,
  lplim
} from './bigIntegerInternals.js';
import { Classic, Montgomery, NullExp, Barrett } from './BigIntegerReductions.js';
export { Classic, Montgomery, NullExp, Barrett } from './BigIntegerReductions.js';

function nbi(): BigInteger {
  return new BigInteger(null);
}
function nbv(i: number): BigInteger {
  const r = nbi();
  r.fromInt(i);
  return r;
}

export class BigInteger {
  data: number[] = [];
  t = 0;
  s = 0;
  declare DB: number;
  declare DM: number;
  declare DV: number;
  declare FV: number;
  declare F1: number;
  declare F2: number;
  declare am: (i: number, x: number, w: BigInteger, j: number, c: number, n: number) => number;

  static ZERO: BigInteger;
  static ONE: BigInteger;

  constructor(
    a?: number | string | number[] | null,
    b?: number | BigIntegerRandomSource | null,
    c?: BigIntegerRandomSource
  ) {
    if (a != null) {
      if (typeof a === 'number') {
        if (typeof b === 'number') this.fromNumber(a, b, c);
        else this.fromNumber(a, b!);
      } else if (b == null && typeof a !== 'string') this.fromString(a as number[], 256);
      else this.fromString(a as string, b as number);
    }
  }

  copyTo(r: BigInteger) {
    for (let i = this.t - 1; i >= 0; --i) r.data[i] = this.data[i];
    r.t = this.t;
    r.s = this.s;
  }

  fromInt(x: number) {
    this.t = 1;
    this.s = x < 0 ? -1 : 0;
    if (x > 0) this.data[0] = x;
    else if (x < -1) this.data[0] = x + this.DV;
    else this.t = 0;
  }

  fromString(s: string, b: number): void;
  fromString(s: number[], b: number): void;
  fromString(s: string | number[], b: number) {
    let k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 256)
      k = 8; // byte array
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else {
      this.fromRadix(s as string, b);
      return;
    }
    this.t = 0;
    this.s = 0;
    let i = s.length,
      mi = false,
      sh = 0;
    while (--i >= 0) {
      const x = k == 8 ? (s as number[])[i]! & 0xff : intAt(s as string, i);
      if (x < 0) {
        if ((s as string).charAt(i) == '-') mi = true;
        continue;
      }
      mi = false;
      if (sh == 0) this.data[this.t++] = x;
      else if (sh + k > this.DB) {
        this.data[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
        this.data[this.t++] = x >> (this.DB - sh);
      } else this.data[this.t - 1] |= x << sh;
      sh += k;
      if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && ((s as number[])[0]! & 0x80) != 0) {
      this.s = -1;
      if (sh > 0) this.data[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
  }

  clamp() {
    const c = this.s & this.DM;
    while (this.t > 0 && this.data[this.t - 1] == c) --this.t;
  }

  toString(b: number): string {
    if (this.s < 0) return '-' + this.negate().toString(b);
    let k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    let km = (1 << k) - 1,
      d,
      m = false,
      r = '',
      i = this.t;
    let p = this.DB - ((i * this.DB) % k);
    if (i-- > 0) {
      if (p < this.DB && (d = this.data[i] >> p) > 0) {
        m = true;
        r = int2char(d);
      }
      while (i >= 0) {
        if (p < k) {
          d = (this.data[i] & ((1 << p) - 1)) << (k - p);
          d |= this.data[--i] >> (p += this.DB - k);
        } else {
          d = (this.data[i] >> (p -= k)) & km;
          if (p <= 0) {
            p += this.DB;
            --i;
          }
        }
        if (d > 0) m = true;
        if (m) r += int2char(d);
      }
    }
    return m ? r : '0';
  }

  negate() {
    const r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
  }

  abs() {
    return this.s < 0 ? this.negate() : this;
  }

  compareTo(a: BigInteger) {
    let r = this.s - a.s;
    if (r != 0) return r;
    let i = this.t;
    r = i - a.t;
    if (r != 0) return this.s < 0 ? -r : r;
    while (--i >= 0) if ((r = this.data[i] - a.data[i]) != 0) return r;
    return 0;
  }

  bitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this.data[this.t - 1] ^ (this.s & this.DM));
  }

  dlShiftTo(n: number, r: BigInteger) {
    let i;
    for (i = this.t - 1; i >= 0; --i) r.data[i + n] = this.data[i];
    for (i = n - 1; i >= 0; --i) r.data[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
  }

  drShiftTo(n: number, r: BigInteger) {
    for (let i = n; i < this.t; ++i) r.data[i - n] = this.data[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
  }

  lShiftTo(n: number, r: BigInteger) {
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << cbs) - 1;
    let ds = Math.floor(n / this.DB),
      c = (this.s << bs) & this.DM,
      i;
    for (i = this.t - 1; i >= 0; --i) {
      r.data[i + ds + 1] = (this.data[i] >> cbs) | c;
      c = (this.data[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r.data[i] = 0;
    r.data[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
  }

  rShiftTo(n: number, r: BigInteger) {
    r.s = this.s;
    const ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
      r.t = 0;
      return;
    }
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << bs) - 1;
    r.data[0] = this.data[ds] >> bs;
    for (let i = ds + 1; i < this.t; ++i) {
      r.data[i - ds - 1] |= (this.data[i] & bm) << cbs;
      r.data[i - ds] = this.data[i] >> bs;
    }
    if (bs > 0) r.data[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
  }

  subTo(a: BigInteger, r: BigInteger) {
    let i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
    while (i < m) {
      c += this.data[i] - a.data[i];
      r.data[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c -= a.s;
      while (i < this.t) {
        c += this.data[i];
        r.data[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c -= a.data[i];
        r.data[i++] = c & this.DM;
        c >>= this.DB;
      }
      c -= a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c < -1) r.data[i++] = this.DV + c;
    else if (c > 0) r.data[i++] = c;
    r.t = i;
    r.clamp();
  }

  // HAC 14.12
  // "this" should be the larger one if appropriate.
  multiplyTo(a: BigInteger, r: BigInteger) {
    const x = this.abs(),
      y = a.abs();
    let i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r.data[i] = 0;
    for (i = 0; i < y.t; ++i) r.data[i + x.t] = x.am(0, y.data[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
  }

  // HAC 14.16
  squareTo(r: BigInteger) {
    const x = this.abs();
    let i = (r.t = 2 * x.t);
    while (--i >= 0) r.data[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
      const c = x.am(i, x.data[i], r, 2 * i, 0, 1);
      if ((r.data[i + x.t] += x.am(i + 1, 2 * x.data[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
        r.data[i + x.t] -= x.DV;
        r.data[i + x.t + 1] = 1;
      }
    }
    if (r.t > 0) r.data[r.t - 1] += x.am(i, x.data[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
  }

  // HAC 14.20
  // r != q, this != m.  q or r may be null.
  divRemTo(m: BigInteger, q: BigInteger | null, r: BigInteger | null) {
    const pm = m.abs();
    if (pm.t <= 0) return;
    const pt = this.abs();
    if (pt.t < pm.t) {
      if (q != null) q.fromInt(0);
      if (r != null) this.copyTo(r);
      return;
    }
    if (r == null) r = nbi();
    const y = nbi(),
      ts = this.s,
      ms = m.s;
    const nsh = this.DB - nbits(pm.data[pm.t - 1]); // normalize modulus
    if (nsh > 0) {
      pm.lShiftTo(nsh, y);
      pt.lShiftTo(nsh, r);
    } else {
      pm.copyTo(y);
      pt.copyTo(r);
    }
    const ys = y.t;
    const y0 = y.data[ys - 1];
    if (y0 == 0) return;
    const yt = y0 * (1 << this.F1) + (ys > 1 ? y.data[ys - 2] >> this.F2 : 0);
    const d1 = this.FV / yt,
      d2 = (1 << this.F1) / yt,
      e = 1 << this.F2;
    let i = r.t,
      j = i - ys,
      t = q == null ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
      r.data[r.t++] = 1;
      r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y); // "negative" y so we can replace sub with am later
    while (y.t < ys) y.data[y.t++] = 0;
    while (--j >= 0) {
      // Estimate quotient digit
      let qd = r.data[--i] == y0 ? this.DM : Math.floor(r.data[i] * d1 + (r.data[i - 1] + e) * d2);
      if ((r.data[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
        // Try it out
        y.dlShiftTo(j, t);
        r.subTo(t, r);
        while (r.data[i] < --qd) r.subTo(t, r);
      }
    }
    if (q != null) {
      r.drShiftTo(ys, q);
      if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
  }

  mod(a: BigInteger) {
    const r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
  }

  // justification:
  //         xy == 1 (mod m)
  //         xy =  1+km
  //   xy(2-xy) = (1+km)(1-km)
  // x[y(2-xy)] = 1-k^2m^2
  // x[y(2-xy)] == 1 (mod m^2)
  // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
  // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
  // JS multiply "overflows" differently from C/C++, so care is needed here.
  invDigit() {
    if (this.t < 1) return 0;
    const x = this.data[0];
    if ((x & 1) == 0) return 0;
    let y = x & 3; // y == 1/x mod 2^2
    y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    y = (y * (2 - ((x * y) % this.DV))) % this.DV; // y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return y > 0 ? this.DV - y : -y;
  }

  isEven() {
    return (this.t > 0 ? this.data[0] & 1 : this.s) == 0;
  }

  // HAC 14.79
  exp(e: number, z: BigIntegerReduction) {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    let r = nbi(),
      r2 = nbi(),
      g = z.convert(this),
      i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
      z.sqrTo(r, r2);
      if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
      else {
        const t = r;
        r = r2;
        r2 = t;
      }
    }
    return z.revert(r);
  }

  modPowInt(e: number, m: BigInteger) {
    let z;
    if (e < 256 || m.isEven()) z = new Classic(m);
    else z = new Montgomery(m);
    return this.exp(e, z);
  }

  clone() {
    const r = nbi();
    this.copyTo(r);
    return r;
  }

  intValue() {
    if (this.s < 0) {
      if (this.t == 1) return this.data[0] - this.DV;
      else if (this.t == 0) return -1;
    } else if (this.t == 1) return this.data[0];
    else if (this.t == 0) return 0;
    // assumes 16 < DB < 32
    return ((this.data[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this.data[0];
  }

  byteValue() {
    return this.t == 0 ? this.s : (this.data[0] << 24) >> 24;
  }

  shortValue() {
    return this.t == 0 ? this.s : (this.data[0] << 16) >> 16;
  }

  chunkSize(r: number) {
    return Math.floor((Math.LN2 * this.DB) / Math.log(r));
  }

  signum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this.data[0] <= 0)) return 0;
    else return 1;
  }

  toRadix(b: number) {
    if (b == null) b = 10;
    if (this.signum() == 0 || b < 2 || b > 36) return '0';
    const cs = this.chunkSize(b);
    const a = Math.pow(b, cs);
    let d = nbv(a),
      y = nbi(),
      z = nbi(),
      r = '';
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
      r = (a + z.intValue()).toString(b).substr(1) + r;
      y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
  }

  fromRadix(s: string, b: number) {
    this.fromInt(0);
    if (b == null) b = 10;
    const cs = this.chunkSize(b);
    let d = Math.pow(b, cs),
      mi = false,
      j = 0,
      w = 0;
    for (let i = 0; i < s.length; ++i) {
      const x = intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) == '-' && this.signum() == 0) mi = true;
        continue;
      }
      w = b * w + x;
      if (++j >= cs) {
        this.dMultiply(d);
        this.dAddOffset(w, 0);
        j = 0;
        w = 0;
      }
    }
    if (j > 0) {
      this.dMultiply(Math.pow(b, j));
      this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
  }

  fromNumber(a: number, b: BigIntegerRandomSource): void;
  fromNumber(a: number, b: number, c?: BigIntegerRandomSource): void;
  fromNumber(a: number, b?: number | BigIntegerRandomSource, c?: BigIntegerRandomSource) {
    if (typeof b === 'number') {
      // new BigInteger(int,int,RNG)
      if (a < 2) this.fromInt(1);
      else {
        this.fromNumber(a, c!);
        if (!this.testBit(a - 1))
          // force MSB set
          this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
        if (this.isEven()) this.dAddOffset(1, 0); // force odd
        while (!this.isProbablePrime(b)) {
          this.dAddOffset(2, 0);
          if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
        }
      }
    } else {
      // new BigInteger(int,RNG)
      const rng = b as BigIntegerRandomSource;
      const x: number[] = [],
        t = a & 7;
      x.length = (a >> 3) + 1;
      rng.nextBytes(x);
      if (t > 0) x[0] &= (1 << t) - 1;
      else x[0] = 0;
      this.fromString(x, 256);
    }
  }

  toByteArray(): number[] {
    let i = this.t,
      r = [];
    r[0] = this.s;
    let p = this.DB - ((i * this.DB) % 8),
      d,
      k = 0;
    if (i-- > 0) {
      if (p < this.DB && (d = this.data[i] >> p) != (this.s & this.DM) >> p) r[k++] = d | (this.s << (this.DB - p));
      while (i >= 0) {
        if (p < 8) {
          d = (this.data[i] & ((1 << p) - 1)) << (8 - p);
          d |= this.data[--i] >> (p += this.DB - 8);
        } else {
          d = (this.data[i] >> (p -= 8)) & 0xff;
          if (p <= 0) {
            p += this.DB;
            --i;
          }
        }
        if ((d & 0x80) != 0) d |= -256;
        if (k == 0 && (this.s & 0x80) != (d & 0x80)) ++k;
        if (k > 0 || d != this.s) r[k++] = d;
      }
    }
    return r;
  }

  equals(a: BigInteger) {
    return this.compareTo(a) == 0;
  }
  min(a: BigInteger) {
    return this.compareTo(a) < 0 ? this : a;
  }
  max(a: BigInteger) {
    return this.compareTo(a) > 0 ? this : a;
  }

  bitwiseTo(a: BigInteger, op: BitwiseWordOp, r: BigInteger) {
    let i,
      f,
      m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r.data[i] = op(this.data[i], a.data[i]);
    if (a.t < this.t) {
      f = a.s & this.DM;
      for (i = m; i < this.t; ++i) r.data[i] = op(this.data[i], f);
      r.t = this.t;
    } else {
      f = this.s & this.DM;
      for (i = m; i < a.t; ++i) r.data[i] = op(f, a.data[i]);
      r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
  }

  and(a: BigInteger) {
    const r = nbi();
    this.bitwiseTo(a, op_and, r);
    return r;
  }

  or(a: BigInteger) {
    const r = nbi();
    this.bitwiseTo(a, op_or, r);
    return r;
  }

  xor(a: BigInteger) {
    const r = nbi();
    this.bitwiseTo(a, op_xor, r);
    return r;
  }

  andNot(a: BigInteger) {
    const r = nbi();
    this.bitwiseTo(a, op_andnot, r);
    return r;
  }

  not() {
    const r = nbi();
    for (let i = 0; i < this.t; ++i) r.data[i] = this.DM & ~this.data[i];
    r.t = this.t;
    r.s = ~this.s;
    return r;
  }

  shiftLeft(n: number) {
    const r = nbi();
    if (n < 0) this.rShiftTo(-n, r);
    else this.lShiftTo(n, r);
    return r;
  }

  shiftRight(n: number) {
    const r = nbi();
    if (n < 0) this.lShiftTo(-n, r);
    else this.rShiftTo(n, r);
    return r;
  }

  getLowestSetBit() {
    for (let i = 0; i < this.t; ++i) if (this.data[i] != 0) return i * this.DB + lbit(this.data[i]);
    if (this.s < 0) return this.t * this.DB;
    return -1;
  }

  bitCount() {
    let r = 0,
      x = this.s & this.DM;
    for (let i = 0; i < this.t; ++i) r += cbit(this.data[i] ^ x);
    return r;
  }

  testBit(n: number) {
    const j = Math.floor(n / this.DB);
    if (j >= this.t) return this.s != 0;
    return (this.data[j] & (1 << (n % this.DB))) != 0;
  }

  changeBit(n: number, op: BitwiseWordOp) {
    const r = BigInteger.ONE.shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
  }

  setBit(n: number) {
    return this.changeBit(n, op_or);
  }

  clearBit(n: number) {
    return this.changeBit(n, op_andnot);
  }

  flipBit(n: number) {
    return this.changeBit(n, op_xor);
  }

  addTo(a: BigInteger, r: BigInteger) {
    let i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
    while (i < m) {
      c += this.data[i] + a.data[i];
      r.data[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c += a.s;
      while (i < this.t) {
        c += this.data[i];
        r.data[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c += a.data[i];
        r.data[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c > 0) r.data[i++] = c;
    else if (c < -1) r.data[i++] = this.DV + c;
    r.t = i;
    r.clamp();
  }

  add(a: BigInteger) {
    const r = nbi();
    this.addTo(a, r);
    return r;
  }

  subtract(a: BigInteger) {
    const r = nbi();
    this.subTo(a, r);
    return r;
  }

  multiply(a: BigInteger) {
    const r = nbi();
    this.multiplyTo(a, r);
    return r;
  }

  square() {
    const r = nbi();
    this.squareTo(r);
    return r;
  }

  divide(a: BigInteger) {
    const r = nbi();
    this.divRemTo(a, r, null);
    return r;
  }

  remainder(a: BigInteger) {
    const r = nbi();
    this.divRemTo(a, null, r);
    return r;
  }

  divideAndRemainder(a: BigInteger): BigInteger[] {
    const q = nbi(),
      r = nbi();
    this.divRemTo(a, q, r);
    return [q, r];
  }

  dMultiply(n: number) {
    this.data[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  }

  dAddOffset(n: number, w: number) {
    if (n == 0) return;
    while (this.t <= w) this.data[this.t++] = 0;
    this.data[w] += n;
    while (this.data[w] >= this.DV) {
      this.data[w] -= this.DV;
      if (++w >= this.t) this.data[this.t++] = 0;
      ++this.data[w];
    }
  }

  pow(e: number) {
    return this.exp(e, new NullExp());
  }

  // "this" should be the larger one if appropriate.
  multiplyLowerTo(a: BigInteger, n: number, r: BigInteger) {
    let i = Math.min(this.t + a.t, n);
    r.s = 0; // assumes a,this >= 0
    r.t = i;
    while (i > 0) r.data[--i] = 0;
    let j;
    for (j = r.t - this.t; i < j; ++i) r.data[i + this.t] = this.am(0, a.data[i], r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a.data[i], r, i, 0, n - i);
    r.clamp();
  }

  // "this" should be the larger one if appropriate.
  multiplyUpperTo(a: BigInteger, n: number, r: BigInteger) {
    --n;
    let i = (r.t = this.t + a.t - n);
    r.s = 0; // assumes a,this >= 0
    while (--i >= 0) r.data[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i)
      r.data[this.t + i - n] = this.am(n - i, a.data[i], r, 0, 0, this.t + i - n);
    r.clamp();
    r.drShiftTo(1, r);
  }

  modPow(e: BigInteger, m: BigInteger) {
    let i = e.bitLength(),
      k,
      r = nbv(1),
      z;
    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;
    if (i < 8) z = new Classic(m);
    else if (m.isEven()) z = new Barrett(m);
    else z = new Montgomery(m);

    let g = [],
      n = 3,
      k1 = k - 1,
      km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
      const g2 = nbi();
      z.sqrTo(g[1], g2);
      while (n <= km) {
        g[n] = nbi();
        z.mulTo(g2, g[n - 2], g[n]);
        n += 2;
      }
    }

    let j = e.t - 1,
      w,
      is1 = true,
      r2 = nbi(),
      t;
    i = nbits(e.data[j]) - 1;
    while (j >= 0) {
      if (i >= k1) w = (e.data[j] >> (i - k1)) & km;
      else {
        w = (e.data[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
        if (j > 0) w |= e.data[j - 1] >> (this.DB + i - k1);
      }

      n = k;
      while ((w & 1) == 0) {
        w >>= 1;
        --n;
      }
      if ((i -= n) < 0) {
        i += this.DB;
        --j;
      }
      if (is1) {
        // ret == 1, don't bother squaring or multiplying it
        g[w].copyTo(r);
        is1 = false;
      } else {
        while (n > 1) {
          z.sqrTo(r, r2);
          z.sqrTo(r2, r);
          n -= 2;
        }
        if (n > 0) z.sqrTo(r, r2);
        else {
          t = r;
          r = r2;
          r2 = t;
        }
        z.mulTo(r2, g[w], r);
      }

      while (j >= 0 && (e.data[j] & (1 << i)) == 0) {
        z.sqrTo(r, r2);
        t = r;
        r = r2;
        r2 = t;
        if (--i < 0) {
          i = this.DB - 1;
          --j;
        }
      }
    }
    return z.revert(r);
  }

  gcd(a: BigInteger) {
    let x = this.s < 0 ? this.negate() : this.clone();
    let y = a.s < 0 ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
      const t = x;
      x = y;
      y = t;
    }
    let i = x.getLowestSetBit(),
      g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
      x.rShiftTo(g, x);
      y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
      if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
      if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
      if (x.compareTo(y) >= 0) {
        x.subTo(y, x);
        x.rShiftTo(1, x);
      } else {
        y.subTo(x, y);
        y.rShiftTo(1, y);
      }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
  }

  modInt(n: number) {
    if (n <= 0) return 0;
    let d = this.DV % n,
      r = this.s < 0 ? n - 1 : 0;
    if (this.t > 0)
      if (d == 0) r = this.data[0] % n;
      else for (let i = this.t - 1; i >= 0; --i) r = (d * r + this.data[i]) % n;
    return r;
  }

  modInverse(m: BigInteger) {
    if (this.signum() == 0) {
      // inverse module m is found.
      return BigInteger.ZERO;
    }
    const ac = m.isEven();
    if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
    const u = m.clone(),
      v = this.clone();
    const a = nbv(1),
      b = nbv(0),
      c = nbv(0),
      d = nbv(1);
    while (u.signum() != 0) {
      while (u.isEven()) {
        u.rShiftTo(1, u);
        if (ac) {
          if (!a.isEven() || !b.isEven()) {
            a.addTo(this, a);
            b.subTo(m, b);
          }
          a.rShiftTo(1, a);
        } else if (!b.isEven()) b.subTo(m, b);
        b.rShiftTo(1, b);
      }
      while (v.isEven()) {
        v.rShiftTo(1, v);
        if (ac) {
          if (!c.isEven() || !d.isEven()) {
            c.addTo(this, c);
            d.subTo(m, d);
          }
          c.rShiftTo(1, c);
        } else if (!d.isEven()) d.subTo(m, d);
        d.rShiftTo(1, d);
      }
      if (u.compareTo(v) >= 0) {
        u.subTo(v, u);
        if (ac) a.subTo(c, a);
        b.subTo(d, b);
      } else {
        v.subTo(u, v);
        if (ac) c.subTo(a, c);
        d.subTo(b, d);
      }
    }
    if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d);
    else return d;
    if (d.signum() < 0) return d.add(m);
    else return d;
  }

  isProbablePrime(t: number) {
    let i,
      x = this.abs();
    if (x.t == 1 && x.data[0] <= lowprimes[lowprimes.length - 1]) {
      for (i = 0; i < lowprimes.length; ++i) if (x.data[0] == lowprimes[i]) return true;
      return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < lowprimes.length) {
      let m = lowprimes[i],
        j = i + 1;
      while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
      m = x.modInt(m);
      while (i < j) if (m % lowprimes[i++] == 0) return false;
    }
    return x.millerRabin(t);
  }

  // HAC 4.24, Miller-Rabin
  millerRabin(t: number) {
    const n1 = this.subtract(BigInteger.ONE);
    const k = n1.getLowestSetBit();
    if (k <= 0) return false;
    const r = n1.shiftRight(k);
    const prng = bnGetPrng();
    let a;
    for (let i = 0; i < t; ++i) {
      do {
        a = new BigInteger(this.bitLength(), prng);
      } while (a.compareTo(BigInteger.ONE) <= 0 || a.compareTo(n1) >= 0);
      let y = a.modPow(r, this);
      if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
        let j = 1;
        while (j++ < k && y.compareTo(n1) != 0) {
          y = y.modPowInt(2, this);
          if (y.compareTo(BigInteger.ONE) == 0) return false;
        }
        if (y.compareTo(n1) != 0) return false;
      }
    }
    return true;
  }
}

Object.assign(BigInteger.prototype, {
  DB: dbits,
  DM: (1 << dbits) - 1,
  DV: 1 << dbits,
  FV: Math.pow(2, BI_FP),
  F1: BI_FP - dbits,
  F2: 2 * dbits - BI_FP,
  am: am3
});

BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

import {BigInteger} from './BigInteger.js';

function nbi(): BigInteger { return new BigInteger(null); }

export class Classic {
  m: BigInteger;
  constructor(m: BigInteger) { this.m = m; }
  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
  }
  revert(x: BigInteger): BigInteger { return x; }
  reduce(x: BigInteger): void { x.divRemTo(this.m, null, x); }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void { x.multiplyTo(y, r); this.reduce(r); }
  sqrTo(x: BigInteger, r: BigInteger): void { x.squareTo(r); this.reduce(r); }
}

export class Montgomery {
  m: BigInteger;
  mp: number;
  mpl: number;
  mph: number;
  um: number;
  mt2: number;
  constructor(m: BigInteger) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
  }
  convert(x: BigInteger): BigInteger {
    const r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
  }
  revert(x: BigInteger): BigInteger {
    const r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
  reduce(x: BigInteger): void {
    while (x.t <= this.mt2)
      x.data[x.t++] = 0;
    for (let i = 0; i < this.m.t; ++i) {
      let j = x.data[i]! & 0x7fff;
      const u0 = (j * this.mpl + (((j * this.mph + (x.data[i]! >> 15) * this.mpl) & this.um) << 15)) & x.DM;
      j = i + this.m.t;
      x.data[j]! += this.m.am(0, u0, x, i, 0, this.m.t);
      while (x.data[j]! >= x.DV) { x.data[j]! -= x.DV; x.data[++j]!++; }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }
  sqrTo(x: BigInteger, r: BigInteger): void { x.squareTo(r); this.reduce(r); }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void { x.multiplyTo(y, r); this.reduce(r); }
}

export class NullExp {
  convert(x: BigInteger): BigInteger { return x; }
  revert(x: BigInteger): BigInteger { return x; }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void { x.multiplyTo(y, r); }
  sqrTo(x: BigInteger, r: BigInteger): void { x.squareTo(r); }
}

export class Barrett {
  r2: BigInteger;
  q3: BigInteger;
  mu: BigInteger;
  m: BigInteger;
  constructor(m: BigInteger) {
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
  }
  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
    else if (x.compareTo(this.m) < 0) return x;
    else { const r = nbi(); x.copyTo(r); this.reduce(r); return r; }
  }
  revert(x: BigInteger): BigInteger { return x; }
  reduce(x: BigInteger): void {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) { x.t = this.m.t + 1; x.clamp(); }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }
  sqrTo(x: BigInteger, r: BigInteger): void { x.squareTo(r); this.reduce(r); }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void { x.multiplyTo(y, r); this.reduce(r); }
}

import type { BigIntegerReduction } from './BigIntegerTypes.js';
import { BigInteger } from './BigInteger.js';

function nbi(): BigInteger {
  return new BigInteger(null);
}

export class Classic implements BigIntegerReduction {
  modulus: BigInteger;
  constructor(modulus: BigInteger) {
    this.modulus = modulus;
  }
  convert(value: BigInteger): BigInteger {
    if (value.s < 0 || value.compareTo(this.modulus) >= 0) return value.mod(this.modulus);
    else return value;
  }
  revert(value: BigInteger): BigInteger {
    return value;
  }
  reduce(value: BigInteger): void {
    value.divRemTo(this.modulus, null, value);
  }
  mulTo(multiplicand: BigInteger, multiplier: BigInteger, result: BigInteger): void {
    multiplicand.multiplyTo(multiplier, result);
    this.reduce(result);
  }
  sqrTo(value: BigInteger, result: BigInteger): void {
    value.squareTo(result);
    this.reduce(result);
  }
}

export class Montgomery implements BigIntegerReduction {
  modulus: BigInteger;
  montInvDigit: number;
  montInvLow: number;
  montInvHigh: number;
  umMask: number;
  maxLimbCount: number;
  constructor(modulus: BigInteger) {
    this.modulus = modulus;
    this.montInvDigit = modulus.invDigit();
    this.montInvLow = this.montInvDigit & 0x7fff;
    this.montInvHigh = this.montInvDigit >> 15;
    this.umMask = (1 << (modulus.digitBits - 15)) - 1;
    this.maxLimbCount = 2 * modulus.t;
  }
  convert(value: BigInteger): BigInteger {
    const result = nbi();
    value.abs().dlShiftTo(this.modulus.t, result);
    result.divRemTo(this.modulus, null, result);
    if (value.s < 0 && result.compareTo(BigInteger.ZERO) > 0) this.modulus.subTo(result, result);
    return result;
  }
  revert(value: BigInteger): BigInteger {
    const result = nbi();
    value.copyTo(result);
    this.reduce(result);
    return result;
  }
  reduce(value: BigInteger): void {
    while (value.t <= this.maxLimbCount) value.data[value.t++] = 0;
    for (let limbIndex = 0; limbIndex < this.modulus.t; ++limbIndex) {
      let carryWord = value.data[limbIndex] & 0x7fff;
      const montgomeryFactor =
        (carryWord * this.montInvLow +
          (((carryWord * this.montInvHigh + (value.data[limbIndex] >> 15) * this.montInvLow) & this.umMask) << 15)) &
        value.digitMask;
      carryWord = limbIndex + this.modulus.t;
      value.data[carryWord] += this.modulus.multiplyAdd(0, montgomeryFactor, value, limbIndex, 0, this.modulus.t);
      while (value.data[carryWord] >= value.digitMax) {
        value.data[carryWord] -= value.digitMax;
        value.data[++carryWord]++;
      }
    }
    value.clamp();
    value.drShiftTo(this.modulus.t, value);
    if (value.compareTo(this.modulus) >= 0) value.subTo(this.modulus, value);
  }
  sqrTo(value: BigInteger, result: BigInteger): void {
    value.squareTo(result);
    this.reduce(result);
  }
  mulTo(multiplicand: BigInteger, multiplier: BigInteger, result: BigInteger): void {
    multiplicand.multiplyTo(multiplier, result);
    this.reduce(result);
  }
}

export class NullExp implements BigIntegerReduction {
  convert(value: BigInteger): BigInteger {
    return value;
  }
  revert(value: BigInteger): BigInteger {
    return value;
  }
  mulTo(multiplicand: BigInteger, multiplier: BigInteger, result: BigInteger): void {
    multiplicand.multiplyTo(multiplier, result);
  }
  sqrTo(value: BigInteger, result: BigInteger): void {
    value.squareTo(result);
  }
}

export class Barrett implements BigIntegerReduction {
  rSquared: BigInteger;
  quotientScratch: BigInteger;
  muFactor: BigInteger;
  modulus: BigInteger;
  constructor(modulus: BigInteger) {
    this.rSquared = nbi();
    this.quotientScratch = nbi();
    BigInteger.ONE.dlShiftTo(2 * modulus.t, this.rSquared);
    this.muFactor = this.rSquared.divide(modulus);
    this.modulus = modulus;
  }
  convert(value: BigInteger): BigInteger {
    if (value.s < 0 || value.t > 2 * this.modulus.t) return value.mod(this.modulus);
    else if (value.compareTo(this.modulus) < 0) return value;
    else {
      const result = nbi();
      value.copyTo(result);
      this.reduce(result);
      return result;
    }
  }
  revert(value: BigInteger): BigInteger {
    return value;
  }
  reduce(value: BigInteger): void {
    value.drShiftTo(this.modulus.t - 1, this.rSquared);
    if (value.t > this.modulus.t + 1) {
      value.t = this.modulus.t + 1;
      value.clamp();
    }
    this.muFactor.multiplyUpperTo(this.rSquared, this.modulus.t + 1, this.quotientScratch);
    this.modulus.multiplyLowerTo(this.quotientScratch, this.modulus.t + 1, this.rSquared);
    while (value.compareTo(this.rSquared) < 0) value.dAddOffset(1, this.modulus.t + 1);
    value.subTo(this.rSquared, value);
    while (value.compareTo(this.modulus) >= 0) value.subTo(this.modulus, value);
  }
  sqrTo(value: BigInteger, result: BigInteger): void {
    value.squareTo(result);
    this.reduce(result);
  }
  mulTo(multiplicand: BigInteger, multiplier: BigInteger, result: BigInteger): void {
    multiplicand.multiplyTo(multiplier, result);
    this.reduce(result);
  }
}

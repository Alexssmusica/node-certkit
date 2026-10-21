/* Migrated from lib/jsbn.js */
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.
// Short names follow HAC / jsBN convention (e.g. `t` limb count, `s` sign, `r`/`q`/`a`/`x`/`y` operands).

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
  opAnd,
  opOr,
  opXor,
  opAndNot,
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
function nbv(index: number): BigInteger {
  const result = nbi();
  result.fromInt(index);
  return result;
}

export class BigInteger {
  data: number[] = [];
  /* eslint-disable id-length -- jsBN limb count and sign (instance-shape snapshot) */
  t = 0;
  s = 0;
  /* eslint-enable id-length */
  declare digitBits: number;
  declare digitMask: number;
  declare digitMax: number;
  declare floatScale: number;
  declare floatHighBits: number;
  declare floatLowBits: number;
  declare multiplyAdd: (
    index: number,
    value: number,
    word: BigInteger,
    innerIndex: number,
    carry: number,
    limbCount: number
  ) => number;

  static ZERO: BigInteger;
  static ONE: BigInteger;

  constructor(
    input?: number | string | number[] | null,
    radixOrRandom?: number | BigIntegerRandomSource | null,
    randomSource?: BigIntegerRandomSource
  ) {
    if (input != null) {
      if (typeof input === 'number') {
        if (typeof radixOrRandom === 'number') this.fromNumber(input, radixOrRandom, randomSource);
        else this.fromNumber(input, radixOrRandom!);
      } else if (radixOrRandom == null && typeof input !== 'string') this.fromString(input, 256);
      else this.fromString(input as string, radixOrRandom as number);
    }
  }

  copyTo(result: BigInteger) {
    for (let index = this.t - 1; index >= 0; --index) result.data[index] = this.data[index];
    result.t = this.t;
    result.s = this.s;
  }

  fromInt(value: number) {
    this.t = 1;
    this.s = value < 0 ? -1 : 0;
    if (value > 0) this.data[0] = value;
    else if (value < -1) this.data[0] = value + this.digitMax;
    else this.t = 0;
  }

  fromString(input: string, addend: number): void;
  fromString(input: number[], addend: number): void;
  fromString(input: string | number[], addend: number) {
    let limbIndex;
    if (addend == 16) limbIndex = 4;
    else if (addend == 8) limbIndex = 3;
    else if (addend == 256)
      limbIndex = 8; // byte array
    else if (addend == 2) limbIndex = 1;
    else if (addend == 32) limbIndex = 5;
    else if (addend == 4) limbIndex = 2;
    else {
      this.fromRadix(input as string, addend);
      return;
    }
    this.t = 0;
    this.s = 0;
    let index = input.length;
    let isNegativeInput = false;
    let shiftBits = 0;
    while (--index >= 0) {
      const value = limbIndex == 8 ? (input as number[])[index] & 0xff : intAt(input as string, index);
      if (value < 0) {
        if ((input as string).charAt(index) == '-') isNegativeInput = true;
        continue;
      }
      isNegativeInput = false;
      if (shiftBits == 0) this.data[this.t++] = value;
      else if (shiftBits + limbIndex > this.digitBits) {
        this.data[this.t - 1] |= (value & ((1 << (this.digitBits - shiftBits)) - 1)) << shiftBits;
        this.data[this.t++] = value >> (this.digitBits - shiftBits);
      } else this.data[this.t - 1] |= value << shiftBits;
      shiftBits += limbIndex;
      if (shiftBits >= this.digitBits) shiftBits -= this.digitBits;
    }
    if (limbIndex == 8 && ((input as number[])[0] & 0x80) != 0) {
      this.s = -1;
      if (shiftBits > 0) this.data[this.t - 1] |= ((1 << (this.digitBits - shiftBits)) - 1) << shiftBits;
    }
    this.clamp();
    if (isNegativeInput) BigInteger.ZERO.subTo(this, this);
  }

  clamp() {
    const carry = this.s & this.digitMask;
    while (this.t > 0 && this.data[this.t - 1] == carry) --this.t;
  }

  toString(radix: number): string {
    if (this.s < 0) return '-' + this.negate().toString(radix);
    let limbIndex;
    if (radix == 16) limbIndex = 4;
    else if (radix == 8) limbIndex = 3;
    else if (radix == 2) limbIndex = 1;
    else if (radix == 32) limbIndex = 5;
    else if (radix == 4) limbIndex = 2;
    else return this.toRadix(radix);
    const radixMask = (1 << limbIndex) - 1;
    let digit;
    let modulus = false;
    let result = '';
    let index = this.t;
    let prime = this.digitBits - ((index * this.digitBits) % limbIndex);
    if (index-- > 0) {
      if (prime < this.digitBits && (digit = this.data[index] >> prime) > 0) {
        modulus = true;
        result = int2char(digit);
      }
      while (index >= 0) {
        if (prime < limbIndex) {
          digit = (this.data[index] & ((1 << prime) - 1)) << (limbIndex - prime);
          digit |= this.data[--index] >> (prime += this.digitBits - limbIndex);
        } else {
          digit = (this.data[index] >> (prime -= limbIndex)) & radixMask;
          if (prime <= 0) {
            prime += this.digitBits;
            --index;
          }
        }
        if (digit > 0) modulus = true;
        if (modulus) result += int2char(digit);
      }
    }
    return modulus ? result : '0';
  }

  negate() {
    const result = nbi();
    BigInteger.ZERO.subTo(this, result);
    return result;
  }

  abs() {
    return this.s < 0 ? this.negate() : this;
  }

  compareTo(augend: BigInteger) {
    let result = this.s - augend.s;
    if (result != 0) return result;
    let index = this.t;
    result = index - augend.t;
    if (result != 0) return this.s < 0 ? -result : result;
    while (--index >= 0) if ((result = this.data[index] - augend.data[index]) != 0) return result;
    return 0;
  }

  bitLength() {
    if (this.t <= 0) return 0;
    return this.digitBits * (this.t - 1) + nbits(this.data[this.t - 1] ^ (this.s & this.digitMask));
  }

  dlShiftTo(limbCount: number, result: BigInteger) {
    let index;
    for (index = this.t - 1; index >= 0; --index) result.data[index + limbCount] = this.data[index];
    for (index = limbCount - 1; index >= 0; --index) result.data[index] = 0;
    result.t = this.t + limbCount;
    result.s = this.s;
  }

  drShiftTo(limbCount: number, result: BigInteger) {
    for (let index = limbCount; index < this.t; ++index) result.data[index - limbCount] = this.data[index];
    result.t = Math.max(this.t - limbCount, 0);
    result.s = this.s;
  }

  lShiftTo(limbCount: number, result: BigInteger) {
    const bitShift = limbCount % this.digitBits;
    const cbs = this.digitBits - bitShift;
    const bitMask = (1 << cbs) - 1;
    const divShift = Math.floor(limbCount / this.digitBits);
    let carry = (this.s << bitShift) & this.digitMask;
    let index;
    for (index = this.t - 1; index >= 0; --index) {
      result.data[index + divShift + 1] = (this.data[index] >> cbs) | carry;
      carry = (this.data[index] & bitMask) << bitShift;
    }
    for (index = divShift - 1; index >= 0; --index) result.data[index] = 0;
    result.data[divShift] = carry;
    result.t = this.t + divShift + 1;
    result.s = this.s;
    result.clamp();
  }

  rShiftTo(limbCount: number, result: BigInteger) {
    result.s = this.s;
    const divShift = Math.floor(limbCount / this.digitBits);
    if (divShift >= this.t) {
      result.t = 0;
      return;
    }
    const bitShift = limbCount % this.digitBits;
    const cbs = this.digitBits - bitShift;
    const bitMask = (1 << bitShift) - 1;
    result.data[0] = this.data[divShift] >> bitShift;
    for (let index = divShift + 1; index < this.t; ++index) {
      result.data[index - divShift - 1] |= (this.data[index] & bitMask) << cbs;
      result.data[index - divShift] = this.data[index] >> bitShift;
    }
    if (bitShift > 0) result.data[this.t - divShift - 1] |= (this.s & bitMask) << cbs;
    result.t = this.t - divShift;
    result.clamp();
  }

  subTo(augend: BigInteger, result: BigInteger) {
    let index = 0;
    let carry = 0;
    const modulus = Math.min(augend.t, this.t);
    while (index < modulus) {
      carry += this.data[index] - augend.data[index];
      result.data[index++] = carry & this.digitMask;
      carry >>= this.digitBits;
    }
    if (augend.t < this.t) {
      carry -= augend.s;
      while (index < this.t) {
        carry += this.data[index];
        result.data[index++] = carry & this.digitMask;
        carry >>= this.digitBits;
      }
      carry += this.s;
    } else {
      carry += this.s;
      while (index < augend.t) {
        carry -= augend.data[index];
        result.data[index++] = carry & this.digitMask;
        carry >>= this.digitBits;
      }
      carry -= augend.s;
    }
    result.s = carry < 0 ? -1 : 0;
    if (carry < -1) result.data[index++] = this.digitMax + carry;
    else if (carry > 0) result.data[index++] = carry;
    result.t = index;
    result.clamp();
  }

  // HAC 14.12
  // "this" should be the larger one if appropriate.
  multiplyTo(augend: BigInteger, result: BigInteger) {
    const value = this.abs(),
      multiplier = augend.abs();
    let index = value.t;
    result.t = index + multiplier.t;
    while (--index >= 0) result.data[index] = 0;
    for (index = 0; index < multiplier.t; ++index)
      result.data[index + value.t] = value.multiplyAdd(0, multiplier.data[index], result, index, 0, value.t);
    result.s = 0;
    result.clamp();
    if (this.s != augend.s) BigInteger.ZERO.subTo(result, result);
  }

  // HAC 14.16
  squareTo(result: BigInteger) {
    const value = this.abs();
    let index = (result.t = 2 * value.t);
    while (--index >= 0) result.data[index] = 0;
    for (index = 0; index < value.t - 1; ++index) {
      const carry = value.multiplyAdd(index, value.data[index], result, 2 * index, 0, 1);
      if (
        (result.data[index + value.t] += value.multiplyAdd(
          index + 1,
          2 * value.data[index],
          result,
          2 * index + 1,
          carry,
          value.t - index - 1
        )) >= value.digitMax
      ) {
        result.data[index + value.t] -= value.digitMax;
        result.data[index + value.t + 1] = 1;
      }
    }
    if (result.t > 0) result.data[result.t - 1] += value.multiplyAdd(index, value.data[index], result, 2 * index, 0, 1);
    result.s = 0;
    result.clamp();
  }

  // HAC 14.20
  // r != q, this != m.  q or r may be null.
  divRemTo(modulus: BigInteger, quotient: BigInteger | null, result: BigInteger | null) {
    const partialModulus = modulus.abs();
    if (partialModulus.t <= 0) return;
    const partialTotal = this.abs();
    if (partialTotal.t < partialModulus.t) {
      if (quotient != null) quotient.fromInt(0);
      if (result != null) this.copyTo(result);
      return;
    }
    if (result == null) result = nbi();
    const multiplier = nbi(),
      tempSign = this.s,
      modSign = modulus.s;
    const nsh = this.digitBits - nbits(partialModulus.data[partialModulus.t - 1]); // normalize modulus
    if (nsh > 0) {
      partialModulus.lShiftTo(nsh, multiplier);
      partialTotal.lShiftTo(nsh, result);
    } else {
      partialModulus.copyTo(multiplier);
      partialTotal.copyTo(result);
    }
    const ySign = multiplier.t;
    const yLowLimb = multiplier.data[ySign - 1];
    if (yLowLimb == 0) return;
    const yTopLimb =
      yLowLimb * (1 << this.floatHighBits) + (ySign > 1 ? multiplier.data[ySign - 2] >> this.floatLowBits : 0);
    const divHigh = this.floatScale / yTopLimb,
      divLow = (1 << this.floatHighBits) / yTopLimb,
      exponent = 1 << this.floatLowBits;
    let index = result.t;
    let innerIndex = index - ySign;
    const quotientScratch = quotient == null ? nbi() : quotient;
    multiplier.dlShiftTo(innerIndex, quotientScratch);
    if (result.compareTo(quotientScratch) >= 0) {
      result.data[result.t++] = 1;
      result.subTo(quotientScratch, result);
    }
    BigInteger.ONE.dlShiftTo(ySign, quotientScratch);
    quotientScratch.subTo(multiplier, multiplier); // "negative" y so we can replace sub with am later
    while (multiplier.t < ySign) multiplier.data[multiplier.t++] = 0;
    while (--innerIndex >= 0) {
      // Estimate quotient digit
      let quotientDigit =
        result.data[--index] == yLowLimb
          ? this.digitMask
          : Math.floor(result.data[index] * divHigh + (result.data[index - 1] + exponent) * divLow);
      if (
        (result.data[index] += multiplier.multiplyAdd(0, quotientDigit, result, innerIndex, 0, ySign)) < quotientDigit
      ) {
        // Try it out
        multiplier.dlShiftTo(innerIndex, quotientScratch);
        result.subTo(quotientScratch, result);
        while (result.data[index] < --quotientDigit) result.subTo(quotientScratch, result);
      }
    }
    if (quotient != null) {
      result.drShiftTo(ySign, quotient);
      if (tempSign != modSign) BigInteger.ZERO.subTo(quotient, quotient);
    }
    result.t = ySign;
    result.clamp();
    if (nsh > 0) result.rShiftTo(nsh, result); // Denormalize remainder
    if (tempSign < 0) BigInteger.ZERO.subTo(result, result);
  }

  mod(augend: BigInteger) {
    const result = nbi();
    this.abs().divRemTo(augend, null, result);
    if (this.s < 0 && result.compareTo(BigInteger.ZERO) > 0) augend.subTo(result, result);
    return result;
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
    const value = this.data[0];
    if ((value & 1) == 0) return 0;
    let multiplier = value & 3; // y == 1/x mod 2^2
    multiplier = (multiplier * (2 - (value & 0xf) * multiplier)) & 0xf; // y == 1/x mod 2^4
    multiplier = (multiplier * (2 - (value & 0xff) * multiplier)) & 0xff; // y == 1/x mod 2^8
    multiplier = (multiplier * (2 - (((value & 0xffff) * multiplier) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    multiplier = (multiplier * (2 - ((value * multiplier) % this.digitMax))) % this.digitMax; // y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return multiplier > 0 ? this.digitMax - multiplier : -multiplier;
  }

  isEven() {
    return (this.t > 0 ? this.data[0] & 1 : this.s) == 0;
  }

  // HAC 14.79
  exp(exponent: number, accumulator: BigIntegerReduction) {
    if (exponent > 0xffffffff || exponent < 1) return BigInteger.ONE;
    let result = nbi();
    let resultAlt = nbi();
    const generator = accumulator.convert(this);
    let index = nbits(exponent) - 1;
    generator.copyTo(result);
    while (--index >= 0) {
      accumulator.sqrTo(result, resultAlt);
      if ((exponent & (1 << index)) > 0) accumulator.mulTo(resultAlt, generator, result);
      else {
        const swapTemp = result;
        result = resultAlt;
        resultAlt = swapTemp;
      }
    }
    return accumulator.revert(result);
  }

  modPowInt(exponent: number, modulus: BigInteger) {
    let accumulator;
    if (exponent < 256 || modulus.isEven()) accumulator = new Classic(modulus);
    else accumulator = new Montgomery(modulus);
    return this.exp(exponent, accumulator);
  }

  clone() {
    const result = nbi();
    this.copyTo(result);
    return result;
  }

  intValue() {
    if (this.s < 0) {
      if (this.t == 1) return this.data[0] - this.digitMax;
      else if (this.t == 0) return -1;
    } else if (this.t == 1) return this.data[0];
    else if (this.t == 0) return 0;
    // assumes 16 < DB < 32
    return ((this.data[1] & ((1 << (32 - this.digitBits)) - 1)) << this.digitBits) | this.data[0];
  }

  byteValue() {
    return this.t == 0 ? this.s : (this.data[0] << 24) >> 24;
  }

  shortValue() {
    return this.t == 0 ? this.s : (this.data[0] << 16) >> 16;
  }

  chunkSize(result: number) {
    return Math.floor((Math.LN2 * this.digitBits) / Math.log(result));
  }

  signum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this.data[0] <= 0)) return 0;
    else return 1;
  }

  toRadix(addend: number) {
    if (addend == null) addend = 10;
    if (this.signum() == 0 || addend < 2 || addend > 36) return '0';
    const carryShift = this.chunkSize(addend);
    const augend = Math.pow(addend, carryShift);
    const digit = nbv(augend);
    const multiplier = nbi();
    const accumulator = nbi();
    let result = '';
    this.divRemTo(digit, multiplier, accumulator);
    while (multiplier.signum() > 0) {
      result = (augend + accumulator.intValue()).toString(addend).substr(1) + result;
      multiplier.divRemTo(digit, multiplier, accumulator);
    }
    return accumulator.intValue().toString(addend) + result;
  }

  fromRadix(input: string, addend: number) {
    this.fromInt(0);
    if (addend == null) addend = 10;
    const carryShift = this.chunkSize(addend);
    const digit = Math.pow(addend, carryShift);
    let isNegativeInput = false;
    let innerIndex = 0;
    let word = 0;
    for (let index = 0; index < input.length; ++index) {
      const value = intAt(input, index);
      if (value < 0) {
        if (input.charAt(index) == '-' && this.signum() == 0) isNegativeInput = true;
        continue;
      }
      word = addend * word + value;
      if (++innerIndex >= carryShift) {
        this.dMultiply(digit);
        this.dAddOffset(word, 0);
        innerIndex = 0;
        word = 0;
      }
    }
    if (innerIndex > 0) {
      this.dMultiply(Math.pow(addend, innerIndex));
      this.dAddOffset(word, 0);
    }
    if (isNegativeInput) BigInteger.ZERO.subTo(this, this);
  }

  fromNumber(augend: number, addend: BigIntegerRandomSource): void;
  fromNumber(augend: number, addend: number, carry?: BigIntegerRandomSource): void;
  fromNumber(augend: number, addend?: number | BigIntegerRandomSource, carry?: BigIntegerRandomSource) {
    if (typeof addend === 'number') {
      // new BigInteger(int,int,RNG)
      if (augend < 2) this.fromInt(1);
      else {
        this.fromNumber(augend, carry!);
        if (!this.testBit(augend - 1))
          // force MSB set
          this.bitwiseTo(BigInteger.ONE.shiftLeft(augend - 1), opOr, this);
        if (this.isEven()) this.dAddOffset(1, 0); // force odd
        while (!this.isProbablePrime(addend)) {
          this.dAddOffset(2, 0);
          if (this.bitLength() > augend) this.subTo(BigInteger.ONE.shiftLeft(augend - 1), this);
        }
      }
    } else {
      // new BigInteger(int,RNG)
      const rng = addend as BigIntegerRandomSource;
      const value: number[] = [];
      const extraBits = augend & 7;
      value.length = (augend >> 3) + 1;
      rng.nextBytes(value);
      if (extraBits > 0) value[0] &= (1 << extraBits) - 1;
      else value[0] = 0;
      this.fromString(value, 256);
    }
  }

  toByteArray(): number[] {
    let index = this.t;
    const result: number[] = [];
    result[0] = this.s;
    let prime = this.digitBits - ((index * this.digitBits) % 8),
      digit,
      limbIndex = 0;
    if (index-- > 0) {
      if (prime < this.digitBits && (digit = this.data[index] >> prime) != (this.s & this.digitMask) >> prime)
        result[limbIndex++] = digit | (this.s << (this.digitBits - prime));
      while (index >= 0) {
        if (prime < 8) {
          digit = (this.data[index] & ((1 << prime) - 1)) << (8 - prime);
          digit |= this.data[--index] >> (prime += this.digitBits - 8);
        } else {
          digit = (this.data[index] >> (prime -= 8)) & 0xff;
          if (prime <= 0) {
            prime += this.digitBits;
            --index;
          }
        }
        if ((digit & 0x80) != 0) digit |= -256;
        if (limbIndex == 0 && (this.s & 0x80) != (digit & 0x80)) ++limbIndex;
        if (limbIndex > 0 || digit != this.s) result[limbIndex++] = digit;
      }
    }
    return result;
  }

  equals(augend: BigInteger) {
    return this.compareTo(augend) == 0;
  }
  min(augend: BigInteger) {
    return this.compareTo(augend) < 0 ? this : augend;
  }
  max(augend: BigInteger) {
    return this.compareTo(augend) > 0 ? this : augend;
  }

  bitwiseTo(augend: BigInteger, wordOp: BitwiseWordOp, result: BigInteger) {
    let index;
    let fillWord;
    const modulus = Math.min(augend.t, this.t);
    for (index = 0; index < modulus; ++index) result.data[index] = wordOp(this.data[index], augend.data[index]);
    if (augend.t < this.t) {
      fillWord = augend.s & this.digitMask;
      for (index = modulus; index < this.t; ++index) result.data[index] = wordOp(this.data[index], fillWord);
      result.t = this.t;
    } else {
      fillWord = this.s & this.digitMask;
      for (index = modulus; index < augend.t; ++index) result.data[index] = wordOp(fillWord, augend.data[index]);
      result.t = augend.t;
    }
    result.s = wordOp(this.s, augend.s);
    result.clamp();
  }

  and(augend: BigInteger) {
    const result = nbi();
    this.bitwiseTo(augend, opAnd, result);
    return result;
  }

  // eslint-disable-next-line id-length -- BigInteger#or matches node-forge instance shape
  or(augend: BigInteger) {
    const result = nbi();
    this.bitwiseTo(augend, opOr, result);
    return result;
  }

  xor(augend: BigInteger) {
    const result = nbi();
    this.bitwiseTo(augend, opXor, result);
    return result;
  }

  andNot(augend: BigInteger) {
    const result = nbi();
    this.bitwiseTo(augend, opAndNot, result);
    return result;
  }

  not() {
    const result = nbi();
    for (let index = 0; index < this.t; ++index) result.data[index] = this.digitMask & ~this.data[index];
    result.t = this.t;
    result.s = ~this.s;
    return result;
  }

  shiftLeft(limbCount: number) {
    const result = nbi();
    if (limbCount < 0) this.rShiftTo(-limbCount, result);
    else this.lShiftTo(limbCount, result);
    return result;
  }

  shiftRight(limbCount: number) {
    const result = nbi();
    if (limbCount < 0) this.lShiftTo(-limbCount, result);
    else this.rShiftTo(limbCount, result);
    return result;
  }

  getLowestSetBit() {
    for (let index = 0; index < this.t; ++index)
      if (this.data[index] != 0) return index * this.digitBits + lbit(this.data[index]);
    if (this.s < 0) return this.t * this.digitBits;
    return -1;
  }

  bitCount() {
    let result = 0;
    const value = this.s & this.digitMask;
    for (let index = 0; index < this.t; ++index) result += cbit(this.data[index] ^ value);
    return result;
  }

  testBit(limbCount: number) {
    const innerIndex = Math.floor(limbCount / this.digitBits);
    if (innerIndex >= this.t) return this.s != 0;
    return (this.data[innerIndex] & (1 << (limbCount % this.digitBits))) != 0;
  }

  changeBit(limbCount: number, wordOp: BitwiseWordOp) {
    const result = BigInteger.ONE.shiftLeft(limbCount);
    this.bitwiseTo(result, wordOp, result);
    return result;
  }

  setBit(limbCount: number) {
    return this.changeBit(limbCount, opOr);
  }

  clearBit(limbCount: number) {
    return this.changeBit(limbCount, opAndNot);
  }

  flipBit(limbCount: number) {
    return this.changeBit(limbCount, opXor);
  }

  addTo(augend: BigInteger, result: BigInteger) {
    let index = 0;
    let carry = 0;
    const modulus = Math.min(augend.t, this.t);
    while (index < modulus) {
      carry += this.data[index] + augend.data[index];
      result.data[index++] = carry & this.digitMask;
      carry >>= this.digitBits;
    }
    if (augend.t < this.t) {
      carry += augend.s;
      while (index < this.t) {
        carry += this.data[index];
        result.data[index++] = carry & this.digitMask;
        carry >>= this.digitBits;
      }
      carry += this.s;
    } else {
      carry += this.s;
      while (index < augend.t) {
        carry += augend.data[index];
        result.data[index++] = carry & this.digitMask;
        carry >>= this.digitBits;
      }
      carry += augend.s;
    }
    result.s = carry < 0 ? -1 : 0;
    if (carry > 0) result.data[index++] = carry;
    else if (carry < -1) result.data[index++] = this.digitMax + carry;
    result.t = index;
    result.clamp();
  }

  add(augend: BigInteger) {
    const result = nbi();
    this.addTo(augend, result);
    return result;
  }

  subtract(augend: BigInteger) {
    const result = nbi();
    this.subTo(augend, result);
    return result;
  }

  multiply(augend: BigInteger) {
    const result = nbi();
    this.multiplyTo(augend, result);
    return result;
  }

  square() {
    const result = nbi();
    this.squareTo(result);
    return result;
  }

  divide(augend: BigInteger) {
    const result = nbi();
    this.divRemTo(augend, result, null);
    return result;
  }

  remainder(augend: BigInteger) {
    const result = nbi();
    this.divRemTo(augend, null, result);
    return result;
  }

  divideAndRemainder(augend: BigInteger): BigInteger[] {
    const quotient = nbi(),
      result = nbi();
    this.divRemTo(augend, quotient, result);
    return [quotient, result];
  }

  dMultiply(limbCount: number) {
    this.data[this.t] = this.multiplyAdd(0, limbCount - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  }

  dAddOffset(limbCount: number, word: number) {
    if (limbCount == 0) return;
    while (this.t <= word) this.data[this.t++] = 0;
    this.data[word] += limbCount;
    while (this.data[word] >= this.digitMax) {
      this.data[word] -= this.digitMax;
      if (++word >= this.t) this.data[this.t++] = 0;
      ++this.data[word];
    }
  }

  pow(exponent: number) {
    return this.exp(exponent, new NullExp());
  }

  // "this" should be the larger one if appropriate.
  multiplyLowerTo(augend: BigInteger, limbCount: number, result: BigInteger) {
    let index = Math.min(this.t + augend.t, limbCount);
    result.s = 0; // assumes a,this >= 0
    result.t = index;
    while (index > 0) result.data[--index] = 0;
    let innerIndex;
    for (innerIndex = result.t - this.t; index < innerIndex; ++index)
      result.data[index + this.t] = this.multiplyAdd(0, augend.data[index], result, index, 0, this.t);
    for (innerIndex = Math.min(augend.t, limbCount); index < innerIndex; ++index)
      this.multiplyAdd(0, augend.data[index], result, index, 0, limbCount - index);
    result.clamp();
  }

  // "this" should be the larger one if appropriate.
  multiplyUpperTo(augend: BigInteger, limbCount: number, result: BigInteger) {
    --limbCount;
    let index = (result.t = this.t + augend.t - limbCount);
    result.s = 0; // assumes a,this >= 0
    while (--index >= 0) result.data[index] = 0;
    for (index = Math.max(limbCount - this.t, 0); index < augend.t; ++index)
      result.data[this.t + index - limbCount] = this.multiplyAdd(
        limbCount - index,
        augend.data[index],
        result,
        0,
        0,
        this.t + index - limbCount
      );
    result.clamp();
    result.drShiftTo(1, result);
  }

  modPow(exponent: BigInteger, modulus: BigInteger) {
    const exponentBitLength = exponent.bitLength();
    let limbIndex;
    let result = nbv(1);
    let accumulator;
    if (exponentBitLength <= 0) return result;
    else if (exponentBitLength < 18) limbIndex = 1;
    else if (exponentBitLength < 48) limbIndex = 3;
    else if (exponentBitLength < 144) limbIndex = 4;
    else if (exponentBitLength < 768) limbIndex = 5;
    else limbIndex = 6;
    if (exponentBitLength < 8) accumulator = new Classic(modulus);
    else if (modulus.isEven()) accumulator = new Barrett(modulus);
    else accumulator = new Montgomery(modulus);

    const generator: BigInteger[] = [];
    let limbCount = 3;
    const windowSize = limbIndex - 1;
    const radixMask = (1 << limbIndex) - 1;
    generator[1] = accumulator.convert(this);
    if (limbIndex > 1) {
      const generatorSq = nbi();
      accumulator.sqrTo(generator[1], generatorSq);
      while (limbCount <= radixMask) {
        generator[limbCount] = nbi();
        accumulator.mulTo(generatorSq, generator[limbCount - 2], generator[limbCount]);
        limbCount += 2;
      }
    }

    let innerIndex = exponent.t - 1;
    let word;
    let is1 = true;
    let resultAlt = nbi();
    let swapTemp: BigInteger;
    let index = nbits(exponent.data[innerIndex]) - 1;
    while (innerIndex >= 0) {
      if (index >= windowSize) word = (exponent.data[innerIndex] >> (index - windowSize)) & radixMask;
      else {
        word = (exponent.data[innerIndex] & ((1 << (index + 1)) - 1)) << (windowSize - index);
        if (innerIndex > 0) word |= exponent.data[innerIndex - 1] >> (this.digitBits + index - windowSize);
      }

      limbCount = limbIndex;
      while ((word & 1) == 0) {
        word >>= 1;
        --limbCount;
      }
      if ((index -= limbCount) < 0) {
        index += this.digitBits;
        --innerIndex;
      }
      if (is1) {
        // ret == 1, don't bother squaring or multiplying it
        generator[word].copyTo(result);
        is1 = false;
      } else {
        while (limbCount > 1) {
          accumulator.sqrTo(result, resultAlt);
          accumulator.sqrTo(resultAlt, result);
          limbCount -= 2;
        }
        if (limbCount > 0) accumulator.sqrTo(result, resultAlt);
        else {
          swapTemp = result;
          result = resultAlt;
          resultAlt = swapTemp;
        }
        accumulator.mulTo(resultAlt, generator[word], result);
      }

      while (innerIndex >= 0 && (exponent.data[innerIndex] & (1 << index)) == 0) {
        accumulator.sqrTo(result, resultAlt);
        swapTemp = result;
        result = resultAlt;
        resultAlt = swapTemp;
        if (--index < 0) {
          index = this.digitBits - 1;
          --innerIndex;
        }
      }
    }
    return accumulator.revert(result);
  }

  gcd(augend: BigInteger) {
    let value = this.s < 0 ? this.negate() : this.clone();
    let multiplier = augend.s < 0 ? augend.negate() : augend.clone();
    if (value.compareTo(multiplier) < 0) {
      const swapTemp = value;
      value = multiplier;
      multiplier = swapTemp;
    }
    let index = value.getLowestSetBit(),
      generator = multiplier.getLowestSetBit();
    if (generator < 0) return value;
    if (index < generator) generator = index;
    if (generator > 0) {
      value.rShiftTo(generator, value);
      multiplier.rShiftTo(generator, multiplier);
    }
    while (value.signum() > 0) {
      if ((index = value.getLowestSetBit()) > 0) value.rShiftTo(index, value);
      if ((index = multiplier.getLowestSetBit()) > 0) multiplier.rShiftTo(index, multiplier);
      if (value.compareTo(multiplier) >= 0) {
        value.subTo(multiplier, value);
        value.rShiftTo(1, value);
      } else {
        multiplier.subTo(value, multiplier);
        multiplier.rShiftTo(1, multiplier);
      }
    }
    if (generator > 0) multiplier.lShiftTo(generator, multiplier);
    return multiplier;
  }

  modInt(limbCount: number) {
    if (limbCount <= 0) return 0;
    const digit = this.digitMax % limbCount;
    let result = this.s < 0 ? limbCount - 1 : 0;
    if (this.t > 0)
      if (digit == 0) result = this.data[0] % limbCount;
      else for (let index = this.t - 1; index >= 0; --index) result = (digit * result + this.data[index]) % limbCount;
    return result;
  }

  modInverse(modulus: BigInteger) {
    if (this.signum() == 0) {
      // inverse module m is found.
      return BigInteger.ZERO;
    }
    const accumulatorCarry = modulus.isEven();
    if ((this.isEven() && accumulatorCarry) || modulus.signum() == 0) return BigInteger.ZERO;
    const uTerm = modulus.clone(),
      vTerm = this.clone();
    const augend = nbv(1),
      addend = nbv(0),
      carry = nbv(0),
      digit = nbv(1);
    while (uTerm.signum() != 0) {
      while (uTerm.isEven()) {
        uTerm.rShiftTo(1, uTerm);
        if (accumulatorCarry) {
          if (!augend.isEven() || !addend.isEven()) {
            augend.addTo(this, augend);
            addend.subTo(modulus, addend);
          }
          augend.rShiftTo(1, augend);
        } else if (!addend.isEven()) addend.subTo(modulus, addend);
        addend.rShiftTo(1, addend);
      }
      while (vTerm.isEven()) {
        vTerm.rShiftTo(1, vTerm);
        if (accumulatorCarry) {
          if (!carry.isEven() || !digit.isEven()) {
            carry.addTo(this, carry);
            digit.subTo(modulus, digit);
          }
          carry.rShiftTo(1, carry);
        } else if (!digit.isEven()) digit.subTo(modulus, digit);
        digit.rShiftTo(1, digit);
      }
      if (uTerm.compareTo(vTerm) >= 0) {
        uTerm.subTo(vTerm, uTerm);
        if (accumulatorCarry) augend.subTo(carry, augend);
        addend.subTo(digit, addend);
      } else {
        vTerm.subTo(uTerm, vTerm);
        if (accumulatorCarry) carry.subTo(augend, carry);
        digit.subTo(addend, digit);
      }
    }
    if (vTerm.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
    if (digit.compareTo(modulus) >= 0) return digit.subtract(modulus);
    if (digit.signum() < 0) digit.addTo(modulus, digit);
    else return digit;
    if (digit.signum() < 0) return digit.add(modulus);
    else return digit;
  }

  isProbablePrime(trialCount: number) {
    let index;
    const value = this.abs();
    if (value.t == 1 && value.data[0] <= lowprimes[lowprimes.length - 1]) {
      for (index = 0; index < lowprimes.length; ++index) if (value.data[0] == lowprimes[index]) return true;
      return false;
    }
    if (value.isEven()) return false;
    index = 1;
    while (index < lowprimes.length) {
      let modulus = lowprimes[index],
        innerIndex = index + 1;
      while (innerIndex < lowprimes.length && modulus < lplim) modulus *= lowprimes[innerIndex++];
      modulus = value.modInt(modulus);
      while (index < innerIndex) if (modulus % lowprimes[index++] == 0) return false;
    }
    return value.millerRabin(trialCount);
  }

  // HAC 4.24, Miller-Rabin
  millerRabin(trialCount: number) {
    const limbCountOne = this.subtract(BigInteger.ONE);
    const limbIndex = limbCountOne.getLowestSetBit();
    if (limbIndex <= 0) return false;
    const result = limbCountOne.shiftRight(limbIndex);
    const prng = bnGetPrng();
    let augend;
    for (let index = 0; index < trialCount; ++index) {
      do {
        augend = new BigInteger(this.bitLength(), prng);
      } while (augend.compareTo(BigInteger.ONE) <= 0 || augend.compareTo(limbCountOne) >= 0);
      let multiplier = augend.modPow(result, this);
      if (multiplier.compareTo(BigInteger.ONE) != 0 && multiplier.compareTo(limbCountOne) != 0) {
        let innerIndex = 1;
        while (innerIndex++ < limbIndex && multiplier.compareTo(limbCountOne) != 0) {
          multiplier = multiplier.modPowInt(2, this);
          if (multiplier.compareTo(BigInteger.ONE) == 0) return false;
        }
        if (multiplier.compareTo(limbCountOne) != 0) return false;
      }
    }
    return true;
  }
}

Object.assign(BigInteger.prototype, {
  digitBits: dbits,
  digitMask: (1 << dbits) - 1,
  digitMax: 1 << dbits,
  floatScale: Math.pow(2, BI_FP),
  floatHighBits: BI_FP - dbits,
  floatLowBits: 2 * dbits - BI_FP,
  multiplyAdd: am3
});

BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

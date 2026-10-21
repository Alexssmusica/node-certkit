import type { BigInteger } from './BigInteger.js';

export interface BigIntegerRandomSource {
  nextBytes(bytes: number[]): void;
}

export interface BigIntegerReduction {
  convert(value: BigInteger): BigInteger;
  revert(value: BigInteger): BigInteger;
  mulTo(multiplicand: BigInteger, multiplier: BigInteger, result: BigInteger): void;
  sqrTo(value: BigInteger, result: BigInteger): void;
}

export type BitwiseWordOp = (leftWord: number, rightWord: number) => number;

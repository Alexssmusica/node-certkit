import type { BigInteger } from './BigInteger.js';

export interface BigIntegerRandomSource {
  nextBytes(x: number[]): void;
}

export interface BigIntegerReduction {
  convert(x: BigInteger): BigInteger;
  revert(x: BigInteger): BigInteger;
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void;
  sqrTo(x: BigInteger, r: BigInteger): void;
}

export type BitwiseWordOp = (x: number, y: number) => number;

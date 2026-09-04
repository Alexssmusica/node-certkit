import { BigInteger } from '../math/BigInteger.js';
import type { BigIntegerRandomSource } from '../math/BigInteger.js';
import { EnvInfo } from '../../infrastructure/env/EnvInfo.js';

const GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];
const THIRTY = new BigInteger(null);
THIRTY.fromInt(30);
const op_or = (x: number, y: number) => x | y;

export type PrimeGenerateOptions = Record<string, unknown> & {
  algorithm?: string | { name: string; options?: Record<string, unknown> };
  prng?: { getBytesSync(count: number): string };
};

function getMillerRabinTests(bits: number): number {
  if (bits <= 100) return 27;
  if (bits <= 150) return 18;
  if (bits <= 200) return 15;
  if (bits <= 250) return 12;
  if (bits <= 300) return 9;
  if (bits <= 350) return 8;
  if (bits <= 400) return 7;
  if (bits <= 500) return 6;
  if (bits <= 600) return 5;
  if (bits <= 800) return 4;
  if (bits <= 1250) return 3;
  return 2;
}

function generateRandom(bits: number, rng: BigIntegerRandomSource): BigInteger {
  const num = new BigInteger(bits, rng);
  const bits1 = bits - 1;
  if (!num.testBit(bits1)) {
    num.bitwiseTo(BigInteger.ONE.shiftLeft(bits1), op_or, num);
  }
  num.dAddOffset(31 - num.mod(THIRTY).byteValue(), 0);
  return num;
}

function primeincFindPrimeWithoutWorkers(
  bits: number,
  rng: BigIntegerRandomSource,
  options: Record<string, unknown>,
  callback: (err: Error | null, num?: BigInteger) => void
): void {
  const num = generateRandom(bits, rng);
  const deltaIdx = 0;

  let mrTests = getMillerRabinTests(num.bitLength());
  if ('millerRabinTests' in options) {
    mrTests = options.millerRabinTests as number;
  }

  let maxBlockTime = 10;
  if ('maxBlockTime' in options) {
    maxBlockTime = options.maxBlockTime as number;
  }

  primeinc(num, bits, rng, deltaIdx, mrTests, maxBlockTime, callback);
}

function primeinc(
  num: BigInteger,
  bits: number,
  rng: BigIntegerRandomSource,
  deltaIdx: number,
  mrTests: number,
  maxBlockTime: number,
  callback: (err: Error | null, num?: BigInteger) => void
): void {
  const start = +new Date();
  do {
    if (num.bitLength() > bits) {
      num = generateRandom(bits, rng);
    }
    if (num.isProbablePrime(mrTests)) {
      return callback(null, num);
    }
    num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
  } while (maxBlockTime < 0 || +new Date() - start < maxBlockTime);

  EnvInfo.setImmediate(() => {
    primeinc(num, bits, rng, deltaIdx, mrTests, maxBlockTime, callback);
  });
}

export class PrimeService {
  static generateProbablePrime(
    bits: number,
    options: PrimeGenerateOptions | ((err: Error | null, num?: BigInteger) => void),
    callback?: (err: Error | null, num?: BigInteger) => void
  ): void {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = options || {};

    let algorithm = options.algorithm || 'PRIMEINC';
    if (typeof algorithm === 'string') {
      algorithm = { name: algorithm };
    }
    const algorithmOptions = algorithm.options || {};

    const prng = options.prng;
    if (!prng) {
      callback!(new Error('PRNG required for prime generation'));
      return;
    }

    const rng: BigIntegerRandomSource = {
      nextBytes(x: number[]): void {
        const b = prng.getBytesSync(x.length);
        for (let i = 0; i < x.length; ++i) {
          x[i] = b.charCodeAt(i);
        }
      }
    };

    if (algorithm.name === 'PRIMEINC') {
      primeincFindPrimeWithoutWorkers(bits, rng, algorithmOptions, callback!);
      return;
    }

    callback!(new Error('Invalid prime generation algorithm: ' + algorithm.name));
  }

  static createCertkitNamespace(getRandomBytes: (count: number) => string): {
    generateProbablePrime: typeof PrimeService.generateProbablePrime;
  } {
    return {
      generateProbablePrime(bits, options, callback) {
        let opts: PrimeGenerateOptions;
        let cb: (err: Error | null, num?: BigInteger) => void;
        if (typeof options === 'function') {
          cb = options;
          opts = { prng: { getBytesSync: getRandomBytes } };
        } else {
          opts = { ...options, prng: options.prng || { getBytesSync: getRandomBytes } };
          cb = callback!;
        }
        PrimeService.generateProbablePrime(bits, opts, cb);
      }
    };
  }
}

export default PrimeService;

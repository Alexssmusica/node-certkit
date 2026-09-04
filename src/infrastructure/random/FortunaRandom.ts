import { Fortuna, type PrngContext, type PrngPlugin } from '../prng/Fortuna.js';
import { UtilNamespace } from '../../domain/util/UtilNamespace.js';

export type AesPrngBackend = {
  _expandKey: (key: unknown, decrypt: boolean) => unknown;
  _updateBlock: (w: unknown, seed: unknown, output: number[], decrypt: boolean) => void;
};

export type Sha256DigestFactory = {
  create: () => {
    messageLength: number;
    start: () => void;
    update: (bytes: string) => void;
    digest: () => { getBytes: () => string };
  };
};

const RANDOM_CONTEXT_METHODS = [
  'collect',
  'collectInt',
  'generate',
  'generateSync',
  'getBytes',
  'getBytesSync',
  'seedFile',
  'seedFileSync'
] as const;

const RANDOM_CONTEXT_PROPERTIES = [
  'plugin',
  'key',
  'seed',
  'time',
  'reseeds',
  'generated',
  'keyBytes',
  'pools',
  'pool'
] as const;

export type FortunaRandomNamespace = PrngContext & {
  getBytes: (count: number, callback?: (err: Error | null, bytes?: string) => void) => string | void;
  getBytesSync: (count: number) => string;
  createInstance: () => FortunaRandomNamespace;
};

export type FortunaRandomDependencies = {
  aes: AesPrngBackend;
  sha256: Sha256DigestFactory;
};

export class FortunaRandom {
  static createPlugin(deps: FortunaRandomDependencies): PrngPlugin {
    const prngAesOutput = new Array<number>(4);
    const prngAesBuffer = UtilNamespace.createBuffer();

    return {
      formatKey(key: string) {
        const tmp = UtilNamespace.createBuffer(key);
        const words = [tmp.getInt32(), tmp.getInt32(), tmp.getInt32(), tmp.getInt32()];
        return deps.aes._expandKey(words, false);
      },
      formatSeed(seed: string) {
        const tmp = UtilNamespace.createBuffer(seed);
        return [tmp.getInt32(), tmp.getInt32(), tmp.getInt32(), tmp.getInt32()];
      },
      cipher(key: unknown, seed: unknown) {
        deps.aes._updateBlock(key, seed, prngAesOutput, false);
        prngAesBuffer.putInt32(prngAesOutput[0]!);
        prngAesBuffer.putInt32(prngAesOutput[1]!);
        prngAesBuffer.putInt32(prngAesOutput[2]!);
        prngAesBuffer.putInt32(prngAesOutput[3]!);
        return prngAesBuffer.getBytes();
      },
      increment(seed: unknown) {
        const s = seed as number[];
        ++s[3]!;
        return seed;
      },
      md: deps.sha256
    };
  }

  static spawnPrng(deps: FortunaRandomDependencies): FortunaRandomNamespace {
    const ctx = Fortuna.create(FortunaRandom.createPlugin(deps)) as FortunaRandomNamespace;
    ctx.getBytes = function (count: number, callback?: (err: Error | null, bytes?: string) => void) {
      return ctx.generate(count, callback);
    };
    ctx.getBytesSync = function (count: number) {
      const result = ctx.generate(count);
      if (typeof result === 'string') {
        return result;
      }
      return ctx.generateSync(count);
    };
    return ctx;
  }

  static mergeInto(
    target: FortunaRandomNamespace | undefined,
    deps: FortunaRandomDependencies
  ): FortunaRandomNamespace {
    const ctx = FortunaRandom.spawnPrng(deps);

    if (!target || !target.getBytes) {
      const random = ctx;
      random.createInstance = function () {
        return FortunaRandom.spawnPrng(deps);
      };
      return random;
    }

    type MethodKey = (typeof RANDOM_CONTEXT_METHODS)[number];
    type PropertyKey = (typeof RANDOM_CONTEXT_PROPERTIES)[number];

    for (let i = 0; i < RANDOM_CONTEXT_METHODS.length; ++i) {
      const key = RANDOM_CONTEXT_METHODS[i] as MethodKey;
      (target as Record<string, unknown>)[key] = (ctx as Record<string, unknown>)[key];
    }
    for (let i = 0; i < RANDOM_CONTEXT_PROPERTIES.length; ++i) {
      const key = RANDOM_CONTEXT_PROPERTIES[i] as PropertyKey;
      (target as Record<string, unknown>)[key] = (ctx as Record<string, unknown>)[key];
    }

    target.createInstance = function () {
      return FortunaRandom.spawnPrng(deps);
    };

    return target;
  }

  static createCertkitNamespace(deps: FortunaRandomDependencies): FortunaRandomNamespace {
    return FortunaRandom.mergeInto(undefined, deps);
  }
}

export default FortunaRandom;

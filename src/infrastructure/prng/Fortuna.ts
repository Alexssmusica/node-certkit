import crypto from 'node:crypto';
import { ByteStringBuffer } from '../../domain/buffer/ByteStringBuffer.js';
import { EnvInfo } from '../env/EnvInfo.js';
import type { PrngContext, PrngPlugin } from './PrngTypes.js';

export class Fortuna {
  static create(plugin: PrngPlugin): PrngContext {
    const ctx: PrngContext = {
      plugin,
      key: null,
      seed: null,
      time: null,
      reseeds: 0,
      generated: 0,
      keyBytes: '',
      pools: [],
      pool: 0,
      generate: () => '',
      generateSync: () => '',
      seedFile: () => {},
      seedFileSync: () => '',
      collect: () => {},
      collectInt: () => {}
    };

    const md = plugin.md;
    const pools = new Array(32);
    for (let i = 0; i < 32; ++i) {
      pools[i] = md.create();
    }
    ctx.pools = pools;
    ctx.pool = 0;

    ctx.generate = function (count: number, callback?: (err: Error | null, bytes?: string) => void) {
      if (!callback) {
        return ctx.generateSync(count);
      }

      const cipher = ctx.plugin.cipher;
      const increment = ctx.plugin.increment;
      const formatKey = ctx.plugin.formatKey;
      const formatSeed = ctx.plugin.formatSeed;
      const b = new ByteStringBuffer();

      ctx.key = null;

      generate();
      return;

      function generate(err?: Error | null): void {
        if (err) {
          return callback!(err);
        }

        if (b.length() >= count) {
          return callback!(null, b.getBytes(count));
        }

        if (ctx.generated > 0xfffff) {
          ctx.key = null;
        }

        if (ctx.key === null) {
          return EnvInfo.nextTick(function () {
            _reseed(generate);
          });
        }

        const key = ctx.key;
        const seed = ctx.seed!;
        const bytes = cipher(key, seed);
        ctx.generated += bytes.length;
        b.putBytes(bytes);

        ctx.key = formatKey(cipher(key, increment(seed)));
        ctx.seed = formatSeed(cipher(ctx.key, ctx.seed!));

        EnvInfo.setImmediate(() => generate());
      }
    };

    ctx.generateSync = function (count: number): string {
      const cipher = ctx.plugin.cipher;
      const increment = ctx.plugin.increment;
      const formatKey = ctx.plugin.formatKey;
      const formatSeed = ctx.plugin.formatSeed;

      ctx.key = null;

      const b = new ByteStringBuffer();
      while (b.length() < count) {
        if (ctx.generated > 0xfffff) {
          ctx.key = null;
        }

        if (ctx.key === null) {
          _reseedSync();
        }

        const key = ctx.key!;
        const seed = ctx.seed!;
        const bytes = cipher(key, seed);
        ctx.generated += bytes.length;
        b.putBytes(bytes);

        ctx.key = formatKey(cipher(key, increment(seed)));
        ctx.seed = formatSeed(cipher(ctx.key, ctx.seed!));
      }

      return b.getBytes(count);
    };

    function _reseed(callback: (err?: Error | null) => void): void {
      if (ctx.pools[0]!.messageLength >= 32) {
        _seed();
        return callback();
      }
      const needed = (32 - ctx.pools[0]!.messageLength) << 5;
      ctx.seedFile(needed, function (err, bytes) {
        if (err) {
          return callback(err);
        }
        ctx.collect(bytes!);
        _seed();
        callback();
      });
    }

    function _reseedSync(): void {
      if (ctx.pools[0]!.messageLength >= 32) {
        return _seed();
      }
      const needed = (32 - ctx.pools[0]!.messageLength) << 5;
      ctx.collect(ctx.seedFileSync(needed));
      _seed();
    }

    function _seed(): void {
      ctx.reseeds = ctx.reseeds === 0xffffffff ? 0 : ctx.reseeds + 1;

      const mdInstance = ctx.plugin.md.create();
      mdInstance.update(ctx.keyBytes);

      let _2powK = 1;
      for (let k = 0; k < 32; ++k) {
        if (ctx.reseeds % _2powK === 0) {
          mdInstance.update(ctx.pools[k]!.digest().getBytes());
          ctx.pools[k]!.start();
        }
        _2powK = _2powK << 1;
      }

      ctx.keyBytes = mdInstance.digest().getBytes();

      mdInstance.start();
      mdInstance.update(ctx.keyBytes);
      const seedBytes = mdInstance.digest().getBytes();

      ctx.key = ctx.plugin.formatKey(ctx.keyBytes);
      ctx.seed = ctx.plugin.formatSeed(seedBytes);
      ctx.generated = 0;
    }

    function defaultSeedFile(needed: number): string {
      let getRandomValues: ((arr: Uint32Array) => Uint32Array) | null = null;
      const globalScope = EnvInfo.globalScope as typeof globalThis & {
        crypto?: { getRandomValues: (arr: Uint32Array) => Uint32Array };
        msCrypto?: { getRandomValues: (arr: Uint32Array) => Uint32Array };
      };
      const webCrypto = globalScope.crypto || globalScope.msCrypto;
      if (webCrypto && webCrypto.getRandomValues) {
        getRandomValues = function (arr: Uint32Array) {
          return webCrypto.getRandomValues(arr);
        };
      }

      const b = new ByteStringBuffer();
      if (getRandomValues) {
        while (b.length() < needed) {
          const count = Math.max(1, Math.min(needed - b.length(), 65536) / 4);
          const entropy = new Uint32Array(Math.floor(count));
          try {
            getRandomValues(entropy);
            for (let i = 0; i < entropy.length; ++i) {
              b.putInt32(entropy[i]!);
            }
          } catch (e) {
            const QuotaExceededErrorCtor = (
              globalThis as {
                QuotaExceededError?: new (...args: unknown[]) => Error;
              }
            ).QuotaExceededError;
            if (!(typeof QuotaExceededErrorCtor !== 'undefined' && e instanceof QuotaExceededErrorCtor)) {
              throw e;
            }
          }
        }
      }

      if (b.length() < needed) {
        throw new Error('Unable to collect sufficient entropy for PRNG seed.');
      }

      return b.getBytes(needed);
    }

    if (crypto) {
      ctx.seedFile = function (needed: number, callback: (err: Error | null, bytes?: string) => void) {
        crypto.randomBytes(needed, function (err, bytes) {
          if (err) {
            return callback(err);
          }
          callback(null, bytes.toString('binary'));
        });
      };
      ctx.seedFileSync = function (needed: number): string {
        return crypto.randomBytes(needed).toString('binary');
      };
    } else {
      ctx.seedFile = function (needed: number, callback: (err: Error | null, bytes?: string) => void) {
        try {
          callback(null, defaultSeedFile(needed));
        } catch (e) {
          callback(e as Error);
        }
      };
      ctx.seedFileSync = defaultSeedFile;
    }

    ctx.collect = function (bytes: string) {
      const count = bytes.length;
      for (let i = 0; i < count; ++i) {
        ctx.pools[ctx.pool]!.update(bytes.charAt(i));
        ctx.pool = ctx.pool === 31 ? 0 : ctx.pool + 1;
      }
    };

    ctx.collectInt = function (i: number, n: number) {
      let bytes = '';
      for (let x = 0; x < n; x += 8) {
        bytes += String.fromCharCode((i >> x) & 0xff);
      }
      ctx.collect(bytes);
    };

    return ctx;
  }

  static createCertkitNamespace(): { create: typeof Fortuna.create } {
    return {
      create: Fortuna.create.bind(Fortuna)
    };
  }
}

export default Fortuna;

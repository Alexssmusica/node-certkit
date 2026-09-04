import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const RANDOM = certkit.random;
const UTIL = certkit.util;
const fillString = UTIL.fillString as (c: string, n: number) => string;
describe('random', () => {
  it('should generate 10 random bytes', (ctx) => {
    const random = RANDOM.createInstance();
    random.getBytes(16);
    random.getBytes(24);
    random.getBytes(32);

    const b = random.getBytes(10)!;
    expect(b.length).toBe(10);
  });

  it('should use a synchronous seed file', (ctx) => {
    const random = RANDOM.createInstance();
    random.seedFileSync = function (needed) {
      return fillString('a', needed);
    };
    const b = random.getBytes(10)!;
    expect(UTIL.bytesToHex(b)).toBe('80a7901a239c3e606319');
  });

  it('should use an asynchronous seed file', async () => {
    const random = RANDOM.createInstance();
    random.seedFile = function (needed, callback) {
      callback(null, fillString('a', needed));
    };
    await new Promise<void>((resolve, reject) => {
      random.getBytes(10, (err, b) => {
        try {
          expect(err).toBe(null);
          expect(UTIL.bytesToHex(b!)).toBe('80a7901a239c3e606319');
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  it('should collect some random bytes', (ctx) => {
    const random = RANDOM.createInstance();
    random.seedFileSync = function (needed) {
      return fillString('a', needed);
    };
    random.collect('bbb');
    const b = random.getBytes(10)!;
    expect(UTIL.bytesToHex(b)).toBe('ff8d213516047c94ca46');
  });
});

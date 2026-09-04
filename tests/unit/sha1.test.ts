import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const SHA1 = certkit.sha1;
const UTIL = certkit.util;
const fillString = UTIL.fillString as (c: string, n: number) => string;
describe('sha1', () => {
  it('should have correct digest length', (ctx) => {
    const md = SHA1.create();
    expect(md.digestLength).toBe(20);
  });

  it('should digest the empty string', (ctx) => {
    const md = SHA1.create();
    expect(md.digest().toHex()).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  });

  it('should digest "abc"', (ctx) => {
    const md = SHA1.create();
    md.update('abc');
    expect(md.digest().toHex()).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
  });

  it('should digest "The quick brown fox jumps over the lazy dog"', (ctx) => {
    const md = SHA1.create();
    md.update('The quick brown fox jumps over the lazy dog');
    expect(md.digest().toHex()).toBe('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12');
  });

  it('should digest "c\'\u00e8"', (ctx) => {
    const md = SHA1.create();
    md.update("c'\u00e8", 'utf8');
    expect(md.digest().toHex()).toBe('98c9a3f804daa73b68a5660d032499a447350c0d');
  });

  it('should digest "THIS IS A MESSAGE"', (ctx) => {
    const md = SHA1.create();
    md.start();
    md.update('THIS IS ');
    md.update('A MESSAGE');
    // do twice to check continuing digest
    expect(md.digest().toHex()).toBe('5f24f4d6499fd2d44df6c6e94be8b14a796c071d');
    expect(md.digest().toHex()).toBe('5f24f4d6499fd2d44df6c6e94be8b14a796c071d');
  });

  it('should digest a long message', (ctx) => {
    // Note: might be too slow on old browsers
    const md = SHA1.create();
    md.update(fillString('a', 1000000));
    expect(md.digest().toHex()).toBe('34aa973cd4c4daa4f61eeb2bdbad27316534016f');
  });

  it('should digest multiple long messages', (ctx) => {
    // Note: might be too slow on old browsers
    // done multiple times to check hot loop optimizations
    for (let loop = 0; loop < 3; ++loop) {
      const md = SHA1.create();
      for (let i = 0; i < 10000; ++i) {
        md.update('abc');
      }
      expect(md.digest().toHex()).toBe('a838edb5dec47b84b4bfb0a528ea958a5d9d2350');
    }
  });
});

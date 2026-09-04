import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const JSBN = certkit.jsbn;
describe('jsbn', () => {
  describe('GHSA-5m6q-g25r-mvwx', () => {
    // regression tests for GHSA-5m6q-g25r-mvwx
    // test BigInteger.modInverse does not infinite loop with 0 inputs.
    const BigInteger = JSBN.BigInteger;
    it('should test BigInteger(0).modInverse(0) returns 0', (ctx) => {
      const n = BigInteger.ZERO;
      const mod = BigInteger.ZERO;
      const inv = n.modInverse(mod);
      expect(inv.equals(BigInteger.ZERO)).toBeTruthy();
    });
    it('should test BigInteger(0).modInverse(3) returns 0', (ctx) => {
      const n = BigInteger.ZERO;
      const mod = new BigInteger('3', 10);
      const inv = n.modInverse(mod);
      expect(inv.equals(BigInteger.ZERO)).toBeTruthy();
    });
    it('should test BigInteger(3).modInverse(0) returns 0', (ctx) => {
      const n = new BigInteger('3', 10);
      const mod = BigInteger.ZERO;
      const inv = n.modInverse(mod);
      expect(inv.equals(BigInteger.ZERO)).toBeTruthy();
    });
    it('should test BigInteger(3).modInverse(3) returns 0', (ctx) => {
      const n = new BigInteger('3', 10);
      const mod = new BigInteger('3', 10);
      const inv = n.modInverse(mod);
      expect(inv.equals(BigInteger.ZERO)).toBeTruthy();
    });
    it('should test BigInteger(7).modInverse(20) returns 3', (ctx) => {
      const n = new BigInteger('7', 10);
      const mod = new BigInteger('20', 10);
      const inv = n.modInverse(mod);
      expect(inv.equals(new BigInteger('3', 10))).toBeTruthy();
    });
  });
});

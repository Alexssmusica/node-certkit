import { describe, it, expect } from 'vitest';
import { PemCodec } from '../../src/domain/pki/PemCodec.js';

describe('PEM decode ReDoS hardening', function () {
  it('should reject PEM input above the maximum allowed size', () => {
    const oversized = '-----BEGIN CERTIFICATE-----\n' + 'A'.repeat(PemCodec.MAX_DECODE_INPUT_LENGTH) + '\n-----END';
    expect(() => PemCodec.decode(oversized)).toThrow(/exceeds maximum allowed size/);
  });

  it('should decode valid PEM blocks without quadratic regex backtracking', () => {
    const pem =
      '-----BEGIN CERTIFICATE-----\n' +
      'MIIB\n' +
      '-----END CERTIFICATE-----\n' +
      '-----BEGIN RSA PRIVATE KEY-----\n' +
      'MIIB\n' +
      '-----END RSA PRIVATE KEY-----\n';

    const messages = PemCodec.decode(pem);
    expect(messages).toHaveLength(2);
    expect(messages[0]!.type).toBe('CERTIFICATE');
    expect(messages[1]!.type).toBe('RSA PRIVATE KEY');
  });

  it('should fail fast on malformed PEM without END marker', () => {
    const malformed = '-----BEGIN CERTIFICATE-----\n' + ' '.repeat(32000);
    const start = Date.now();
    expect(() => PemCodec.decode(malformed)).toThrow(/Invalid PEM formatted message/);
    expect(Date.now() - start).toBeLessThan(500);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import certkit from '../../src/presentation/index.js';
/*
 * Regression Test for GHSA-554w-wpv2-vw27
 * Verifies that the parser enforces a maximum recursion depth
 * instead of crashing with a call stack overflow.
 */
const asn1 = certkit.asn1;
const util = certkit.util;

describe('GHSA-554w-wpv2-vw27 Security Patch', function () {
  function createNestedDer(depth: number) {
    var obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00');
    for (var i = 0; i < depth; i++) {
      obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [obj]);
    }
    var oldMaxDepth = asn1.maxDepth;
    asn1.maxDepth = depth + 2;
    var der = asn1.toDer(obj).getBytes();
    asn1.maxDepth = oldMaxDepth;
    return der;
  }

  beforeEach(function () {
    // check max depth is the default
    expect(asn1.maxDepth).toBe(256);
  });

  it('should throw a manageable error when default recursion depth is exceeded', (ctx) => {
    // create a payload just above the default limit (256)
    var DANGEROUS_DEPTH = 257;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    expect(function () {
      asn1.fromDer(buf, { strict: true });
    }).toThrow(/ASN.1 parsing error: Max depth exceeded./);
  });

  it('should throw a manageable error when optional recursion depth is exceeded', (ctx) => {
    // create a payload just above the optional defined limit (128)
    var DANGEROUS_DEPTH = 129;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    expect(function () {
      asn1.fromDer(buf, { strict: true, maxDepth: 128 });
    }).toThrow(/ASN.1 parsing error: Max depth exceeded./);
  });

  it('should still parse valid nested structures with new default limits', (ctx) => {
    var oldMaxDepth = asn1.maxDepth;
    asn1.maxDepth = 258;

    // create a payload just above the default limit (256)
    var DANGEROUS_DEPTH = 257;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // verify with new default depth
    asn1.fromDer(buf, { strict: true });

    asn1.maxDepth = oldMaxDepth;
  });

  it('should still parse valid nested structures within default limits', (ctx) => {
    // verify we didn't break default depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, { strict: true });
  });

  it('should still parse valid nested structures within optional limits', (ctx) => {
    // verify we didn't break optional depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, { strict: true, maxDepth: 128 });
  });

  function createNestedBitStringDer(depth: number) {
    function wrapBitString(inner: string) {
      const content = String.fromCharCode(0) + inner;
      const len = content.length;
      let lenBytes: string;
      if (len < 0x80) {
        lenBytes = String.fromCharCode(len);
      } else if (len < 0x100) {
        lenBytes = String.fromCharCode(0x81, len);
      } else if (len < 0x10000) {
        lenBytes = String.fromCharCode(0x82, len >> 8, len & 0xff);
      } else {
        lenBytes = String.fromCharCode(0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
      }
      return String.fromCharCode(0x03) + lenBytes + content;
    }

    let payload = String.fromCharCode(0x05, 0x00);
    for (let i = 0; i < depth; i++) {
      payload = wrapBitString(payload);
    }
    return payload;
  }

  it('should throw when encapsulated BIT STRING nesting exceeds maxDepth', (ctx) => {
    var DANGEROUS_DEPTH = 257;
    var der = createNestedBitStringDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    expect(function () {
      asn1.fromDer(buf, { strict: true, decodeBitStrings: true });
    }).toThrow(/ASN.1 parsing error: Max depth exceeded./);
  });
});

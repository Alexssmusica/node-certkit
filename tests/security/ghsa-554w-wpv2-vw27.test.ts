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
  function createNestedDer(depth) {
    var obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00');
    for (var i = 0; i < depth; i++) {
      obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [obj]);
    }
    return asn1.toDer(obj).getBytes();
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
});

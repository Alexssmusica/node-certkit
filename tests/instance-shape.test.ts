import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../src/presentation/index.js';
import type { PrngPlugin } from '../src/infrastructure/prng/PrngTypes.js';

type ValueDescription = {
  type: string;
  length?: number;
};

type InstanceDescription = {
  label: string;
  ownKeys: string[];
  methods: Record<string, ValueDescription>;
  properties: Record<string, ValueDescription>;
  protoMethods: Record<string, ValueDescription>;
};

type SnapshotDiff = {
  added: string[];
  removed: string[];
  changed: Array<{ key: string; expected: unknown; actual: unknown }>;
};
/**
 * Snapshot test for factory-created instance shapes.
 * Complements api-surface.test.js which only walks the certkit namespace.
 */
import fs from 'node:fs';
import path from 'node:path';
const snapshotPath = path.join(import.meta.dirname, 'instance-shape.snapshot.json');
const expected = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));

const fixtureDir = path.join(import.meta.dirname, 'fixtures');
const bufferB64 = fs.readFileSync(path.join(fixtureDir, 'certificate.pfx.b64'), 'utf8').trim();
const password = fs.readFileSync(path.join(fixtureDir, 'certificate.password.txt'), 'utf8').trim();

function describeValue(value: unknown): ValueDescription {
  if (value === null || value === undefined) {
    return { type: String(value) };
  }
  const t = typeof value;
  if (t === 'function') {
    return { type: 'function', length: (value as (...args: unknown[]) => unknown).length };
  }
  if (t !== 'object') {
    return { type: t };
  }
  if (Array.isArray(value)) {
    return { type: 'array', length: value.length };
  }
  if (value instanceof Date) {
    return { type: 'date' };
  }
  return { type: 'object' };
}

function describeInstance(instance: object, label: string): InstanceDescription {
  const record = instance as Record<string, unknown>;
  const ownKeys = Object.keys(record).sort();
  const methods: Record<string, ValueDescription> = {};
  const properties: Record<string, ValueDescription> = {};

  for (let i = 0; i < ownKeys.length; i++) {
    const key = ownKeys[i];
    const val = record[key];
    if (typeof val === 'function') {
      methods[key] = describeValue(val);
    } else {
      properties[key] = describeValue(val);
    }
  }

  const proto = Object.getPrototypeOf(instance);
  const protoMethods: Record<string, ValueDescription> = {};
  if (proto && proto !== Object.prototype) {
    const names = Object.getOwnPropertyNames(proto).sort();
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      if (name === 'constructor') {
        continue;
      }
      const desc = Object.getOwnPropertyDescriptor(proto, name);
      if (desc && typeof desc.value === 'function') {
        protoMethods[name] = describeValue(desc.value);
      }
    }
  }

  return {
    label,
    ownKeys,
    methods,
    properties,
    protoMethods
  };
}

function loadPkcs12() {
  const decoded = certkit.util.binary.base64.decode(bufferB64);
  const buffer = new Uint8Array(decoded);
  const asn = certkit.asn1.fromDer(new certkit.util.ByteStringBuffer(buffer));
  return certkit.pkcs12.pkcs12FromAsn1(asn, true, password);
}

function buildActual(): Record<string, InstanceDescription> {
  const actual: Record<string, InstanceDescription> = {};

  actual['md5.create'] = describeInstance(certkit.md.md5.create(), 'md5.create');
  actual['sha1.create'] = describeInstance(certkit.md.sha1.create(), 'sha1.create');
  actual['sha256.create'] = describeInstance(certkit.md.sha256.create(), 'sha256.create');
  actual['sha512.create'] = describeInstance(certkit.md.sha512.create(), 'sha512.create');
  actual['hmac.create'] = describeInstance(certkit.hmac.create(), 'hmac.create');

  const aesKey = certkit.util.createBuffer(certkit.random.getBytesSync(16));
  actual['cipher.createCipher(AES-CBC)'] = describeInstance(
    certkit.cipher.createCipher('AES-CBC', aesKey),
    'cipher.createCipher(AES-CBC)'
  );

  actual['prng.create'] = describeInstance(
    certkit.prng.create({ md: certkit.md.sha256 } as unknown as PrngPlugin),
    'prng.create'
  );
  actual['random'] = describeInstance(certkit.random, 'random');
  actual['pki.createCertificate'] = describeInstance(certkit.pki.createCertificate(), 'pki.createCertificate');
  actual['pki.createCertificationRequest'] = describeInstance(
    certkit.pki.createCertificationRequest(),
    'pki.createCertificationRequest'
  );
  actual['pki.createCaStore'] = describeInstance(certkit.pki.createCaStore(), 'pki.createCaStore');
  actual['pkcs12.pkcs12FromAsn1'] = describeInstance(loadPkcs12(), 'pkcs12.pkcs12FromAsn1');

  const n = new certkit.jsbn.BigInteger('a1b2c3d4e5f6789012345678901234567890abcdef', 16);
  const e = new certkit.jsbn.BigInteger('10001', 16);
  const d = new certkit.jsbn.BigInteger('deadbeef', 16);
  const p = new certkit.jsbn.BigInteger('f00d', 16);
  const q = new certkit.jsbn.BigInteger('ba11', 16);

  actual['rsa.setPublicKey'] = describeInstance(certkit.pki.rsa.setPublicKey(n, e), 'rsa.setPublicKey');
  actual['rsa.setPrivateKey'] = describeInstance(certkit.pki.rsa.setPrivateKey(n, e, d, p, q), 'rsa.setPrivateKey');
  actual['pss.create'] = describeInstance(
    certkit.pss.create({
      md: certkit.md.sha1.create(),
      mgf: certkit.mgf.mgf1.create(certkit.md.sha1.create()),
      saltLength: 20
    }),
    'pss.create'
  );
  actual['mgf.mgf1.create'] = describeInstance(certkit.mgf.mgf1.create(certkit.md.sha1.create()), 'mgf.mgf1.create');

  const rc2Key = certkit.util.createBuffer(certkit.random.getBytesSync(16));
  actual['rc2.createEncryptionCipher'] = describeInstance(
    certkit.rc2.createEncryptionCipher(rc2Key, 128),
    'rc2.createEncryptionCipher'
  );
  actual['jsbn.BigInteger'] = describeInstance(new certkit.jsbn.BigInteger('1234'), 'jsbn.BigInteger');
  actual['util.createBuffer'] = describeInstance(certkit.util.createBuffer(), 'util.createBuffer');

  return actual;
}

function diffSnapshots(a: Record<string, unknown>, b: Record<string, unknown>): SnapshotDiff {
  const added: string[] = [];
  const removed: string[] = [];
  const changed: SnapshotDiff['changed'] = [];
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  allKeys.forEach((key) => {
    if (!(key in a)) {
      added.push(key);
    } else if (!(key in b)) {
      removed.push(key);
    } else if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) {
      changed.push({ key, expected: a[key], actual: b[key] });
    }
  });
  return { added, removed, changed };
}

describe('Instance shape snapshot', () => {
  it('matches the committed snapshot', (ctx) => {
    const actual = buildActual();
    const diff = diffSnapshots(expected, actual);
    if (diff.added.length || diff.removed.length || diff.changed.length) {
      const msg = [];
      if (diff.added.length) {
        msg.push(`Added instances: ${diff.added.join(', ')}`);
      }
      if (diff.removed.length) {
        msg.push(`Removed instances: ${diff.removed.join(', ')}`);
      }
      if (diff.changed.length) {
        msg.push(
          `Changed instances: ${diff.changed
            .slice(0, 5)
            .map((c) => {
              return c.key;
            })
            .join(', ')}`
        );
      }
      expect.fail(msg.join('\n'));
    }
  });
});

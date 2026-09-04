# node-certkit

[![Main Checks](https://github.com/Alexssmusica/node-certkit/actions/workflows/main.yaml/badge.svg)](https://github.com/Alexssmusica/node-certkit/actions/workflows/main.yaml)

Node-only TypeScript toolkit for PKI, certificates, and cryptography.

## Features

* **X.509** — create, parse, sign, and verify certificates and chains
* **CSR (PKCS#10)** — create and verify certificate signing requests
* **PKCS#12 / PFX** — load and export password-protected certificate bundles
* **PKCS#8** — private key encoding and PEM conversion
* **RSA** — key generation, sign/verify, PSS, and OAEP
* **ASN.1 / DER** — encode and decode ASN.1 structures
* **PEM** — encode and decode PEM blocks
* **Symmetric ciphers** — AES (ECB, CBC, CFB, OFB, CTR, GCM), DES/3DES, RC2
* **Digests** — MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC
* **PBKDF2** — password-based key derivation
* **PRNG** — Fortuna random number generator
* **Math** — BigInteger and probable-prime generation

This library does **not** include TLS, HTTP, SSH, browser bundles, or Ed25519.
It targets server-side Node.js workflows such as certificate issuance, PKCS#12
handling, and low-level PKI operations.

## Requirements

* Node.js >= 24

## Installation

    npm install node-certkit

## Usage

The package is published as CommonJS (`lib/`). Both import styles are supported:

### CommonJS

```js
const certkit = require('node-certkit').default;
```

### ESM (Node.js consuming CJS)

```js
import certkit from 'node-certkit';
```

### Self-signed certificate

```js
import certkit from 'node-certkit';

const keys = certkit.pki.rsa.generateKeyPair(2048);
const cert = certkit.pki.createCertificate();

cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{name: 'commonName', value: 'example.org'}];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey);

console.log(certkit.pki.certificateToPem(cert));
```

See [examples/create-cert.js](examples/create-cert.js) for a full example with
extensions.

### Certificate signing request (CSR)

```js
import certkit from 'node-certkit';

const keys = certkit.pki.rsa.generateKeyPair(2048);
const csr = certkit.pki.createCertificationRequest();

csr.publicKey = keys.publicKey;
csr.setSubject([{name: 'commonName', value: 'example.org'}]);
csr.sign(keys.privateKey);

console.log(certkit.pki.certificationRequestToPem(csr));
console.log(csr.verify()); // true
```

See [examples/create-csr.js](examples/create-csr.js).

### PKCS#12 / PFX

Create a PKCS#12 bundle and load it back:

```js
import certkit from 'node-certkit';

const keys = certkit.pki.rsa.generateKeyPair(2048);
const cert = certkit.pki.createCertificate();
// ... configure and sign cert ...

const password = 'secret';
const asn1 = certkit.pkcs12.toPkcs12Asn1(
  keys.privateKey, [cert], password,
  {generateLocalKeyId: true, friendlyName: 'my-cert'});
const der = certkit.asn1.toDer(asn1).getBytes();

const loaded = certkit.pkcs12.pkcs12FromAsn1(
  certkit.asn1.fromDer(der), false, password);
```

See [examples/create-pkcs12.js](examples/create-pkcs12.js) for chain verification
and bag extraction.

### RSA sign and verify

```js
import certkit from 'node-certkit';

const keys = certkit.pki.rsa.generateKeyPair(2048);
const md = certkit.md.sha256.create();
md.update('sign this', 'utf8');

const signature = keys.privateKey.sign(md);
const verified = keys.publicKey.verify(md.digest().getBytes(), signature);
```

### AES-GCM

```js
import certkit from 'node-certkit';

const key = certkit.random.getBytesSync(16);
const iv = certkit.random.getBytesSync(12);
const cipher = certkit.cipher.createCipher('AES-GCM', key);
cipher.start({iv, tagLength: 128});
cipher.update(certkit.util.createBuffer('hello'));
cipher.finish();

const encrypted = cipher.output.getBytes();
const tag = cipher.mode.tag.getBytes();
```

### Message digests and HMAC

```js
import certkit from 'node-certkit';

const md = certkit.md.sha256.create();
md.update('message', 'utf8');
console.log(md.digest().toHex());

const hmac = certkit.hmac.create();
hmac.start('sha256', 'secret-key');
hmac.update('message', 'utf8');
console.log(hmac.digest().toHex());
```

### PBKDF2

```js
import certkit from 'node-certkit';

const key = certkit.pkdf2('password', 'salt', 32, 100000, 'sha256');
```

### ASN.1 and PEM

```js
import certkit from 'node-certkit';

const pem = certkit.pki.certificateToPem(cert);
const parsed = certkit.pki.certificateFromPem(pem);

const asn1 = certkit.asn1.fromDer(derBytes);
const der = certkit.asn1.toDer(asn1).getBytes();
```

## API overview

The default export is a flat namespace assembled at load time. Main areas:

| Namespace | Purpose |
|-----------|---------|
| `certkit.pki` | X.509, CSR, PEM, OIDs, CA store, chain verification |
| `certkit.pki.rsa` | RSA key generation |
| `certkit.pkcs12` | PKCS#12 load and export |
| `certkit.asn1` | ASN.1 DER encoding and decoding |
| `certkit.cipher` / `certkit.aes` / `certkit.des` / `certkit.rc2` | Symmetric encryption |
| `certkit.md` / `certkit.md5` / `certkit.sha1` / `certkit.sha256` / `certkit.sha512` | Digests |
| `certkit.hmac` | HMAC |
| `certkit.pbkdf2` | PBKDF2 key derivation |
| `certkit.pem` | Generic PEM encode/decode |
| `certkit.util` | Buffers, Base64, hex, encoding helpers |
| `certkit.random` / `certkit.prng` | Random bytes and PRNG |
| `certkit.jsbn` | BigInteger |
| `certkit.prime` | Probable-prime generation |
| `certkit.pkcs1` | RSA-OAEP encoding |
| `certkit.pss` | RSA-PSS |
| `certkit.mgf` / `certkit.mgf1` | Mask generation functions |

Named exports from the package entry:

```js
import certkit, {createCertkit} from 'node-certkit';
```

## TypeScript / migrating from node-forge

This package ships its own types (no `@types/node-forge` needed). The runtime
API is intentionally similar to node-forge; most call sites only need to change
the import:

```ts
// before
import forge from 'node-forge';

// after
import certkit from 'node-certkit';
```

### Type equivalents

| node-forge (`@types/node-forge`) | node-certkit |
|----------------------------------|--------------|
| `forge.pkcs12.PKCS12Pfx` | `Pkcs12Pfx` or `certkit.pkcs12.Pkcs12Pfx` (named import) |
| `forge.pki.Certificate` | `X509Certificate` or `certkit.pki.Certificate` (named import) |
| `forge.pki.rsa.PrivateKey` | `RsaPrivateKey` or `certkit.pki.rsa.PrivateKey` (named import) |
| `forge.asn1.Asn1` | `Asn1Object` or `certkit.asn1.Asn1` (named import) |
| `forge.util.ByteBuffer` | `ByteStringBuffer` or `certkit.util.ByteBuffer` (named import) |

### Importing types

**Important:** `import certkit from 'node-certkit'` gives you the runtime API
only. Forge-style namespace types such as `certkit.pki.rsa.PrivateKey` require
the **named import** (same instance, merged with the type namespace):

```ts
// TS2503: Cannot find namespace 'certkit' — default import has no type namespace
import certkit from 'node-certkit';
let key: certkit.pki.rsa.PrivateKey; // error

// Correct: named import for runtime + namespace types
import { certkit, type Pkcs12Pfx } from 'node-certkit';

let privateKey: certkit.pki.rsa.PrivateKey | null = null;
let certificate: certkit.pki.Certificate | null = null;
```

With **default import**, use named type exports instead of namespace paths:

```ts
import certkit, { type Pkcs12Pfx, type RsaPrivateKey, type X509Certificate } from 'node-certkit';

function getKey(p12: Pkcs12Pfx): string {
  const bags = p12.getBags({ bagType: certkit.pki.oids.keyBag });
  // ...
}
```

### NFSe certificate load (typed)

Typical flow when rebuilding a PKCS#12 for NFSe — uses named import throughout:

```ts
import { certkit, type Pkcs12Pfx } from 'node-certkit';

export function loadCertificateNFSe(p12: Pkcs12Pfx) {
  let privateKey: certkit.pki.rsa.PrivateKey | null = null;
  let certificate: certkit.pki.Certificate | null = null;
  const caCertificates: certkit.pki.Certificate[] = [];

  for (const safeContent of p12.safeContents) {
    for (const bag of safeContent.safeBags) {
      if (bag.type === certkit.pki.oids.keyBag) {
        privateKey = bag.key ?? null; // bag.key is optional
      }
      if (bag.type === certkit.pki.oids.certBag && bag.cert) {
        const bc = bag.cert.getExtension('basicConstraints');
        if (!bc || bc['cA'] === false) {
          certificate = bag.cert;
        } else {
          caCertificates.push(bag.cert);
        }
      }
    }
  }

  const tempPassword = Math.random().toString(36).substring(2);
  const p12Asn1 = certkit.pkcs12.toPkcs12Asn1(
    privateKey!,
    [certificate!, ...caCertificates],
    tempPassword,
    { algorithm: '3des' }
  );
  const p12Der = certkit.asn1.toDer(p12Asn1).getBytes();
  return { p12Buffer: Buffer.from(p12Der, 'binary'), tempPassword };
}
```

Note: `bag.certChain` from node-forge typings is not populated by certkit; use
`bag.cert` only. `safeContents[].safeBags` is already `Pkcs12Bag[]` (no need for
`Object.values` + `Array.isArray`).

### PKCS#12 load (typed)

```ts
import certkit, { type Pkcs12Pfx } from 'node-certkit';

const decoded = certkit.util.binary.base64.decode(base64Pfx);
const asn = certkit.asn1.fromDer(new certkit.util.ByteStringBuffer(decoded));
const p12: Pkcs12Pfx = certkit.pkcs12.pkcs12FromAsn1(asn, true, password);
```

`util.binary.base64.decode(input)` returns `Uint8Array` (no need to wrap with
`new Uint8Array(...)` unless you want a copy).

### Stricter null checks

Unlike `@types/node-forge` (which used `any` in several places), certkit types
are strict. `certificate.subject.getField(...)` returns `DnAttribute | null`:

```ts
const cn = certificate.subject.getField({ name: 'commonName' });
if (!cn) {
  throw new Error('commonName not found in certificate subject');
}
const values = cn.value.toString().split(':');
```

## Testing

### Prepare to run tests

    npm install

### Running tests

Tests run with [Vitest][] against the TypeScript sources in `src/`:

    npm test

Watch mode:

    npm run test:watch

Type-check tests only (strict, no emit):

    npm run test:types

Public API type regression (consumer usage + golden test):

    npm run test:types:public

Published declaration file (`lib/index.d.ts`):

    npm run build && npm run test:dts

Security regression tests live under `tests/security/` and are included in
`npm test`.

### Snapshots and fixtures

- `tests/api-surface.snapshot.json` and `tests/instance-shape.snapshot.json`
  are compared by snapshot tests. Do not regenerate them to silence failures
  without investigating each divergence.
- `tests/fixtures/` holds PKCS#12 golden inputs for certificate-load tests.

## License

[MIT](LICENSE)

## Credits

Based on [node-forge](https://github.com/digitalbazaar/forge) by Digital Bazaar.

[Vitest]: https://vitest.dev/

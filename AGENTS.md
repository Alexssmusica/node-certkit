# Agent guidelines — node-certkit

## Naming conventions

This library is a TypeScript port of node-forge. Prefer explicit camelCase for parameters and locals (minimum identifier length 3 per ESLint).

### Domain vocabulary (keep on the public surface)

Abbreviations that are standard in PKI/crypto libraries and frozen on the exported `certkit` object (see `tests/api-surface.test.ts` and `tests/api-surface.snapshot.json`):

`md`, `oid`, `iv`, `dk`, `pem`, `csr`, `tbs`, `cri`, `pfx`, `p12`, `ski`, `ext`, and other keys in the snapshot.

Do not rename snapshot keys. In implementation code, use bracket access (e.g. `cert['md']`) or longer local names (e.g. `digestRegistry`) when ESLint `id-length` applies; wire snapshot names only at assembly boundaries.

`id-length` uses `properties: 'never'`, so property names on objects (e.g. `BigInteger` fields `data`, `s`, `t`, RSA `n`/`e`/`d`) are not linted.

### Public types (breaking change)

Forge-style nested type paths such as `certkit.pki.rsa.PrivateKey` are **not** exported. Use named type exports from `node-certkit` (`RsaPrivateKey`, `X509Certificate`, `Pkcs12Pfx`, etc.).

### Legacy placeholders (rename)

Generic placeholders inherited from node-forge with no semantic value:

`rval`, `tmp`, `obj`, `msg`, `s2`, `b2`, `cap`, `res`, `ret`, `c`/`h` as runtime handles

Prefer descriptive English names: `digestBuffer`, `pemMessage`, `capture`, `extensions`, `runtime`.

### Style rules

- **Variables and parameters:** camelCase, `id-length` minimum 3 (no letter exceptions in eslint.config.js)
- **Types, classes, interfaces:** PascalCase
- **Public API snake_case:** only where already exposed (`encode_rsa_oaep`, error codes like `bad_certificate`) — do not rename
- **Comma-chained `let`:** split into separate declarations

### Lint scope

ESLint `id-length`, `@typescript-eslint/naming-convention`, and `@typescript-eslint/no-shadow` should be **errors** in the base config (no file-level exemptions except `tests/`).

Naming rules are **off** in `tests/` so spec-mirrored vectors do not drown out real warnings.

TypeScript uses `noUncheckedIndexedAccess: false`; removing redundant non-null assertions (`@typescript-eslint/no-unnecessary-type-assertion`) assumes that setting stays off.

### Safety net before merging naming changes

```bash
npm run lint
npm test
npm run test:types
```

`tests/api-surface.test.ts` and `tests/instance-shape.snapshot.json` freeze the public `certkit` runtime object and factory instance shapes — any rename that leaks to the public API will fail.

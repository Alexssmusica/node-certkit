# Agent guidelines — node-certkit

## Naming conventions

This library is a TypeScript port of node-forge. Internal names fall into three categories; treat each differently when editing code.

### 1. Canonical spec notation (preserve)

Short names that mirror RFCs, FIPS, or published algorithms. Renaming hurts auditability against the spec. Document with JSDoc when touching these blocks.

| Area | Examples | Reference |
|------|----------|-----------|
| PKCS#1 OAEP/PSS | `DB`, `PS`, `lHash`, `em`, `mHash`, `maskedDB` | RFC 8017 |
| PKCS#12 key derivation | `D`, `S`, `P`, `I`, `B`, `u`, `v` | RFC 7292 |
| PBKDF2 | `p`, `s`, `c`, `dk`, `u_c` | RFC 2898 |
| RSA key components | `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv` | PKCS#1 (public API) |
| SHA rounds | `a`–`h`, `t1`, `t2`, `s0`, `s1` | FIPS 180 |
| AES | `Nb`, `Nk`, `Nr`, state columns `a`–`d` | FIPS 197 |
| BigInteger / Montgomery | `t`, `s`, `data`, `mp`, `mpl`, `r`, `q` | HAC / jsBN |
| ASN.1 time fields | `MM`, `DD`, `hh`, `mm`, `ss` | X.690 |

### 2. Domain vocabulary (keep)

Abbreviations that are standard in PKI/crypto libraries:

`md`, `oid`, `iv`, `dk`, `pem`, `csr`, `tbs`, `cri`, `pfx`, `p12`, `ski`, `ext`

### 3. Legacy laziness (rename)

Generic placeholders inherited from node-forge with no semantic value:

`rval`, `tmp`, `obj`, `msg`, `s2`, `b2`, `cap`, `res`, `ret`, `c`/`h` as runtime handles

Prefer descriptive English names: `digestBuffer`, `pemMessage`, `capture`, `extensions`, `runtime`.

### Style rules

- **Variables and parameters:** camelCase
- **Types, classes, interfaces:** PascalCase
- **Public API snake_case:** only where already exposed (`encode_rsa_oaep`, error codes like `bad_certificate`) — do not rename
- **Loop indices:** `i`, `j`, `k` are acceptable in tight loops

### Lint scope

ESLint naming rules apply as `error` in: `src/domain/pki/`, `src/domain/asn1/`, `src/domain/buffer/`, `src/domain/util/`, `src/presentation/`.

They are disabled in `src/domain/math/`, `src/domain/cipher/`, and `src/domain/digest/` where canonical algorithm notation applies.

### Safety net before merging naming changes

```bash
npm run lint
npm test
npm run test:types
```

`tests/api-surface.test.ts` snapshots the public `certkit` object — any rename that leaks to the public API will fail.

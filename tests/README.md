Certkit Tests
===========

Automated tests run with [Vitest](https://vitest.dev/) against
`src/presentation/index.ts` (not `dist/`).

Commands
--------

    npm test              # run all tests once (tests/**/*.test.ts)
    npm run test:watch    # watch mode
    npm run test:types    # tsc --noEmit on tests + src (strict)

Layout
------

- `unit/` — cryptographic and PKI unit tests
- `security/` — regression tests for published advisories
- `api-surface.test.ts` — walks the public certkit namespace shape
- `instance-shape.test.ts` — golden shape of a loaded PKCS#12 fixture
- `certificate-load.golden.test.ts` — PKCS#12 load golden test
- `fixtures/` — PKCS#12 inputs for golden tests
- `*.snapshot.json` — committed snapshot baselines

Snapshot policy
---------------

Do not edit snapshot files to silence a failing test without investigating
each divergence:

- A path added or removed in `api-surface.snapshot.json` is a real API change.
- A `length`-only mismatch with an identical path set may be an emit artifact;
  explain each case before updating the snapshot.

See also the [Testing](../README.md#testing) section of the main README.

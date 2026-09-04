import type { NativeCryptoProvider } from '../ports/index.js';
import type { DigestAlgorithmRegistry, HmacContext } from '../digest/DigestTypes.js';

export type Pbkdf2Dependencies = {
  usePureJavaScript: boolean;
  nativeCrypto: NativeCryptoProvider;
  mdAlgorithms: DigestAlgorithmRegistry;
  hmacCreate: () => HmacContext;
};

type Pbkdf2MessageDigest = {
  digestLength: number;
  start: () => void;
  update: (bytes: string) => void;
  digest: () => { getBytes: () => string };
};

export type Pbkdf2Callback = (err: Error | null, key?: string) => void;

export type Pbkdf2Function = {
  (p: string, s: string, c: number, dkLen: number, md?: string | Pbkdf2MessageDigest | null): string;
  (
    p: string,
    s: string,
    c: number,
    dkLen: number,
    md: string | Pbkdf2MessageDigest | null | undefined,
    callback: Pbkdf2Callback
  ): void;
  (p: string, s: string, c: number, dkLen: number, callback: Pbkdf2Callback): void;
};

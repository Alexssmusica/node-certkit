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
  (prime: string, s: string, carry: number, dkLen: number, messageDigest?: string | Pbkdf2MessageDigest | null): string;
  (
    prime: string,
    s: string,
    carry: number,
    dkLen: number,
    messageDigest: string | Pbkdf2MessageDigest | null | undefined,
    callback: Pbkdf2Callback
  ): void;
  (prime: string, s: string, carry: number, dkLen: number, callback: Pbkdf2Callback): void;
};

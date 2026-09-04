/**
 * Port for cryptographically secure random bytes.
 */
export interface RandomSource {
  getBytesSync(count: number): string;
  getBytes(count: number, callback: (err: Error | null, bytes?: string) => void): string | void;
}

/**
 * Port for probable prime generation.
 */
export interface PrimeGenerator {
  generateProbablePrime(
    bits: number,
    options: Record<string, unknown>,
    callback: (err: Error | null, num?: unknown) => void
  ): void;
}

/**
 * Port for Node.js native crypto fast paths.
 */
export interface NativeCryptoProvider {
  readonly available: boolean;
  readonly pbkdf2SyncSupportsDigest: boolean;
  readonly pbkdf2Available: boolean;
  randomBytes(length: number): Buffer;
  randomBytes(length: number, callback: (err: Error | null, bytes: Buffer) => void): void;
  pbkdf2Sync(password: string, salt: string, iterations: number, keylen: number, digest?: string): Buffer;
  pbkdf2?(
    password: string,
    salt: string,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey: Buffer) => void
  ): void;
  generateKeyPairSync(type: string, options: Record<string, unknown>): { publicKey: string; privateKey: string };
  generateKeyPair(
    type: string,
    options: Record<string, unknown>,
    callback: (err: Error | null, publicKey: string, privateKey: string) => void
  ): void;
}

/**
 * Port for time access (certificate validity checks).
 */
export interface Clock {
  now(): Date;
}

/**
 * Port for PEM-encoded RSA key parsing (breaks rsa↔pki cycle).
 */
export interface PemKeyCodec {
  privateKeyFromPem(pem: string): unknown;
  publicKeyFromPem(pem: string): unknown;
}

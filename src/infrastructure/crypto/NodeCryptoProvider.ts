import crypto from 'node:crypto';
import type { NativeCryptoProvider } from '../../domain/ports/index.js';

export class NodeCryptoProvider implements NativeCryptoProvider {
  readonly available = true;
  readonly pbkdf2SyncSupportsDigest = crypto.pbkdf2Sync.length > 4;
  readonly pbkdf2Available = typeof crypto.pbkdf2 === 'function';

  randomBytes(length: number, callback?: (err: Error | null, bytes: Buffer) => void): Buffer {
    if (callback) {
      crypto.randomBytes(length, callback);
      return Buffer.alloc(0);
    }
    return crypto.randomBytes(length);
  }

  pbkdf2Sync(password: string, salt: string, iterations: number, keylen: number, digest?: string): Buffer {
    if (this.pbkdf2SyncSupportsDigest && digest) {
      return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
    }
    return (crypto.pbkdf2Sync as (p: string, s: string, i: number, k: number) => Buffer)(password, salt, iterations, keylen);
  }

  pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey: Buffer) => void
  ): void {
    if (this.pbkdf2SyncSupportsDigest) {
      crypto.pbkdf2(password, salt, iterations, keylen, digest, callback);
      return;
    }
    (crypto.pbkdf2 as unknown as (p: string, s: string, i: number, k: number, cb: (err: Error | null, key: Buffer) => void) => void)(
      password,
      salt,
      iterations,
      keylen,
      callback
    );
  }

  generateKeyPairSync(_type: string, options: Record<string, unknown>): { publicKey: string; privateKey: string } {
    return crypto.generateKeyPairSync('rsa', options as unknown as crypto.RSAKeyPairOptions<'pem', 'pem'>);
  }

  generateKeyPair(
    _type: string,
    options: Record<string, unknown>,
    callback: (err: Error | null, publicKey: string, privateKey: string) => void
  ): void {
    crypto.generateKeyPair('rsa', options as unknown as crypto.RSAKeyPairOptions<'pem', 'pem'>, callback);
  }
}

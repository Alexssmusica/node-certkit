import type {RandomSource, NativeCryptoProvider} from '../../domain/ports/index.js';

export class NodeRandomSource implements RandomSource {
  constructor(private readonly nativeCrypto: NativeCryptoProvider) {}

  getBytesSync(count: number): string {
    return this.nativeCrypto.randomBytes(count).toString('binary');
  }

  getBytes(count: number, callback: (err: Error | null, bytes?: string) => void): void {
    this.nativeCrypto.randomBytes(count, (err, bytes) => {
      if (err) {
        callback(err);
        return;
      }
      callback(null, bytes.toString('binary'));
    });
  }
}

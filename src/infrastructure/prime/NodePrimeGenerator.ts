import type { BigInteger } from '../../domain/math/BigInteger.js';
import { PrimeService } from '../../domain/prime/PrimeService.js';
import type { PrimeGenerateOptions } from '../../domain/prime/PrimeTypes.js';
import type { PrimeGenerator } from '../../domain/ports/index.js';
import { NodeRandomSource } from '../random/NodeRandomSource.js';
import { NodeCryptoProvider } from '../crypto/NodeCryptoProvider.js';

/**
 * Node.js probable prime generator using PRIMEINC algorithm.
 */
export class NodePrimeGenerator implements PrimeGenerator {
  readonly #randomSource: { getBytesSync(count: number): string };

  constructor(randomSource?: { getBytesSync(count: number): string }) {
    this.#randomSource = randomSource ?? new NodeRandomSource(new NodeCryptoProvider());
  }

  generateProbablePrime(
    bits: number,
    options: PrimeGenerateOptions,
    callback: (err: Error | null, num?: BigInteger) => void
  ): void {
    const opts: PrimeGenerateOptions = { ...options };
    if (!opts.prng) {
      opts.prng = this.#randomSource;
    }
    PrimeService.generateProbablePrime(bits, opts, callback);
  }
}

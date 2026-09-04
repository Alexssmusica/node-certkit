import {PrimeService} from '../../domain/prime/PrimeService.js';
import type {PrimeGenerator} from '../../domain/ports/index.js';
import {NodeRandomSource} from '../random/NodeRandomSource.js';
import {NodeCryptoProvider} from '../crypto/NodeCryptoProvider.js';

/**
 * Node.js probable prime generator using PRIMEINC algorithm.
 */
export class NodePrimeGenerator implements PrimeGenerator {
  readonly #randomSource: {getBytesSync(count: number): string};

  constructor(randomSource?: {getBytesSync(count: number): string}) {
    this.#randomSource = randomSource ?? new NodeRandomSource(new NodeCryptoProvider());
  }

  generateProbablePrime(
    bits: number,
    options: Record<string, unknown>,
    callback: (err: Error | null, num?: unknown) => void
  ): void {
    const opts = {...options};
    if (!opts.prng) {
      opts.prng = this.#randomSource;
    }
    PrimeService.generateProbablePrime(bits, opts, callback);
  }
}

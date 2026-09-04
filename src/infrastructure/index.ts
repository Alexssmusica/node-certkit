import type { Clock, NativeCryptoProvider, PrimeGenerator, RandomSource } from '../domain/ports/index.js';
import type { InfrastructureContext } from './InfrastructureTypes.js';
import { NodeCryptoProvider } from './crypto/NodeCryptoProvider.js';
import { NodePrimeGenerator } from './prime/NodePrimeGenerator.js';
import { NodeRandomSource } from './random/NodeRandomSource.js';
import { SystemClock } from './env/SystemClock.js';

export function createInfrastructure(): InfrastructureContext {
  const nativeCrypto = new NodeCryptoProvider();
  return {
    randomSource: new NodeRandomSource(nativeCrypto),
    primeGenerator: new NodePrimeGenerator(),
    nativeCrypto,
    clock: new SystemClock()
  };
}

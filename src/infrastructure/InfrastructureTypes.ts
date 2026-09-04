import type { Clock, NativeCryptoProvider, PrimeGenerator, RandomSource } from '../domain/ports/index.js';

export interface InfrastructureContext {
  randomSource: RandomSource;
  primeGenerator: PrimeGenerator;
  nativeCrypto: NativeCryptoProvider;
  clock: Clock;
}

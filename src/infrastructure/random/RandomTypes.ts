import type { PrngContext } from '../prng/PrngTypes.js';

export type AesPrngBackend = {
  _expandKey: (key: unknown, decrypt: boolean) => unknown;
  _updateBlock: (w: unknown, seed: unknown, output: number[], decrypt: boolean) => void;
};

export type Sha256DigestFactory = {
  create: () => {
    messageLength: number;
    start: () => void;
    update: (bytes: string) => void;
    digest: () => { getBytes: () => string };
  };
};

export type FortunaRandomNamespace = PrngContext & {
  getBytes: (count: number, callback?: (err: Error | null, bytes?: string) => void) => string | void;
  getBytesSync: (count: number) => string;
  createInstance: () => FortunaRandomNamespace;
};

export type FortunaRandomDependencies = {
  aes: AesPrngBackend;
  sha256: Sha256DigestFactory;
};

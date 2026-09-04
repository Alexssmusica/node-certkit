import type {ByteStringBuffer} from '../buffer/ByteStringBuffer.js';
import type {CipherModeOptions} from './cipherModeUtils.js';

export type CipherApi<TMode> = {
  createCipher: (algorithm: string, key: unknown) => {
    start: (...args: unknown[]) => void;
  };
  createDecipher: (algorithm: string, key: unknown) => {
    start: (...args: unknown[]) => void;
  };
  registerAlgorithm: (name: string, factory: () => unknown) => void;
  modes: Record<string, new (options: CipherModeOptions) => TMode>;
};

export type ModeConstructor<TMode> = CipherApi<TMode>['modes'][string];

export type CreateCipherOptions = {
  key?: unknown;
  output?: ByteStringBuffer | null;
  decrypt?: boolean;
  mode?: string;
};

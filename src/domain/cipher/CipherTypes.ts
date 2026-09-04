import type { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { BlockCipher } from './BlockCipher.js';
import type { AesAlgorithm } from './AesAlgorithm.js';
import type { DesAlgorithm } from './DesAlgorithm.js';
import type { Rc2Cipher } from './Rc2Cipher.js';
import type { EcbMode } from './EcbMode.js';
import type { CbcMode } from './CbcMode.js';
import type { CfbMode } from './CfbMode.js';
import type { OfbMode } from './OfbMode.js';
import type { CtrMode } from './CtrMode.js';
import type { GcmMode } from './GcmMode.js';

export type CipherApi<TMode> = {
  createCipher: (
    algorithm: string,
    key: unknown
  ) => {
    start: (...args: unknown[]) => void;
  };
  createDecipher: (
    algorithm: string,
    key: unknown
  ) => {
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

export type CipherAlgorithm = {
  mode: {
    blockSize: number;
    name?: string;
    tag?: ByteStringBuffer;
    start: (options: Record<string, unknown>) => void;
    encrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    decrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    pad?: (input: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    unpad?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    afterFinish?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
  };
  initialize: (options: BlockCipherOptions) => void;
};

export type BlockCipherOptions = {
  algorithm: CipherAlgorithm;
  key: string | ByteStringBuffer;
  decrypt: boolean;
};

export type BlockCipherStartOptions = {
  iv?: string | ByteStringBuffer | number[] | null;
  additionalData?: string | ByteStringBuffer;
  tagLength?: number;
  tag?: string | ByteStringBuffer;
  output?: ByteStringBuffer;
};

export type PaddingFunction = (blockSize: number, buffer: ByteStringBuffer, decrypt: boolean) => boolean;

export type BlockCipherApi = {
  encrypt: (inBlock: number[], outBlock: number[]) => void;
  decrypt: (inBlock: number[], outBlock: number[]) => void;
};

export type CipherModeOptions = {
  cipher?: BlockCipherApi;
  blockSize?: number;
};

export type CipherModeStartOptions = {
  iv?: string | ByteStringBuffer | number[] | null;
  decrypt?: boolean;
  additionalData?: string | ByteStringBuffer;
  tagLength?: number;
  tag?: string | ByteStringBuffer;
  overflow?: number;
};

export type PadOptions = {
  overflow?: number;
  decrypt?: boolean;
};

export type CipherModesObject = {
  ecb: typeof EcbMode;
  cbc: typeof CbcMode;
  cfb: typeof CfbMode;
  ofb: typeof OfbMode;
  ctr: typeof CtrMode;
  gcm: typeof GcmMode;
};

export type CipherAlgorithmFactory = () => unknown;

export type CipherNamespaceObject = {
  algorithms: Record<string, CipherAlgorithmFactory>;
  modes: CipherModesObject;
  createCipher: (algorithm: string | unknown, key: unknown) => BlockCipher;
  createDecipher: (algorithm: string | unknown, key: unknown) => BlockCipher;
  registerAlgorithm: (name: string, algorithm: CipherAlgorithmFactory) => void;
  getAlgorithm: (name: string) => CipherAlgorithmFactory | null;
  BlockCipher: typeof BlockCipher;
};

export type Rc2CipherObject = {
  output?: ByteStringBuffer;
  start: (iv?: string | ByteStringBuffer | null, output?: ByteStringBuffer | null) => void;
  update: (input: ByteStringBuffer) => void;
  finish: (pad?: PaddingFunction) => boolean;
};

export type Rc2NamespaceObject = {
  expandKey: typeof Rc2Cipher.expandKey;
  startEncrypting: typeof Rc2Cipher.startEncrypting;
  createEncryptionCipher: typeof Rc2Cipher.createEncryptionCipher;
  startDecrypting: typeof Rc2Cipher.startDecrypting;
  createDecryptionCipher: typeof Rc2Cipher.createDecryptionCipher;
};

export type AesNamespaceObject = Record<string, unknown> & {
  startEncrypting: (...args: unknown[]) => unknown;
  createEncryptionCipher: (...args: unknown[]) => unknown;
  startDecrypting: (...args: unknown[]) => unknown;
  createDecryptionCipher: (...args: unknown[]) => unknown;
  Algorithm: typeof AesAlgorithm;
  _expandKey: (key: number[], decrypt: boolean) => number[];
  _updateBlock: (w: number[], input: number[], output: number[], decrypt: boolean) => void;
};

export type AesTables = {
  sbox: number[];
  isbox: number[];
  rcon: number[];
  mix: number[][];
  imix: number[][];
};

export type DesNamespaceObject = Record<string, unknown> & {
  startEncrypting: (...args: unknown[]) => unknown;
  createEncryptionCipher: (...args: unknown[]) => unknown;
  startDecrypting: (...args: unknown[]) => unknown;
  createDecryptionCipher: (...args: unknown[]) => unknown;
  Algorithm: typeof DesAlgorithm;
};

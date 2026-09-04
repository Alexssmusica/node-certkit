import type { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { Mgf1 } from './Mgf1.js';

export type MessageDigest = {
  digestLength: number;
  start: () => void;
  update: (bytes: string) => void;
  digest: () => ByteStringBuffer;
};

export type Mgf1Object = {
  generate: (seed: string, maskLen: number) => string;
};

export type Mgf1CertkitNamespace = ReturnType<typeof Mgf1.createCertkitNamespace>;

export type MgfNamespaceObject = {
  mgf1: Mgf1CertkitNamespace;
};

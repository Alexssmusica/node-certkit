import type { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { MessageDigest } from './MgfTypes.js';

export type MgfObject = {
  generate: (seed: string, maskLen: number) => string;
};

export type PssCreateOptions = {
  md: MessageDigest;
  mgf: MgfObject;
  saltLength?: number;
  prng?: { getBytesSync(count: number): string };
  salt?: string | ByteStringBuffer;
};

export type PssObject = {
  encode: (md: MessageDigest, modBits: number) => string;
  verify: (mHash: string, em: string, modBits: number) => boolean;
};

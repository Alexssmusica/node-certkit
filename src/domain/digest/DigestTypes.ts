import type { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';

export interface Md5Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Md5Digest;
  update: (msg: string, encoding?: string) => Md5Digest;
  digest: () => ByteStringBuffer;
}

export interface Sha1Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Sha1Digest;
  update: (msg: string, encoding?: string) => Sha1Digest;
  digest: () => ByteStringBuffer;
}

export interface Sha256Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength64: number[] | null;
  messageLengthSize: number;
  start: () => Sha256Digest;
  update: (msg: string, encoding?: string) => Sha256Digest;
  digest: () => ByteStringBuffer;
}

export interface Sha512Digest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  messageLength128: number[] | null;
  messageLengthSize: number;
  start: () => Sha512Digest;
  update: (msg: string, encoding?: string) => Sha512Digest;
  digest: () => ByteStringBuffer;
}

export interface BlockDigest {
  blockLength: number;
  start: () => BlockDigest;
  update: (msg: string, encoding?: string) => BlockDigest;
  digest: () => ByteStringBuffer;
}

export type DigestAlgorithmRegistry = Record<string, { create: () => BlockDigest }>;

export interface HmacContext {
  start: (md: string | BlockDigest | null, key: unknown) => void;
  update: (bytes: string) => void;
  getMac: () => ByteStringBuffer;
  digest: () => ByteStringBuffer;
}

export type DigestFactory<T = unknown> = {
  create: () => T;
};

export type MdRegistry = {
  algorithms: Record<string, DigestFactory>;
  md5: DigestFactory<Md5Digest>;
  sha1: DigestFactory<Sha1Digest>;
  sha256: DigestFactory<Sha256Digest>;
  sha384: DigestFactory<Sha512Digest>;
  sha512: DigestFactory<Sha512Digest>;
  'sha512/256': DigestFactory<Sha512Digest>;
  'sha512/224': DigestFactory<Sha512Digest>;
};

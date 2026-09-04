import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { DataBuffer } from '../buffer/DataBuffer.js';
import { Base58Codec } from '../encoding/Base58Codec.js';
import { Base64Codec } from '../encoding/Base64Codec.js';
import { HexCodec } from '../encoding/HexCodec.js';
import { RawCodec } from '../encoding/RawCodec.js';
import { Utf16Codec, Utf8TextCodec } from '../encoding/Utf16Codec.js';
import { EnvInfo } from '../../infrastructure/env/EnvInfo.js';

type BaseNModule = {
  encode: (
    input: Uint8Array | { length(): number; at(i: number): number },
    alphabet: string,
    maxline?: number
  ) => string;
  decode: (input: string, alphabet: string) => Uint8Array | undefined;
};

/** Flat util namespace shape matching legacy certkit.util API. */
export type UtilNamespaceObject = Record<string, unknown> & {
  ByteBuffer: typeof ByteStringBuffer;
  ByteStringBuffer: typeof ByteStringBuffer;
  DataBuffer: typeof DataBuffer;
  binary: {
    raw: { encode: typeof RawCodec.encode; decode: typeof RawCodec.decode };
    hex: { encode: (bytes: Uint8Array | string) => string; decode: typeof HexCodec.decode };
    base64: { encode: typeof Base64Codec.encode; decode: typeof Base64Codec.decode };
    base58: { encode: typeof Base58Codec.encode; decode: typeof Base58Codec.decode };
    baseN: BaseNModule;
  };
  text: {
    utf8: { encode: typeof Utf8TextCodec.encode; decode: typeof Utf8TextCodec.decode };
    utf16: { encode: typeof Utf16Codec.encode; decode: typeof Utf16Codec.decode };
  };
  createBuffer: (input?: unknown, encoding?: string) => ByteStringBuffer;
  bytesToHex: (bytes: string) => string;
  hexToBytes: (hex: string) => string;
  encode64: (input: string, maxline?: number) => string;
  decode64: (input: string) => string;
  nextTick: typeof EnvInfo.nextTick;
  setImmediate: typeof EnvInfo.setImmediate;
  isNodejs: boolean;
  globalScope: typeof globalThis;
  estimateCores: (
    options: { update?: boolean } | ((err: null, cores: number) => void),
    callback?: (err: null, cores: number) => void
  ) => void;
  cores?: number;
};

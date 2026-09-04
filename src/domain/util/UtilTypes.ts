import type { ByteStringBufferInput } from '../buffer/BufferTypes.js';
import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { DataBuffer } from '../buffer/DataBuffer.js';
import { Base58Codec } from '../encoding/Base58Codec.js';
import { Base64Codec } from '../encoding/Base64Codec.js';
import { HexCodec } from '../encoding/HexCodec.js';
import { RawCodec } from '../encoding/RawCodec.js';
import { Utf16Codec, Utf8TextCodec } from '../encoding/Utf16Codec.js';
import { decodeUtf8, encodeUtf8 } from '../encoding/Utf8Codec.js';
import { EnvInfo } from '../../infrastructure/env/EnvInfo.js';
import { UtilNamespace } from './UtilNamespace.js';

type BaseNModule = {
  encode: (
    input: Uint8Array | { length(): number; at(i: number): number },
    alphabet: string,
    maxline?: number
  ) => string;
  decode: (input: string, alphabet: string) => Uint8Array | undefined;
};

/** Flat util namespace shape matching legacy certkit.util API. */
export type UtilNamespaceObject = {
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
  isArray: typeof UtilNamespace.isArray;
  isArrayBuffer: typeof UtilNamespace.isArrayBuffer;
  isArrayBufferView: typeof UtilNamespace.isArrayBufferView;
  createBuffer: (input?: ByteStringBufferInput, encoding?: string) => ByteStringBuffer;
  fillString: typeof UtilNamespace.fillString;
  xorBytes: typeof UtilNamespace.xorBytes;
  int32ToBytes: typeof UtilNamespace.int32ToBytes;
  bytesToHex: typeof UtilNamespace.bytesToHex;
  hexToBytes: typeof UtilNamespace.hexToBytes;
  encode64: typeof UtilNamespace.encode64;
  decode64: typeof UtilNamespace.decode64;
  encodeUtf8: typeof encodeUtf8;
  decodeUtf8: typeof decodeUtf8;
  isEmpty: typeof UtilNamespace.isEmpty;
  format: typeof UtilNamespace.format;
  formatNumber: typeof UtilNamespace.formatNumber;
  formatSize: typeof UtilNamespace.formatSize;
  bytesFromIP: typeof UtilNamespace.bytesFromIP;
  bytesFromIPv4: typeof UtilNamespace.bytesFromIPv4;
  bytesFromIPv6: typeof UtilNamespace.bytesFromIPv6;
  bytesToIP: typeof UtilNamespace.bytesToIP;
  bytesToIPv4: typeof UtilNamespace.bytesToIPv4;
  bytesToIPv6: typeof UtilNamespace.bytesToIPv6;
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

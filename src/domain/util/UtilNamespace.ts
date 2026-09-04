import {ByteStringBuffer} from '../buffer/ByteStringBuffer.js';
import {DataBuffer} from '../buffer/DataBuffer.js';
import {Base58Codec} from '../encoding/Base58Codec.js';
import {Base64Codec} from '../encoding/Base64Codec.js';
import {HexCodec} from '../encoding/HexCodec.js';
import {RawCodec} from '../encoding/RawCodec.js';
import {Utf16Codec, Utf8TextCodec} from '../encoding/Utf16Codec.js';
import {encodeUtf8, decodeUtf8} from '../encoding/Utf8Codec.js';
import {EnvInfo} from '../../infrastructure/env/EnvInfo.js';
import {isArray, isArrayBuffer, isArrayBufferView} from './typeChecks.js';

type BaseNModule = {
  encode: (input: Uint8Array | {length(): number; at(i: number): number}, alphabet: string, maxline?: number) => string;
  decode: (input: string, alphabet: string) => Buffer | Uint8Array | undefined;
};

/** Flat util namespace shape matching legacy certkit.util API. */
export type UtilNamespaceObject = Record<string, unknown> & {
  ByteBuffer: typeof ByteStringBuffer;
  ByteStringBuffer: typeof ByteStringBuffer;
  DataBuffer: typeof DataBuffer;
  binary: {
    raw: {encode: typeof RawCodec.encode; decode: typeof RawCodec.decode};
    hex: {encode: (bytes: Uint8Array | string) => string; decode: typeof HexCodec.decode};
    base64: {encode: typeof Base64Codec.encode; decode: typeof Base64Codec.decode};
    base58: {encode: typeof Base58Codec.encode; decode: typeof Base58Codec.decode};
    baseN: BaseNModule;
  };
  text: {
    utf8: {encode: typeof Utf8TextCodec.encode; decode: typeof Utf8TextCodec.decode};
    utf16: {encode: typeof Utf16Codec.encode; decode: typeof Utf16Codec.decode};
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
    options: {update?: boolean} | ((err: null, cores: number) => void),
    callback?: (err: null, cores: number) => void
  ) => void;
  cores?: number;
};

export class UtilNamespace {
  static isArray = isArray;

  static isArrayBuffer = isArrayBuffer;

  static isArrayBufferView = isArrayBufferView;

  static createBuffer(input?: unknown, encoding?: string): ByteStringBuffer {
    encoding = encoding || 'raw';
    if (input !== undefined && encoding === 'utf8') {
      input = encodeUtf8(input as string);
    }
    return new ByteStringBuffer(input as ConstructorParameters<typeof ByteStringBuffer>[0]);
  }

  static fillString(c: string, n: number): string {
    let s = '';
    while (n > 0) {
      if (n & 1) {
        s += c;
      }
      n >>>= 1;
      if (n > 0) {
        c += c;
      }
    }
    return s;
  }

  static xorBytes(s1: string, s2: string, n: number): string {
    let s3 = '';
    let b = '';
    let t = '';
    let i = 0;
    let c = 0;
    for (; n > 0; --n, ++i) {
      b = String.fromCharCode(s1.charCodeAt(i) ^ s2.charCodeAt(i));
      if (c >= 10) {
        s3 += t;
        t = '';
        c = 0;
      }
      t += b;
      ++c;
    }
    s3 += t;
    return s3;
  }

  static hexToBytes(hex: string): string {
    return HexCodec.decodeToString(hex);
  }

  static bytesToHex(bytes: string): string {
    return UtilNamespace.createBuffer(bytes).toHex();
  }

  static int32ToBytes(i: number): string {
    return (
      String.fromCharCode(i >> 24 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF));
  }

  static encode64(input: string, maxline?: number): string {
    return Base64Codec.encodeString(input, maxline);
  }

  static decode64(input: string): string {
    return Base64Codec.decodeString(input);
  }

  static encodeUtf8 = encodeUtf8;

  static decodeUtf8 = decodeUtf8;

  static isEmpty(obj: object): boolean {
    for (const prop in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, prop)) {
        return false;
      }
    }
    return true;
  }

  static format(format: string, ...args: unknown[]): string {
    const re = /%./g;
    let match: RegExpExecArray | null;
    let part: string;
    let argi = 0;
    const parts: string[] = [];
    let last = 0;
    while ((match = re.exec(format))) {
      part = format.substring(last, re.lastIndex - 2);
      if (part.length > 0) {
        parts.push(part);
      }
      last = re.lastIndex;
      const code = match[0][1]!;
      switch (code) {
      case 's':
      case 'o':
        if (argi < args.length) {
          parts.push(String(args[argi++]));
        } else {
          parts.push('<?>');
        }
        break;
      case '%':
        parts.push('%');
        break;
      default:
        parts.push('<%' + code + '?>');
      }
    }
    parts.push(format.substring(last));
    return parts.join('');
  }

  static formatNumber(number: number, decimals?: number, dec_point?: string, thousands_sep?: string): string {
    const n = number;
    const c = isNaN(decimals = Math.abs(decimals!)) ? 2 : decimals!;
    const d = dec_point === undefined ? ',' : dec_point;
    const t = thousands_sep === undefined ? '.' : thousands_sep;
    const s = n < 0 ? '-' : '';
    const i = parseInt(String(Math.abs(+n || 0).toFixed(c)), 10) + '';
    const j = (i.length > 3) ? i.length % 3 : 0;
    return s + (j ? i.substr(0, j) + t : '') +
      i.substr(j).replace(/(\d{3})(?=\d)/g, '$1' + t) +
      (c ? d + Math.abs(n - parseInt(i, 10)).toFixed(c).slice(2) : '');
  }

  static formatSize(size: number): string {
    if (size >= 1073741824) {
      return UtilNamespace.formatNumber(size / 1073741824, 2, '.', '') + ' GiB';
    } else if (size >= 1048576) {
      return UtilNamespace.formatNumber(size / 1048576, 2, '.', '') + ' MiB';
    } else if (size >= 1024) {
      return UtilNamespace.formatNumber(size / 1024, 0) + ' KiB';
    } else {
      return UtilNamespace.formatNumber(size, 0) + ' bytes';
    }
  }

  static bytesFromIP(ip: string): string | null {
    if (ip.indexOf('.') !== -1) {
      return UtilNamespace.bytesFromIPv4(ip);
    }
    if (ip.indexOf(':') !== -1) {
      return UtilNamespace.bytesFromIPv6(ip);
    }
    return null;
  }

  static bytesFromIPv4(ip: string): string | null {
    const parts = ip.split('.');
    if (parts.length !== 4) {
      return null;
    }
    const b = UtilNamespace.createBuffer();
    for (let i = 0; i < parts.length; ++i) {
      const num = parseInt(parts[i]!, 10);
      if (isNaN(num)) {
        return null;
      }
      b.putByte(num);
    }
    return b.getBytes();
  }

  static bytesFromIPv6(ip: string): string | null {
    let blanks = 0;
    const segments = ip.split(':').filter(function(e) {
      if (e.length === 0) {
        ++blanks;
      }
      return true;
    });
    let zeros = (8 - segments.length + blanks) * 2;
    const b = UtilNamespace.createBuffer();
    for (let i = 0; i < 8; ++i) {
      if (!segments[i] || segments[i]!.length === 0) {
        b.fillWithByte(0, zeros);
        zeros = 0;
        continue;
      }
      const bytes = UtilNamespace.hexToBytes(segments[i]!);
      if (bytes.length < 2) {
        b.putByte(0);
      }
      b.putBytes(bytes);
    }
    return b.getBytes();
  }

  static bytesToIP(bytes: string): string | null {
    if (bytes.length === 4) {
      return UtilNamespace.bytesToIPv4(bytes);
    }
    if (bytes.length === 16) {
      return UtilNamespace.bytesToIPv6(bytes);
    }
    return null;
  }

  static bytesToIPv4(bytes: string): string | null {
    if (bytes.length !== 4) {
      return null;
    }
    const ip: number[] = [];
    for (let i = 0; i < bytes.length; ++i) {
      ip.push(bytes.charCodeAt(i));
    }
    return ip.join('.');
  }

  static bytesToIPv6(bytes: string): string | null {
    if (bytes.length !== 16) {
      return null;
    }
    const ip: string[] = [];
    const zeroGroups: {start: number; end: number}[] = [];
    let zeroMaxGroup = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      let hex = UtilNamespace.bytesToHex(bytes[i]! + bytes[i + 1]!);
      while (hex[0] === '0' && hex !== '0') {
        hex = hex.substr(1);
      }
      if (hex === '0') {
        const last = zeroGroups[zeroGroups.length - 1];
        const idx = ip.length;
        if (!last || idx !== last.end + 1) {
          zeroGroups.push({start: idx, end: idx});
        } else {
          last.end = idx;
          if ((last.end - last.start) >
            (zeroGroups[zeroMaxGroup]!.end - zeroGroups[zeroMaxGroup]!.start)) {
            zeroMaxGroup = zeroGroups.length - 1;
          }
        }
      }
      ip.push(hex);
    }
    if (zeroGroups.length > 0) {
      const group = zeroGroups[zeroMaxGroup]!;
      if (group.end - group.start > 0) {
        ip.splice(group.start, group.end - group.start + 1, '');
        if (group.start === 0) {
          ip.unshift('');
        }
        if (group.end === 7) {
          ip.push('');
        }
      }
    }
    return ip.join(':');
  }
}

/**
 * Builds a flat certkit.util namespace object with all legacy aliases preserved.
 */
export function createUtilNamespace(baseN: BaseNModule): UtilNamespaceObject {
  const ns = {} as UtilNamespaceObject;

  ns.isArray = UtilNamespace.isArray;
  ns.isArrayBuffer = UtilNamespace.isArrayBuffer;
  ns.isArrayBufferView = UtilNamespace.isArrayBufferView;
  ns.createBuffer = function(input?: unknown, encoding?: string) {
    return UtilNamespace.createBuffer(input, encoding);
  };
  ns.fillString = UtilNamespace.fillString.bind(UtilNamespace);
  ns.xorBytes = UtilNamespace.xorBytes.bind(UtilNamespace);
  ns.hexToBytes = UtilNamespace.hexToBytes.bind(UtilNamespace);
  ns.bytesToHex = UtilNamespace.bytesToHex.bind(UtilNamespace);
  ns.int32ToBytes = UtilNamespace.int32ToBytes.bind(UtilNamespace);
  ns.encode64 = UtilNamespace.encode64.bind(UtilNamespace);
  ns.decode64 = UtilNamespace.decode64.bind(UtilNamespace);
  ns.encodeUtf8 = encodeUtf8;
  ns.decodeUtf8 = decodeUtf8;
  ns.isEmpty = UtilNamespace.isEmpty.bind(UtilNamespace);
  ns.format = UtilNamespace.format.bind(UtilNamespace);
  ns.formatNumber = UtilNamespace.formatNumber.bind(UtilNamespace);
  ns.formatSize = UtilNamespace.formatSize.bind(UtilNamespace);
  ns.bytesFromIP = UtilNamespace.bytesFromIP.bind(UtilNamespace);
  ns.bytesFromIPv4 = UtilNamespace.bytesFromIPv4.bind(UtilNamespace);
  ns.bytesFromIPv6 = UtilNamespace.bytesFromIPv6.bind(UtilNamespace);
  ns.bytesToIP = UtilNamespace.bytesToIP.bind(UtilNamespace);
  ns.bytesToIPv4 = UtilNamespace.bytesToIPv4.bind(UtilNamespace);
  ns.bytesToIPv6 = UtilNamespace.bytesToIPv6.bind(UtilNamespace);

  ns.nextTick = EnvInfo.nextTick;
  ns.setImmediate = EnvInfo.setImmediate;
  ns.isNodejs = EnvInfo.isNodejs;
  ns.globalScope = EnvInfo.globalScope;
  ns.estimateCores = function(
    options: Parameters<typeof EnvInfo.estimateCores>[1],
    callback?: Parameters<typeof EnvInfo.estimateCores>[2]
  ) {
    return EnvInfo.estimateCores(ns, options, callback);
  };

  ns.ByteStringBuffer = ByteStringBuffer;
  ns.DataBuffer = DataBuffer;
  ns.ByteBuffer = ByteStringBuffer;

  ns.binary = {
    raw: {
      encode: RawCodec.encode,
      decode: RawCodec.decode
    },
    hex: {
      encode: ns.bytesToHex as (bytes: Uint8Array | string) => string,
      decode: HexCodec.decode
    },
    base64: {
      encode: Base64Codec.encode,
      decode: Base64Codec.decode
    },
    base58: {
      encode: Base58Codec.encode,
      decode: Base58Codec.decode
    },
    baseN: {
      encode: baseN.encode,
      decode: baseN.decode
    }
  };

  ns.text = {
    utf8: {
      encode: Utf8TextCodec.encode,
      decode: Utf8TextCodec.decode
    },
    utf16: {
      encode: Utf16Codec.encode,
      decode: Utf16Codec.decode
    }
  };

  return ns;
}

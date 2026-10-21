import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { DataBuffer } from '../buffer/DataBuffer.js';
import { Base58Codec } from '../encoding/Base58Codec.js';
import { Base64Codec } from '../encoding/Base64Codec.js';
import { HexCodec } from '../encoding/HexCodec.js';
import { RawCodec } from '../encoding/RawCodec.js';
import { Utf16Codec, Utf8TextCodec } from '../encoding/Utf16Codec.js';
import { encodeUtf8, decodeUtf8 } from '../encoding/Utf8Codec.js';
import { EnvInfo } from '../../infrastructure/env/EnvInfo.js';
import { isArray, isArrayBuffer, isArrayBufferView } from './typeChecks.js';
import type { UtilNamespaceObject } from './UtilTypes.js';

type BaseNModule = {
  encode: (
    input: Uint8Array | { length(): number; at(i: number): number },
    alphabet: string,
    maxline?: number
  ) => string;
  decode: (input: string, alphabet: string) => Uint8Array | undefined;
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

  static fillString(fillChar: string, repeatCount: number): string {
    let result = '';
    while (repeatCount > 0) {
      if (repeatCount & 1) {
        result += fillChar;
      }
      repeatCount >>>= 1;
      if (repeatCount > 0) {
        fillChar += fillChar;
      }
    }
    return result;
  }

  static xorBytes(firstBytes: string, secondBytes: string, byteCount: number): string {
    let xorResult = '';
    let xorByte: string;
    let chunk = '';
    let index = 0;
    let chunkLength = 0;
    for (; byteCount > 0; --byteCount, ++index) {
      xorByte = String.fromCharCode(firstBytes.charCodeAt(index) ^ secondBytes.charCodeAt(index));
      if (chunkLength >= 10) {
        xorResult += chunk;
        chunk = '';
        chunkLength = 0;
      }
      chunk += xorByte;
      ++chunkLength;
    }
    xorResult += chunk;
    return xorResult;
  }

  static hexToBytes(hex: string): string {
    return HexCodec.decodeToString(hex);
  }

  static bytesToHex(bytes: string): string {
    return UtilNamespace.createBuffer(bytes).toHex();
  }

  static int32ToBytes(i: number): string {
    return (
      String.fromCharCode((i >> 24) & 0xff) +
      String.fromCharCode((i >> 16) & 0xff) +
      String.fromCharCode((i >> 8) & 0xff) +
      String.fromCharCode(i & 0xff)
    );
  }

  static encode64(input: string, maxline?: number): string {
    return Base64Codec.encodeString(input, maxline);
  }

  static decode64(input: string): string {
    return Base64Codec.decodeString(input);
  }

  static encodeUtf8 = encodeUtf8;

  static decodeUtf8 = decodeUtf8;

  static isEmpty(record: object): boolean {
    for (const prop in record) {
      if (Object.prototype.hasOwnProperty.call(record, prop)) {
        return false;
      }
    }
    return true;
  }

  static format(format: string, ...args: unknown[]): string {
    const formatPattern = /%./g;
    let match: RegExpExecArray | null;
    let part: string;
    let argi = 0;
    const parts: string[] = [];
    let last = 0;
    while ((match = formatPattern.exec(format))) {
      part = format.substring(last, formatPattern.lastIndex - 2);
      if (part.length > 0) {
        parts.push(part);
      }
      last = formatPattern.lastIndex;
      const code = match[0][1];
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

  static formatNumber(number: number, decimals?: number, decimalPoint?: string, thousandsSeparator?: string): string {
    const num = number;
    const fractionDigits = isNaN((decimals = Math.abs(decimals!))) ? 2 : decimals;
    const decimalSep = decimalPoint === undefined ? ',' : decimalPoint;
    const thousandsSep = thousandsSeparator === undefined ? '.' : thousandsSeparator;
    const signPrefix = num < 0 ? '-' : '';
    const integerPart = parseInt(String(Math.abs(+num || 0).toFixed(fractionDigits)), 10) + '';
    const headLength = integerPart.length > 3 ? integerPart.length % 3 : 0;
    return (
      signPrefix +
      (headLength ? integerPart.substr(0, headLength) + thousandsSep : '') +
      integerPart.substr(headLength).replace(/(\d{3})(?=\d)/g, '$1' + thousandsSep) +
      (fractionDigits
        ? decimalSep +
          Math.abs(num - parseInt(integerPart, 10))
            .toFixed(fractionDigits)
            .slice(2)
        : '')
    );
  }

  static formatSize(size: number): string {
    const KIBIBYTE = 1024;
    const MEBIBYTE = 1048576;
    const GIBIBYTE = 1073741824;
    if (size >= GIBIBYTE) {
      return UtilNamespace.formatNumber(size / GIBIBYTE, 2, '.', '') + ' GiB';
    } else if (size >= MEBIBYTE) {
      return UtilNamespace.formatNumber(size / MEBIBYTE, 2, '.', '') + ' MiB';
    } else if (size >= KIBIBYTE) {
      return UtilNamespace.formatNumber(size / KIBIBYTE, 0) + ' KiB';
    } else {
      return UtilNamespace.formatNumber(size, 0) + ' bytes';
    }
  }

  static bytesFromIP(ipAddress: string): string | null {
    if (ipAddress.indexOf('.') !== -1) {
      return UtilNamespace.bytesFromIPv4(ipAddress);
    }
    if (ipAddress.indexOf(':') !== -1) {
      return UtilNamespace.bytesFromIPv6(ipAddress);
    }
    return null;
  }

  static bytesFromIPv4(ipAddress: string): string | null {
    const parts = ipAddress.split('.');
    if (parts.length !== 4) {
      return null;
    }
    const buffer = UtilNamespace.createBuffer();
    for (let i = 0; i < parts.length; ++i) {
      const num = parseInt(parts[i], 10);
      if (isNaN(num)) {
        return null;
      }
      buffer.putByte(num);
    }
    return buffer.getBytes();
  }

  static bytesFromIPv6(ipAddress: string): string | null {
    let blanks = 0;
    const segments = ipAddress.split(':').filter(function (segment) {
      if (segment.length === 0) {
        ++blanks;
      }
      return true;
    });
    let zeros = (8 - segments.length + blanks) * 2;
    const buffer = UtilNamespace.createBuffer();
    for (let i = 0; i < 8; ++i) {
      if (!segments[i] || segments[i].length === 0) {
        buffer.fillWithByte(0, zeros);
        zeros = 0;
        continue;
      }
      const bytes = UtilNamespace.hexToBytes(segments[i]);
      if (bytes.length < 2) {
        buffer.putByte(0);
      }
      buffer.putBytes(bytes);
    }
    return buffer.getBytes();
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
    const octets: number[] = [];
    for (let i = 0; i < bytes.length; ++i) {
      octets.push(bytes.charCodeAt(i));
    }
    return octets.join('.');
  }

  static bytesToIPv6(bytes: string): string | null {
    if (bytes.length !== 16) {
      return null;
    }
    const hextets: string[] = [];
    const zeroGroups: { start: number; end: number }[] = [];
    let zeroMaxGroup = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      let hex = UtilNamespace.bytesToHex(bytes[i] + bytes[i + 1]);
      while (hex[0] === '0' && hex !== '0') {
        hex = hex.substr(1);
      }
      if (hex === '0') {
        const last = zeroGroups[zeroGroups.length - 1];
        const idx = hextets.length;
        if (!last || idx !== last.end + 1) {
          zeroGroups.push({ start: idx, end: idx });
        } else {
          last.end = idx;
          if (last.end - last.start > zeroGroups[zeroMaxGroup].end - zeroGroups[zeroMaxGroup].start) {
            zeroMaxGroup = zeroGroups.length - 1;
          }
        }
      }
      hextets.push(hex);
    }
    if (zeroGroups.length > 0) {
      const group = zeroGroups[zeroMaxGroup];
      if (group.end - group.start > 0) {
        hextets.splice(group.start, group.end - group.start + 1, '');
        if (group.start === 0) {
          hextets.unshift('');
        }
        if (group.end === 7) {
          hextets.push('');
        }
      }
    }
    return hextets.join(':');
  }
}

/**
 * Builds a flat certkit.util namespace object with all legacy aliases preserved.
 */
export function createUtilNamespace(baseN: BaseNModule): UtilNamespaceObject {
  const utilNamespace = {} as UtilNamespaceObject;

  utilNamespace.isArray = UtilNamespace.isArray;
  utilNamespace.isArrayBuffer = UtilNamespace.isArrayBuffer;
  utilNamespace.isArrayBufferView = UtilNamespace.isArrayBufferView;
  utilNamespace.createBuffer = function (input?: unknown, encoding?: string) {
    return UtilNamespace.createBuffer(input, encoding);
  };
  utilNamespace.fillString = UtilNamespace.fillString.bind(UtilNamespace);
  utilNamespace.xorBytes = UtilNamespace.xorBytes.bind(UtilNamespace);
  utilNamespace.hexToBytes = UtilNamespace.hexToBytes.bind(UtilNamespace);
  utilNamespace.bytesToHex = UtilNamespace.bytesToHex.bind(UtilNamespace);
  utilNamespace.int32ToBytes = UtilNamespace.int32ToBytes.bind(UtilNamespace);
  utilNamespace.encode64 = UtilNamespace.encode64.bind(UtilNamespace);
  utilNamespace.decode64 = UtilNamespace.decode64.bind(UtilNamespace);
  utilNamespace.encodeUtf8 = encodeUtf8;
  utilNamespace.decodeUtf8 = decodeUtf8;
  utilNamespace.isEmpty = UtilNamespace.isEmpty.bind(UtilNamespace);
  utilNamespace.format = UtilNamespace.format.bind(UtilNamespace);
  utilNamespace.formatNumber = UtilNamespace.formatNumber.bind(UtilNamespace);
  utilNamespace.formatSize = UtilNamespace.formatSize.bind(UtilNamespace);
  utilNamespace.bytesFromIP = UtilNamespace.bytesFromIP.bind(UtilNamespace);
  utilNamespace.bytesFromIPv4 = UtilNamespace.bytesFromIPv4.bind(UtilNamespace);
  utilNamespace.bytesFromIPv6 = UtilNamespace.bytesFromIPv6.bind(UtilNamespace);
  utilNamespace.bytesToIP = UtilNamespace.bytesToIP.bind(UtilNamespace);
  utilNamespace.bytesToIPv4 = UtilNamespace.bytesToIPv4.bind(UtilNamespace);
  utilNamespace.bytesToIPv6 = UtilNamespace.bytesToIPv6.bind(UtilNamespace);

  utilNamespace.nextTick = EnvInfo.nextTick;
  utilNamespace.setImmediate = EnvInfo.setImmediate;
  utilNamespace.isNodejs = EnvInfo.isNodejs;
  utilNamespace.globalScope = EnvInfo.globalScope;
  utilNamespace.estimateCores = function (
    options: Parameters<typeof EnvInfo.estimateCores>[1],
    callback?: Parameters<typeof EnvInfo.estimateCores>[2]
  ) {
    return EnvInfo.estimateCores(utilNamespace, options, callback);
  };

  utilNamespace.ByteStringBuffer = ByteStringBuffer;
  utilNamespace.DataBuffer = DataBuffer;
  utilNamespace.ByteBuffer = ByteStringBuffer;

  utilNamespace.binary = {
    raw: {
      encode: function (bytes: Uint8Array | { length(): number; at(i: number): number }) {
        return RawCodec.encode(bytes as Uint8Array);
      },
      decode: function (bytes: Uint8Array, output?: Uint8Array, offset?: number) {
        return output === undefined ? RawCodec.decode(bytes) : RawCodec.decode(bytes, output, offset);
      }
    },
    hex: {
      encode: function (bytes: Uint8Array | string) {
        return typeof bytes === 'string' ? utilNamespace.bytesToHex(bytes) : HexCodec.encode(bytes);
      },
      decode: function (hex: string, output?: Uint8Array, offset?: number) {
        return output === undefined ? HexCodec.decode(hex) : HexCodec.decode(hex, output, offset);
      }
    },
    base64: {
      encode: function (input: Uint8Array | { length(): number; at(i: number): number }, maxline?: number) {
        return Base64Codec.encode(input as Uint8Array, maxline);
      },
      decode: function (input: string, output?: Uint8Array, offset?: number) {
        return output === undefined ? Base64Codec.decode(input) : Base64Codec.decode(input, output, offset);
      }
    },
    base58: {
      encode: function (input: Uint8Array | { length(): number; at(i: number): number }, maxline?: number) {
        return Base58Codec.encode(input, maxline);
      },
      decode: function (input: string, maxline?: number) {
        return Base58Codec.decode(input, maxline);
      }
    },
    baseN: {
      encode: function (
        input: Uint8Array | { length(): number; at(i: number): number },
        alphabet: string,
        maxline?: number
      ) {
        return baseN.encode(input, alphabet, maxline);
      },
      decode: function (input: string, alphabet: string) {
        return baseN.decode(input, alphabet);
      }
    }
  } as UtilNamespaceObject['binary'];

  utilNamespace.text = {
    utf8: {
      encode: function (input: string, output?: Uint8Array, offset?: number) {
        return Utf8TextCodec.encode(input, output, offset);
      },
      decode: function (bytes: Uint8Array) {
        return Utf8TextCodec.decode(bytes);
      }
    },
    utf16: {
      encode: function (input: string, output?: Uint16Array, offset?: number) {
        return Utf16Codec.encode(input, output as unknown as Uint8Array, offset);
      },
      decode: function (bytes: Uint8Array) {
        return Utf16Codec.decode(bytes);
      }
    }
  };

  return utilNamespace;
}

import {encodeUtf8, decodeUtf8} from './Utf8Codec.js';

export class Utf16Codec {
  static encode(str: string, output?: Uint8Array, offset?: number): Uint8Array | number {
    let out = output;
    if (!out) {
      out = new Uint8Array(str.length * 2);
    }
    const view = new Uint16Array(out.buffer);
    const off = offset || 0;
    let j = off;
    let k = off;
    for (let i = 0; i < str.length; ++i) {
      view[k++] = str.charCodeAt(i);
      j += 2;
    }
    return output ? (j - off) : out;
  }

  static decode(bytes: Uint8Array): string {
    return String.fromCharCode.apply(null, Array.from(new Uint16Array(bytes.buffer)));
  }
}

export class Utf8TextCodec {
  static encode(str: string, output?: Uint8Array, offset?: number): Uint8Array | number {
    const encoded = encodeUtf8(str);
    let out = output;
    if (!out) {
      out = new Uint8Array(encoded.length);
    }
    const off = offset || 0;
    let j = off;
    for (let i = 0; i < encoded.length; ++i) {
      out[j++] = encoded.charCodeAt(i);
    }
    return output ? (j - off) : out;
  }

  static decode(bytes: Uint8Array): string {
    return decodeUtf8(String.fromCharCode.apply(null, Array.from(bytes)));
  }
}

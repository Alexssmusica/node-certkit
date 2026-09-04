import {checkBitsParam} from './checkBitsParam.js';
import {ByteStringBuffer} from './ByteStringBuffer.js';
import {isArrayBuffer, isArrayBufferView} from '../util/typeChecks.js';
import {Base64Codec} from '../encoding/Base64Codec.js';
import {HexCodec} from '../encoding/HexCodec.js';
import {RawCodec} from '../encoding/RawCodec.js';
import {Utf16Codec, Utf8TextCodec} from '../encoding/Utf16Codec.js';
import {encodeUtf8} from '../encoding/Utf8Codec.js';

export interface DataBufferOptions {
  readOffset?: number;
  writeOffset?: number;
  growSize?: number;
  encoding?: string;
}

type DataBufferInput =
  | string
  | ArrayBuffer
  | ArrayBufferView
  | ByteStringBuffer
  | DataBuffer
  | {read: number; write: number; data: DataView}
  | null
  | undefined;

/**
 * FIXME: Experimental. Do not use yet.
 *
 * Constructor for an ArrayBuffer-backed byte buffer.
 */
type DataViewWithSlice = DataView & {
  slice(start?: number, end?: number): DataView;
};

export class DataBuffer {
  data: DataView;
  read: number;
  write: number;
  growSize: number;

  constructor(b?: DataBufferInput, options?: DataBufferOptions) {
    const opts = options || {};

    this.read = opts.readOffset || 0;
    this.growSize = opts.growSize || 1024;

    const isAB = isArrayBuffer(b);
    const isABV = isArrayBufferView(b);
    if (isAB || isABV) {
      if (isAB) {
        this.data = new DataView(b as ArrayBuffer);
      } else {
        const view = b as ArrayBufferView;
        this.data = new DataView(view.buffer, view.byteOffset, view.byteLength);
      }
      this.write = ('writeOffset' in opts ?
        opts.writeOffset! : this.data.byteLength);
      return;
    }

    this.data = new DataView(new ArrayBuffer(0));
    this.write = 0;

    if (b !== null && b !== undefined) {
      this.putBytes(b as string);
    }

    if ('writeOffset' in opts) {
      this.write = opts.writeOffset!;
    }
  }

  length(): number {
    return this.write - this.read;
  }

  isEmpty(): boolean {
    return this.length() <= 0;
  }

  accommodate(amount: number, growSize?: number): this {
    if (this.length() >= amount) {
      return this;
    }
    const grow = Math.max(growSize || this.growSize, amount);

    const src = new Uint8Array(
      this.data.buffer, this.data.byteOffset, this.data.byteLength);
    const dst = new Uint8Array(this.length() + grow);
    dst.set(src);
    this.data = new DataView(dst.buffer);

    return this;
  }

  putByte(b: number): this {
    this.accommodate(1);
    this.data.setUint8(this.write++, b);
    return this;
  }

  fillWithByte(b: number, n: number): this {
    this.accommodate(n);
    for (let i = 0; i < n; ++i) {
      (this.data as unknown as {setUint8(byte: number): void}).setUint8(b);
    }
    return this;
  }

  putBytes(bytes: DataBufferInput, encoding?: string): this {
    if (isArrayBufferView(bytes)) {
      const view = bytes as ArrayBufferView;
      const src = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const len = src.byteLength - src.byteOffset;
      this.accommodate(len);
      const dst = new Uint8Array(this.data.buffer, this.write);
      dst.set(src);
      this.write += len;
      return this;
    }

    if (isArrayBuffer(bytes)) {
      const src = new Uint8Array(bytes as ArrayBuffer);
      this.accommodate(src.byteLength);
      const dst = new Uint8Array(this.data.buffer);
      dst.set(src, this.write);
      this.write += src.byteLength;
      return this;
    }

    if (bytes instanceof DataBuffer ||
      (typeof bytes === 'object' && bytes !== null &&
        typeof (bytes as DataBuffer).read === 'number' &&
        typeof (bytes as DataBuffer).write === 'number' &&
        isArrayBufferView((bytes as DataBuffer).data))) {
      const buf = bytes as DataBuffer;
      const src = new (Uint8Array as unknown as {
        new (length: number, offset: number, len: number): Uint8Array;
      })(buf.data.byteLength, buf.read, buf.length());
      this.accommodate(src.byteLength);
      const dst = new (Uint8Array as unknown as {
        new (length: number, offset: number): Uint8Array;
      })(buf.data.byteLength, this.write);
      dst.set(src);
      this.write += src.byteLength;
      return this;
    }

    if (bytes instanceof ByteStringBuffer) {
      bytes = bytes.data;
      encoding = 'binary';
    }

    encoding = encoding || 'binary';
    if (typeof bytes === 'string') {
      let view: Uint8Array;

      if (encoding === 'hex') {
        this.accommodate(Math.ceil(bytes.length / 2));
        view = new Uint8Array(this.data.buffer, this.write);
        this.write += HexCodec.decode(bytes, view, this.write) as number;
        return this;
      }
      if (encoding === 'base64') {
        this.accommodate(Math.ceil(bytes.length / 4) * 3);
        view = new Uint8Array(this.data.buffer, this.write);
        this.write += Base64Codec.decode(bytes, view, this.write) as number;
        return this;
      }

      if (encoding === 'utf8') {
        bytes = encodeUtf8(bytes);
        encoding = 'binary';
      }

      if (encoding === 'binary' || encoding === 'raw') {
        this.accommodate(bytes.length);
        view = new Uint8Array(this.data.buffer, this.write);
        this.write += RawCodec.decode(view as unknown as string, view, this.write) as number;
        return this;
      }

      if (encoding === 'utf16') {
        this.accommodate(bytes.length * 2);
        const view16 = new Uint16Array(this.data.buffer, this.write);
        this.write += Utf16Codec.encode(view16 as unknown as string, view16 as unknown as Uint8Array) as number;
        return this;
      }

      throw new Error('Invalid encoding: ' + encoding);
    }

    throw Error('Invalid parameter: ' + bytes);
  }

  putBuffer(buffer: DataBuffer): this {
    this.putBytes(buffer);
    buffer.clear();
    return this;
  }

  putString(str: string): this {
    return this.putBytes(str, 'utf16');
  }

  putInt16(i: number): this {
    this.accommodate(2);
    this.data.setInt16(this.write, i);
    this.write += 2;
    return this;
  }

  putInt24(i: number): this {
    this.accommodate(3);
    this.data.setInt16(this.write, i >> 8 & 0xFFFF);
    this.data.setInt8(this.write, i >> 16 & 0xFF);
    this.write += 3;
    return this;
  }

  putInt32(i: number): this {
    this.accommodate(4);
    this.data.setInt32(this.write, i);
    this.write += 4;
    return this;
  }

  putInt16Le(i: number): this {
    this.accommodate(2);
    this.data.setInt16(this.write, i, true);
    this.write += 2;
    return this;
  }

  putInt24Le(i: number): this {
    this.accommodate(3);
    this.data.setInt8(this.write, i >> 16 & 0xFF);
    this.data.setInt16(this.write, i >> 8 & 0xFFFF, true);
    this.write += 3;
    return this;
  }

  putInt32Le(i: number): this {
    this.accommodate(4);
    this.data.setInt32(this.write, i, true);
    this.write += 4;
    return this;
  }

  putInt(i: number, n: number): this {
    checkBitsParam(n);
    this.accommodate(n / 8);
    do {
      n -= 8;
      this.data.setInt8(this.write++, (i >> n) & 0xFF);
    } while (n > 0);
    return this;
  }

  putSignedInt(i: number, n: number): this {
    checkBitsParam(n);
    this.accommodate(n / 8);
    if (i < 0) {
      i += 2 << (n - 1);
    }
    return this.putInt(i, n);
  }

  getByte(): number {
    return this.data.getInt8(this.read++);
  }

  getInt16(): number {
    const rval = this.data.getInt16(this.read);
    this.read += 2;
    return rval;
  }

  getInt24(): number {
    const rval = (
      this.data.getInt16(this.read) << 8 ^
      this.data.getInt8(this.read + 2));
    this.read += 3;
    return rval;
  }

  getInt32(): number {
    const rval = this.data.getInt32(this.read);
    this.read += 4;
    return rval;
  }

  getInt16Le(): number {
    const rval = this.data.getInt16(this.read, true);
    this.read += 2;
    return rval;
  }

  getInt24Le(): number {
    const rval = (
      this.data.getInt8(this.read) ^
      this.data.getInt16(this.read + 1, true) << 8);
    this.read += 3;
    return rval;
  }

  getInt32Le(): number {
    const rval = this.data.getInt32(this.read, true);
    this.read += 4;
    return rval;
  }

  getInt(n: number): number {
    checkBitsParam(n);
    let rval = 0;
    do {
      rval = (rval << 8) + this.data.getInt8(this.read++);
      n -= 8;
    } while (n > 0);
    return rval;
  }

  getSignedInt(n: number): number {
    let x = this.getInt(n);
    const max = 2 << (n - 2);
    if (x >= max) {
      x -= max << 1;
    }
    return x;
  }

  getBytes(count?: number | null): DataView | string {
    const data = this.data as DataViewWithSlice;
    let rval: DataView | string;
    if (count) {
      count = Math.min(this.length(), count);
      rval = data.slice(this.read, this.read + count);
      this.read += count;
    } else if (count === 0) {
      rval = '';
    } else {
      rval = (this.read === 0) ? data : data.slice(this.read);
      this.clear();
    }
    return rval;
  }

  bytes(count?: number): DataView {
    const data = this.data as DataViewWithSlice;
    return (typeof count === 'undefined' ?
      data.slice(this.read) :
      data.slice(this.read, this.read + count));
  }

  at(i: number): number {
    return this.data.getUint8(this.read + i);
  }

  setAt(i: number, b: number): this {
    this.data.setUint8(i, b);
    return this;
  }

  last(): number {
    return this.data.getUint8(this.write - 1);
  }

  copy(): DataBuffer {
    return new DataBuffer(this);
  }

  compact(): this {
    if (this.read > 0) {
      const src = new Uint8Array(this.data.buffer, this.read);
      const dst = new Uint8Array(src.byteLength);
      dst.set(src);
      this.data = new DataView(dst.buffer as ArrayBuffer);
      this.write -= this.read;
      this.read = 0;
    }
    return this;
  }

  clear(): this {
    this.data = new DataView(new ArrayBuffer(0));
    this.read = this.write = 0;
    return this;
  }

  truncate(count: number): this {
    this.write = Math.max(0, this.length() - count);
    this.read = Math.min(this.read, this.write);
    return this;
  }

  toHex(): string {
    let rval = '';
    for (let i = this.read; i < this.data.byteLength; ++i) {
      const b = this.data.getUint8(i);
      if (b < 16) {
        rval += '0';
      }
      rval += b.toString(16);
    }
    return rval;
  }

  toString(encoding?: string): string {
    const view = new Uint8Array(this.data.buffer, this.data.byteOffset + this.read, this.length());
    encoding = encoding || 'utf8';

    if (encoding === 'binary' || encoding === 'raw') {
      return RawCodec.encode(view);
    }
    if (encoding === 'hex') {
      return HexCodec.encode(view);
    }
    if (encoding === 'base64') {
      return Base64Codec.encode(view);
    }

    if (encoding === 'utf8') {
      return Utf8TextCodec.decode(view);
    }
    if (encoding === 'utf16') {
      return Utf16Codec.decode(view);
    }

    throw new Error('Invalid encoding: ' + encoding);
  }
}

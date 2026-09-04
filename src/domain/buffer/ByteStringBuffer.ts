import { checkBitsParam } from './checkBitsParam.js';
import { isArrayBuffer, isArrayBufferView } from '../util/typeChecks.js';
import { decodeUtf8, encodeUtf8 } from '../encoding/Utf8Codec.js';

const MAX_CONSTRUCTED_STRING_LENGTH = 4096;

export type ByteStringBufferInput =
  string | ArrayBuffer | ArrayBufferView | Buffer | ByteStringBuffer | { data: string; read: number };

/**
 * Constructor for a binary string backed byte buffer.
 */
export class ByteStringBuffer {
  data: string;
  read: number;
  _constructedStringLength: number;
  /** When true, reads past the end throw instead of returning stale values. */
  strictReads: boolean;

  constructor(b?: ByteStringBufferInput | null) {
    this.data = '';
    this.read = 0;
    this._constructedStringLength = 0;
    this.strictReads = false;

    if (typeof b === 'string') {
      this.data = b;
    } else if (isArrayBuffer(b) || isArrayBufferView(b)) {
      if (typeof Buffer !== 'undefined' && b instanceof Buffer) {
        this.data = b.toString('binary');
      } else {
        const arr = new Uint8Array(b as ArrayBuffer);
        try {
          this.data = String.fromCharCode.apply(null, Array.from(arr));
        } catch {
          for (let i = 0; i < arr.length; ++i) {
            this.putByte(arr[i]!);
          }
        }
      }
    } else if (
      b instanceof ByteStringBuffer ||
      (typeof b === 'object' && b !== null && typeof b.data === 'string' && typeof b.read === 'number')
    ) {
      this.data = b.data;
      this.read = b.read;
    }
  }

  _optimizeConstructedString(x: number): void {
    this._constructedStringLength += x;
    if (this._constructedStringLength > MAX_CONSTRUCTED_STRING_LENGTH) {
      this.data.substr(0, 1);
      this._constructedStringLength = 0;
    }
  }

  length(): number {
    return this.data.length - this.read;
  }

  isEmpty(): boolean {
    return this.length() <= 0;
  }

  putByte(b: number): this {
    return this.putBytes(String.fromCharCode(b));
  }

  fillWithByte(b: number, n: number): this {
    let byte = String.fromCharCode(b);
    let d = this.data;
    while (n > 0) {
      if (n & 1) {
        d += byte;
      }
      n >>>= 1;
      if (n > 0) {
        byte += byte;
      }
    }
    this.data = d;
    this._optimizeConstructedString(n);
    return this;
  }

  putBytes(bytes: string): this {
    this.data += bytes;
    this._optimizeConstructedString(bytes.length);
    return this;
  }

  putString(str: string): this {
    return this.putBytes(encodeUtf8(str));
  }

  putInt16(i: number): this {
    return this.putBytes(String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode(i & 0xff));
  }

  putInt24(i: number): this {
    return this.putBytes(
      String.fromCharCode((i >> 16) & 0xff) + String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode(i & 0xff)
    );
  }

  putInt32(i: number): this {
    return this.putBytes(
      String.fromCharCode((i >> 24) & 0xff) +
        String.fromCharCode((i >> 16) & 0xff) +
        String.fromCharCode((i >> 8) & 0xff) +
        String.fromCharCode(i & 0xff)
    );
  }

  putInt16Le(i: number): this {
    return this.putBytes(String.fromCharCode(i & 0xff) + String.fromCharCode((i >> 8) & 0xff));
  }

  putInt24Le(i: number): this {
    return this.putBytes(
      String.fromCharCode(i & 0xff) + String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode((i >> 16) & 0xff)
    );
  }

  putInt32Le(i: number): this {
    return this.putBytes(
      String.fromCharCode(i & 0xff) +
        String.fromCharCode((i >> 8) & 0xff) +
        String.fromCharCode((i >> 16) & 0xff) +
        String.fromCharCode((i >> 24) & 0xff)
    );
  }

  putInt(i: number, n: number): this {
    checkBitsParam(n);
    let bytes = '';
    do {
      n -= 8;
      bytes += String.fromCharCode((i >> n) & 0xff);
    } while (n > 0);
    return this.putBytes(bytes);
  }

  putSignedInt(i: number, n: number): this {
    if (i < 0) {
      i += 2 << (n - 1);
    }
    return this.putInt(i, n);
  }

  putBuffer(buffer: { getBytes(count?: number): string }): this {
    return this.putBytes(buffer.getBytes());
  }

  getByte(): number {
    if (this.strictReads && this.read >= this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    return this.data.charCodeAt(this.read++);
  }

  getInt16(): number {
    if (this.strictReads && this.read + 2 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval = (this.data.charCodeAt(this.read) << 8) ^ this.data.charCodeAt(this.read + 1);
    this.read += 2;
    return rval;
  }

  getInt24(): number {
    if (this.strictReads && this.read + 3 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval =
      (this.data.charCodeAt(this.read) << 16) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      this.data.charCodeAt(this.read + 2);
    this.read += 3;
    return rval;
  }

  getInt32(): number {
    if (this.strictReads && this.read + 4 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval =
      (this.data.charCodeAt(this.read) << 24) ^
      (this.data.charCodeAt(this.read + 1) << 16) ^
      (this.data.charCodeAt(this.read + 2) << 8) ^
      this.data.charCodeAt(this.read + 3);
    this.read += 4;
    return rval;
  }

  getInt16Le(): number {
    if (this.strictReads && this.read + 2 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval = this.data.charCodeAt(this.read) ^ (this.data.charCodeAt(this.read + 1) << 8);
    this.read += 2;
    return rval;
  }

  getInt24Le(): number {
    if (this.strictReads && this.read + 3 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16);
    this.read += 3;
    return rval;
  }

  getInt32Le(): number {
    if (this.strictReads && this.read + 4 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const rval =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16) ^
      (this.data.charCodeAt(this.read + 3) << 24);
    this.read += 4;
    return rval;
  }

  getInt(n: number): number {
    checkBitsParam(n);
    const byteCount = n >> 3;
    if (this.strictReads && this.read + byteCount > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    let rval = 0;
    do {
      rval = (rval << 8) + this.data.charCodeAt(this.read++);
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

  getBytes(count?: number | null): string {
    let rval: string;
    if (count) {
      count = Math.min(this.length(), count);
      rval = this.data.slice(this.read, this.read + count);
      this.read += count;
    } else if (count === 0) {
      rval = '';
    } else {
      rval = this.read === 0 ? this.data : this.data.slice(this.read);
      this.clear();
    }
    return rval;
  }

  bytes(count?: number): string {
    return typeof count === 'undefined' ? this.data.slice(this.read) : this.data.slice(this.read, this.read + count);
  }

  at(i: number): number {
    if (this.read + i >= this.data.length || this.read + i < 0) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    return this.data.charCodeAt(this.read + i);
  }

  setAt(i: number, b: number): this {
    this.data = this.data.substr(0, this.read + i) + String.fromCharCode(b) + this.data.substr(this.read + i + 1);
    return this;
  }

  last(): number {
    return this.data.charCodeAt(this.data.length - 1);
  }

  copy(): ByteStringBuffer {
    const c = new ByteStringBuffer(this.data);
    c.read = this.read;
    return c;
  }

  compact(): this {
    if (this.read > 0) {
      this.data = this.data.slice(this.read);
      this.read = 0;
    }
    return this;
  }

  clear(): this {
    this.data = '';
    this.read = 0;
    return this;
  }

  truncate(count: number): this {
    const len = Math.max(0, this.length() - count);
    this.data = this.data.substr(this.read, len);
    this.read = 0;
    return this;
  }

  toHex(): string {
    let rval = '';
    for (let i = this.read; i < this.data.length; ++i) {
      const b = this.data.charCodeAt(i);
      if (b < 16) {
        rval += '0';
      }
      rval += b.toString(16);
    }
    return rval;
  }

  toString(): string {
    return decodeUtf8(this.bytes());
  }
}

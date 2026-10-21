import { checkBitsParam } from './checkBitsParam.js';
import { isArrayBuffer, isArrayBufferView } from '../util/typeChecks.js';
import { decodeUtf8, encodeUtf8 } from '../encoding/Utf8Codec.js';
import type { ByteStringBufferInput } from './BufferTypes.js';

const MAX_CONSTRUCTED_STRING_LENGTH = 4096;

/**
 * Constructor for a binary string backed byte buffer.
 */
export class ByteStringBuffer {
  data: string;
  read: number;
  _constructedStringLength: number;
  /** When true, reads past the end throw instead of returning stale values. */
  strictReads: boolean;

  constructor(input?: ByteStringBufferInput | null) {
    this.data = '';
    this.read = 0;
    this._constructedStringLength = 0;
    this.strictReads = false;

    if (typeof input === 'string') {
      this.data = input;
    } else if (isArrayBuffer(input) || isArrayBufferView(input)) {
      if (typeof Buffer !== 'undefined' && input instanceof Buffer) {
        this.data = input.toString('binary');
      } else {
        const arr = new Uint8Array(input as ArrayBuffer);
        try {
          this.data = String.fromCharCode.apply(null, Array.from(arr));
        } catch {
          for (let index = 0; index < arr.length; ++index) {
            this.putByte(arr[index]);
          }
        }
      }
    } else if (
      input instanceof ByteStringBuffer ||
      (typeof input === 'object' && input !== null && typeof input.data === 'string' && typeof input.read === 'number')
    ) {
      this.data = input.data;
      this.read = input.read;
    }
  }

  /**
   * Tracks repeated string concatenation and periodically flattens the internal
   * buffer. The discarded `substr(0, 1)` call is intentional: it nudges the
   * JS engine to flatten cons strings (node-forge legacy heuristic).
   */
  _optimizeConstructedString(lengthDelta: number): void {
    this._constructedStringLength += lengthDelta;
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

  putByte(byteValue: number): this {
    return this.putBytes(String.fromCharCode(byteValue));
  }

  fillWithByte(byteValue: number, repeatCount: number): this {
    let byte = String.fromCharCode(byteValue);
    let data = this.data;
    let remaining = repeatCount;
    while (remaining > 0) {
      if (remaining & 1) {
        data += byte;
      }
      remaining >>>= 1;
      if (remaining > 0) {
        byte += byte;
      }
    }
    this.data = data;
    this._optimizeConstructedString(repeatCount);
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

  putInt16(index: number): this {
    return this.putBytes(String.fromCharCode((index >> 8) & 0xff) + String.fromCharCode(index & 0xff));
  }

  putInt24(index: number): this {
    return this.putBytes(
      String.fromCharCode((index >> 16) & 0xff) +
        String.fromCharCode((index >> 8) & 0xff) +
        String.fromCharCode(index & 0xff)
    );
  }

  putInt32(index: number): this {
    return this.putBytes(
      String.fromCharCode((index >> 24) & 0xff) +
        String.fromCharCode((index >> 16) & 0xff) +
        String.fromCharCode((index >> 8) & 0xff) +
        String.fromCharCode(index & 0xff)
    );
  }

  putInt16Le(index: number): this {
    return this.putBytes(String.fromCharCode(index & 0xff) + String.fromCharCode((index >> 8) & 0xff));
  }

  putInt24Le(index: number): this {
    return this.putBytes(
      String.fromCharCode(index & 0xff) +
        String.fromCharCode((index >> 8) & 0xff) +
        String.fromCharCode((index >> 16) & 0xff)
    );
  }

  putInt32Le(index: number): this {
    return this.putBytes(
      String.fromCharCode(index & 0xff) +
        String.fromCharCode((index >> 8) & 0xff) +
        String.fromCharCode((index >> 16) & 0xff) +
        String.fromCharCode((index >> 24) & 0xff)
    );
  }

  putInt(index: number, bitCount: number): this {
    checkBitsParam(bitCount);
    let bytes = '';
    let remainingBits = bitCount;
    do {
      remainingBits -= 8;
      bytes += String.fromCharCode((index >> remainingBits) & 0xff);
    } while (remainingBits > 0);
    return this.putBytes(bytes);
  }

  putSignedInt(index: number, bitCount: number): this {
    if (index < 0) {
      index += 2 << (bitCount - 1);
    }
    return this.putInt(index, bitCount);
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
    const value = (this.data.charCodeAt(this.read) << 8) ^ this.data.charCodeAt(this.read + 1);
    this.read += 2;
    return value;
  }

  getInt24(): number {
    if (this.strictReads && this.read + 3 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const value =
      (this.data.charCodeAt(this.read) << 16) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      this.data.charCodeAt(this.read + 2);
    this.read += 3;
    return value;
  }

  getInt32(): number {
    if (this.strictReads && this.read + 4 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const value =
      (this.data.charCodeAt(this.read) << 24) ^
      (this.data.charCodeAt(this.read + 1) << 16) ^
      (this.data.charCodeAt(this.read + 2) << 8) ^
      this.data.charCodeAt(this.read + 3);
    this.read += 4;
    return value;
  }

  getInt16Le(): number {
    if (this.strictReads && this.read + 2 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const value = this.data.charCodeAt(this.read) ^ (this.data.charCodeAt(this.read + 1) << 8);
    this.read += 2;
    return value;
  }

  getInt24Le(): number {
    if (this.strictReads && this.read + 3 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const value =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16);
    this.read += 3;
    return value;
  }

  getInt32Le(): number {
    if (this.strictReads && this.read + 4 > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    const value =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16) ^
      (this.data.charCodeAt(this.read + 3) << 24);
    this.read += 4;
    return value;
  }

  getInt(bitCount: number): number {
    checkBitsParam(bitCount);
    const byteCount = bitCount >> 3;
    if (this.strictReads && this.read + byteCount > this.data.length) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    let value = 0;
    let remainingBits = bitCount;
    do {
      value = (value << 8) + this.data.charCodeAt(this.read++);
      remainingBits -= 8;
    } while (remainingBits > 0);
    return value;
  }

  getSignedInt(bitCount: number): number {
    let signedValue = this.getInt(bitCount);
    const max = 2 << (bitCount - 2);
    if (signedValue >= max) {
      signedValue -= max << 1;
    }
    return signedValue;
  }

  getBytes(count?: number | null): string {
    let value: string;
    if (count) {
      count = Math.min(this.length(), count);
      value = this.data.slice(this.read, this.read + count);
      this.read += count;
    } else if (count === 0) {
      value = '';
    } else {
      value = this.read === 0 ? this.data : this.data.slice(this.read);
      this.clear();
    }
    return value;
  }

  bytes(count?: number): string {
    return typeof count === 'undefined' ? this.data.slice(this.read) : this.data.slice(this.read, this.read + count);
  }

  // eslint-disable-next-line id-length -- ByteStringBuffer#at matches node-forge instance shape
  at(index: number): number {
    if (this.read + index >= this.data.length || this.read + index < 0) {
      throw new RangeError('ByteStringBuffer read past end of buffer.');
    }
    return this.data.charCodeAt(this.read + index);
  }

  setAt(index: number, byteValue: number): this {
    this.data =
      this.data.substr(0, this.read + index) + String.fromCharCode(byteValue) + this.data.substr(this.read + index + 1);
    return this;
  }

  last(): number {
    return this.data.charCodeAt(this.data.length - 1);
  }

  copy(): ByteStringBuffer {
    const copyBuffer = new ByteStringBuffer(this.data);
    copyBuffer.read = this.read;
    return copyBuffer;
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
    let value = '';
    for (let index = this.read; index < this.data.length; ++index) {
      const byteValue = this.data.charCodeAt(index);
      if (byteValue < 16) {
        value += '0';
      }
      value += byteValue.toString(16);
    }
    return value;
  }

  toString(): string {
    return decodeUtf8(this.bytes());
  }
}

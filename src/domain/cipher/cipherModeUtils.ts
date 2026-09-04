import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';
import type { BlockCipherApi, CipherModeOptions, CipherModeStartOptions, PadOptions } from './CipherTypes.js';

export function transformIV(iv: string | ByteStringBuffer | number[] | unknown, blockSize: number): number[] {
  if (typeof iv === 'string') {
    iv = new ByteStringBuffer(iv);
  }

  if (isArray(iv) && (iv as unknown[]).length > 4) {
    const tmp = iv as number[];
    iv = new ByteStringBuffer();
    for (let i = 0; i < tmp.length; ++i) {
      (iv as ByteStringBuffer).putByte(tmp[i]!);
    }
  }

  const buf = iv as ByteStringBuffer;
  if (buf.length() < blockSize) {
    throw new Error('Invalid IV length; got ' + buf.length() + ' bytes and expected ' + blockSize + ' bytes.');
  }

  if (!isArray(iv)) {
    const ints: number[] = [];
    const blocks = blockSize / 4;
    for (let i = 0; i < blocks; ++i) {
      ints.push(buf.getInt32());
    }
    iv = ints;
  }

  return iv as number[];
}

export function inc32(block: number[]): void {
  block[block.length - 1] = (block[block.length - 1]! + 1) & 0xffffffff;
}

export function from64To32(num: number): [number, number] {
  return [(num / 0x100000000) | 0, num & 0xffffffff];
}

/**
 * Validate and remove PKCS#7 padding from a decrypted buffer.
 */
export function validatePkcs7Padding(output: ByteStringBuffer, blockSize: number): boolean {
  const len = output.length();
  if (len === 0 || len % blockSize !== 0) {
    return false;
  }

  const count = output.at(len - 1);
  if (count < 1 || count > blockSize || count > len) {
    return false;
  }

  for (let i = len - count; i < len; ++i) {
    if (output.at(i) !== count) {
      return false;
    }
  }

  output.truncate(count);
  return true;
}

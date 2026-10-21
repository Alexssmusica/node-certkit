import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';
export function transformIV(iv: string | ByteStringBuffer | number[], blockSize: number): number[] {
  if (typeof iv === 'string') {
    iv = new ByteStringBuffer(iv);
  }

  if (isArray(iv) && iv.length > 4) {
    const ivBytes = iv;
    iv = new ByteStringBuffer();
    for (let i = 0; i < ivBytes.length; ++i) {
      iv.putByte(ivBytes[i]);
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

  return iv;
}

export function inc32(block: number[]): void {
  block[block.length - 1] = (block[block.length - 1] + 1) & 0xffffffff;
}

export function from64To32(num: number): [number, number] {
  return [(num / 0x100000000) | 0, num & 0xffffffff];
}

/**
 * Validate and remove PKCS#7 padding from a decrypted buffer.
 */
export function validatePkcs7Padding(output: ByteStringBuffer, blockSize: number): boolean {
  const bufferLength = output.length();
  if (bufferLength === 0 || bufferLength % blockSize !== 0) {
    return false;
  }

  const paddingByteCount = output.at(bufferLength - 1);
  if (paddingByteCount < 1 || paddingByteCount > blockSize || paddingByteCount > bufferLength) {
    return false;
  }

  for (let i = bufferLength - paddingByteCount; i < bufferLength; ++i) {
    if (output.at(i) !== paddingByteCount) {
      return false;
    }
  }

  output.truncate(paddingByteCount);
  return true;
}

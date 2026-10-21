import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';
export function transformIV(initializationVector: string | ByteStringBuffer | number[], blockSize: number): number[] {
  if (typeof initializationVector === 'string') {
    initializationVector = new ByteStringBuffer(initializationVector);
  }

  if (isArray(initializationVector) && initializationVector.length > 4) {
    const ivBytes = initializationVector;
    initializationVector = new ByteStringBuffer();
    for (let index = 0; index < ivBytes.length; ++index) {
      initializationVector.putByte(ivBytes[index]);
    }
  }

  const buf = initializationVector as ByteStringBuffer;
  if (buf.length() < blockSize) {
    throw new Error('Invalid IV length; got ' + buf.length() + ' bytes and expected ' + blockSize + ' bytes.');
  }

  if (!isArray(initializationVector)) {
    const ints: number[] = [];
    const blocks = blockSize / 4;
    for (let index = 0; index < blocks; ++index) {
      ints.push(buf.getInt32());
    }
    initializationVector = ints;
  }

  return initializationVector;
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

  for (let index = bufferLength - paddingByteCount; index < bufferLength; ++index) {
    if (output.at(index) !== paddingByteCount) {
      return false;
    }
  }

  output.truncate(paddingByteCount);
  return true;
}

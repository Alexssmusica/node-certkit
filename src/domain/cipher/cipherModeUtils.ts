import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { isArray } from '../util/typeChecks.js';

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

export type BlockCipherApi = {
  encrypt: (inBlock: number[], outBlock: number[]) => void;
  decrypt: (inBlock: number[], outBlock: number[]) => void;
};

export type CipherModeOptions = {
  cipher?: BlockCipherApi;
  blockSize?: number;
};

export type CipherModeStartOptions = {
  iv?: string | ByteStringBuffer | number[] | null;
  decrypt?: boolean;
  additionalData?: string | ByteStringBuffer;
  tagLength?: number;
  tag?: string | ByteStringBuffer;
  overflow?: number;
};

export type PadOptions = {
  overflow?: number;
  decrypt?: boolean;
};

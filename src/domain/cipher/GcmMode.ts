import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { constantTimeEquals } from '../util/constantTimeEquals.js';
import { from64To32, inc32 } from './cipherModeUtils.js';
import type { BlockCipherApi, CipherModeOptions, CipherModeStartOptions, PadOptions } from './CipherTypes.js';

/** NIST SP 800-38D GHASH reduction polynomial for GF(2^128). */
const GHASH_REDUCTION_POLY = 0xe1000000;

export class GcmMode {
  name = 'GCM';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[];
  _outBlock: number[];
  _partialOutput: ByteStringBuffer;
  _partialBytes: number;
  _reductionPoly: number;
  _cipherLength?: number;
  _tagLength?: number;
  _tag?: string | null;
  _hashBlock?: number[];
  tag: ByteStringBuffer | null = null;
  _hashSubkey?: number[];
  componentBits?: number;
  _hashTable?: number[][][];
  _j0?: number[];
  _aDataLength?: [number, number];
  _ghashState?: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = new Array<number>(this._ints);
    this._outBlock = new Array<number>(this._ints);
    this._partialOutput = new ByteStringBuffer();
    this._partialBytes = 0;
    this._reductionPoly = GHASH_REDUCTION_POLY;
  }

  start(options: CipherModeStartOptions): void {
    if (!('iv' in options)) {
      throw new Error('Invalid IV parameter.');
    }
    const iv = new ByteStringBuffer(options.iv as string);

    this._cipherLength = 0;

    let additionalData: ByteStringBuffer;
    if ('additionalData' in options) {
      additionalData = new ByteStringBuffer(options.additionalData);
    } else {
      additionalData = new ByteStringBuffer();
    }

    if ('tagLength' in options) {
      this._tagLength = options.tagLength;
    } else {
      this._tagLength = 128;
    }

    this._tag = null;
    if (options.decrypt) {
      this._tag = new ByteStringBuffer(options.tag).getBytes();
      if (this._tag.length !== this._tagLength! / 8) {
        throw new Error('Authentication tag does not match tag length.');
      }
    }

    this._hashBlock = new Array<number>(this._ints);
    this.tag = null;

    this._hashSubkey = new Array<number>(this._ints);
    this.cipher.encrypt([0, 0, 0, 0], this._hashSubkey);

    this.componentBits = 4;
    this._hashTable = this.generateHashTable(this._hashSubkey, this.componentBits);

    const ivLength = iv.length();
    if (ivLength === 12) {
      this._j0 = [iv.getInt32(), iv.getInt32(), iv.getInt32(), 1];
    } else {
      this._j0 = [0, 0, 0, 0];
      while (iv.length() > 0) {
        this._j0 = this.ghash(this._hashSubkey, this._j0, [iv.getInt32(), iv.getInt32(), iv.getInt32(), iv.getInt32()]);
      }
      this._j0 = this.ghash(this._hashSubkey, this._j0, [0, 0].concat(from64To32(ivLength * 8)));
    }

    this._inBlock = this._j0.slice(0);
    inc32(this._inBlock);
    this._partialBytes = 0;

    additionalData = new ByteStringBuffer(additionalData);
    this._aDataLength = from64To32(additionalData.length() * 8);
    const overflow = additionalData.length() % this.blockSize;
    if (overflow) {
      additionalData.fillWithByte(0, this.blockSize - overflow);
    }
    this._ghashState = [0, 0, 0, 0];
    while (additionalData.length() > 0) {
      this._ghashState = this.ghash(this._hashSubkey, this._ghashState, [
        additionalData.getInt32(),
        additionalData.getInt32(),
        additionalData.getInt32(),
        additionalData.getInt32()
      ]);
    }
  }

  encrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    const inputLength = input.length();
    if (inputLength === 0) {
      return true;
    }

    this.cipher.encrypt(this._inBlock, this._outBlock);

    if (this._partialBytes === 0 && inputLength >= this.blockSize) {
      for (let i = 0; i < this._ints; ++i) {
        output.putInt32((this._outBlock[i] ^= input.getInt32()));
      }
      this._cipherLength! += this.blockSize;
    } else {
      let partialBytes = (this.blockSize - inputLength) % this.blockSize;
      if (partialBytes > 0) {
        partialBytes = this.blockSize - partialBytes;
      }

      this._partialOutput.clear();
      for (let i = 0; i < this._ints; ++i) {
        this._partialOutput.putInt32(input.getInt32() ^ this._outBlock[i]);
      }

      if (partialBytes <= 0 || finish) {
        if (finish) {
          const overflow = inputLength % this.blockSize;
          this._cipherLength! += overflow;
          this._partialOutput.truncate(this.blockSize - overflow);
        } else {
          this._cipherLength! += this.blockSize;
        }

        for (let i = 0; i < this._ints; ++i) {
          this._outBlock[i] = this._partialOutput.getInt32();
        }
        this._partialOutput.read -= this.blockSize;
      }

      if (this._partialBytes > 0) {
        this._partialOutput.getBytes(this._partialBytes);
      }

      if (partialBytes > 0 && !finish) {
        input.read -= this.blockSize;
        output.putBytes(this._partialOutput.getBytes(partialBytes - this._partialBytes));
        this._partialBytes = partialBytes;
        return true;
      }

      output.putBytes(this._partialOutput.getBytes(inputLength - this._partialBytes));
      this._partialBytes = 0;
    }

    this._ghashState = this.ghash(this._hashSubkey!, this._ghashState!, this._outBlock);
    inc32(this._inBlock);
  }

  decrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    const inputLength = input.length();
    if (inputLength < this.blockSize && !(finish && inputLength > 0)) {
      return true;
    }

    this.cipher.encrypt(this._inBlock, this._outBlock);
    inc32(this._inBlock);

    this._hashBlock![0] = input.getInt32();
    this._hashBlock![1] = input.getInt32();
    this._hashBlock![2] = input.getInt32();
    this._hashBlock![3] = input.getInt32();
    this._ghashState = this.ghash(this._hashSubkey!, this._ghashState!, this._hashBlock!);

    for (let i = 0; i < this._ints; ++i) {
      output.putInt32(this._outBlock[i] ^ this._hashBlock![i]);
    }

    if (inputLength < this.blockSize) {
      this._cipherLength! += inputLength % this.blockSize;
    } else {
      this._cipherLength! += this.blockSize;
    }
  }

  afterFinish(output: ByteStringBuffer, options: PadOptions): boolean {
    let isValid = true;

    if (options.decrypt && options.overflow) {
      output.truncate(this.blockSize - options.overflow);
    }

    this.tag = new ByteStringBuffer();
    const lengths = this._aDataLength!.concat(from64To32(this._cipherLength! * 8));
    this._ghashState = this.ghash(this._hashSubkey!, this._ghashState!, lengths);

    const tag: number[] = [];
    this.cipher.encrypt(this._j0!, tag);
    for (let i = 0; i < this._ints; ++i) {
      this.tag.putInt32(this._ghashState[i] ^ tag[i]);
    }

    this.tag.truncate(this.tag.length() % (this._tagLength! / 8));

    if (options.decrypt && !constantTimeEquals(this.tag.bytes(), this._tag!)) {
      output.clear();
      isValid = false;
    }

    return isValid;
  }

  multiply(factor: number[], multiplier: number[]): number[] {
    // NIST SP 800-38D GHASH field multiply
    const zAccumulator = [0, 0, 0, 0];
    const vMultiplier = multiplier.slice(0);

    for (let i = 0; i < 128; ++i) {
      const bitMask = factor[(i / 32) | 0] & (1 << (31 - (i % 32)));
      if (bitMask) {
        zAccumulator[0] ^= vMultiplier[0];
        zAccumulator[1] ^= vMultiplier[1];
        zAccumulator[2] ^= vMultiplier[2];
        zAccumulator[3] ^= vMultiplier[3];
      }
      this.pow(vMultiplier, vMultiplier);
    }

    return zAccumulator;
  }

  pow(factor: number[], out: number[]): void {
    const lsb = factor[3] & 1;

    for (let i = 3; i > 0; --i) {
      out[i] = (factor[i] >>> 1) | ((factor[i - 1] & 1) << 31);
    }
    out[0] = factor[0] >>> 1;

    if (lsb) {
      out[0] ^= this._reductionPoly;
    }
  }

  tableMultiply(block: number[]): number[] {
    const productAccumulator = [0, 0, 0, 0];
    for (let nibbleStep = 0; nibbleStep < 32; ++nibbleStep) {
      const wordIndex = (nibbleStep / 8) | 0;
      const nibbleIndex = (block[wordIndex] >>> ((7 - (nibbleStep % 8)) * 4)) & 0xf;
      const nibbleProduct = this._hashTable![nibbleStep][nibbleIndex];
      productAccumulator[0] ^= nibbleProduct[0];
      productAccumulator[1] ^= nibbleProduct[1];
      productAccumulator[2] ^= nibbleProduct[2];
      productAccumulator[3] ^= nibbleProduct[3];
    }
    return productAccumulator;
  }

  ghash(subkeyHash: number[], accumulator: number[], block: number[]): number[] {
    accumulator[0] ^= block[0];
    accumulator[1] ^= block[1];
    accumulator[2] ^= block[2];
    accumulator[3] ^= block[3];
    return this.tableMultiply(accumulator);
  }

  generateHashTable(subkeyHash: number[], bits: number): number[][][] {
    const multiplier = 8 / bits;
    const wordsPerEntry = 4 * multiplier;
    const tableSize = 16 * multiplier;
    const hashTable: number[][][] = new Array<number[][]>(tableSize);
    for (let tableIndex = 0; tableIndex < tableSize; ++tableIndex) {
      const seedBlock = [0, 0, 0, 0];
      const wordIndex = (tableIndex / wordsPerEntry) | 0;
      const bitShift = (wordsPerEntry - 1 - (tableIndex % wordsPerEntry)) * bits;
      seedBlock[wordIndex] = (1 << (bits - 1)) << bitShift;
      hashTable[tableIndex] = this.generateSubHashTable(this.multiply(seedBlock, subkeyHash), bits);
    }
    return hashTable;
  }

  generateSubHashTable(midBlock: number[], bits: number): number[][] {
    const tableSize = 1 << bits;
    const halfSize = tableSize >>> 1;
    const subTable: number[][] = new Array<number[]>(tableSize);
    subTable[halfSize] = midBlock.slice(0);
    let rowIndex = halfSize >>> 1;
    while (rowIndex > 0) {
      this.pow(subTable[2 * rowIndex], (subTable[rowIndex] = []));
      rowIndex >>= 1;
    }
    rowIndex = 2;
    while (rowIndex < halfSize) {
      for (let offset = 1; offset < rowIndex; ++offset) {
        const rowAtIndex = subTable[rowIndex];
        const rowAtOffset = subTable[offset];
        subTable[rowIndex + offset] = [
          rowAtIndex[0] ^ rowAtOffset[0],
          rowAtIndex[1] ^ rowAtOffset[1],
          rowAtIndex[2] ^ rowAtOffset[2],
          rowAtIndex[3] ^ rowAtOffset[3]
        ];
      }
      rowIndex *= 2;
    }
    subTable[0] = [0, 0, 0, 0];
    for (rowIndex = halfSize + 1; rowIndex < tableSize; ++rowIndex) {
      const complementRow = subTable[rowIndex ^ halfSize];
      subTable[rowIndex] = [
        midBlock[0] ^ complementRow[0],
        midBlock[1] ^ complementRow[1],
        midBlock[2] ^ complementRow[2],
        midBlock[3] ^ complementRow[3]
      ];
    }
    return subTable;
  }
}

export default GcmMode;

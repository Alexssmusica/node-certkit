import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { transformIV } from './cipherModeUtils.js';
import type { BlockCipherApi, CipherModeOptions, CipherModeStartOptions } from './CipherTypes.js';

export class CfbMode {
  name = 'CFB';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[] | null;
  _outBlock: number[];
  _partialBlock: number[];
  _partialOutput: ByteStringBuffer;
  _partialBytes: number;
  _iv?: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = null;
    this._outBlock = new Array<number>(this._ints);
    this._partialBlock = new Array<number>(this._ints);
    this._partialOutput = new ByteStringBuffer();
    this._partialBytes = 0;
  }

  start(options: CipherModeStartOptions): void {
    if (!('iv' in options)) {
      throw new Error('Invalid IV parameter.');
    }
    this._iv = transformIV(options.iv!, this.blockSize);
    this._inBlock = this._iv.slice(0);
    this._partialBytes = 0;
  }

  encrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    const inputLength = input.length();
    if (inputLength === 0) {
      return true;
    }

    this.cipher.encrypt(this._inBlock!, this._outBlock);

    if (this._partialBytes === 0 && inputLength >= this.blockSize) {
      for (let index = 0; index < this._ints; ++index) {
        this._inBlock![index] = input.getInt32() ^ this._outBlock[index];
        output.putInt32(this._inBlock![index]);
      }
      return;
    }

    let partialBytes = (this.blockSize - inputLength) % this.blockSize;
    if (partialBytes > 0) {
      partialBytes = this.blockSize - partialBytes;
    }

    this._partialOutput.clear();
    for (let index = 0; index < this._ints; ++index) {
      this._partialBlock[index] = input.getInt32() ^ this._outBlock[index];
      this._partialOutput.putInt32(this._partialBlock[index]);
    }

    if (partialBytes > 0) {
      input.read -= this.blockSize;
    } else {
      for (let index = 0; index < this._ints; ++index) {
        this._inBlock![index] = this._partialBlock[index]!;
      }
    }

    if (this._partialBytes > 0) {
      this._partialOutput.getBytes(this._partialBytes);
    }

    if (partialBytes > 0 && !finish) {
      output.putBytes(this._partialOutput.getBytes(partialBytes - this._partialBytes));
      this._partialBytes = partialBytes;
      return true;
    }

    output.putBytes(this._partialOutput.getBytes(inputLength - this._partialBytes));
    this._partialBytes = 0;
  }

  decrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    const inputLength = input.length();
    if (inputLength === 0) {
      return true;
    }

    this.cipher.encrypt(this._inBlock!, this._outBlock);

    if (this._partialBytes === 0 && inputLength >= this.blockSize) {
      for (let index = 0; index < this._ints; ++index) {
        this._inBlock![index] = input.getInt32();
        output.putInt32(this._inBlock![index] ^ this._outBlock[index]);
      }
      return;
    }

    let partialBytes = (this.blockSize - inputLength) % this.blockSize;
    if (partialBytes > 0) {
      partialBytes = this.blockSize - partialBytes;
    }

    this._partialOutput.clear();
    for (let index = 0; index < this._ints; ++index) {
      this._partialBlock[index] = input.getInt32();
      this._partialOutput.putInt32(this._partialBlock[index] ^ this._outBlock[index]);
    }

    if (partialBytes > 0) {
      input.read -= this.blockSize;
    } else {
      for (let index = 0; index < this._ints; ++index) {
        this._inBlock![index] = this._partialBlock[index]!;
      }
    }

    if (this._partialBytes > 0) {
      this._partialOutput.getBytes(this._partialBytes);
    }

    if (partialBytes > 0 && !finish) {
      output.putBytes(this._partialOutput.getBytes(partialBytes - this._partialBytes));
      this._partialBytes = partialBytes;
      return true;
    }

    output.putBytes(this._partialOutput.getBytes(inputLength - this._partialBytes));
    this._partialBytes = 0;
  }
}

export default CfbMode;

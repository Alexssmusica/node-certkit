import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { BlockCipherApi, CipherModeOptions, CipherModeStartOptions, transformIV } from './cipherModeUtils.js';

export class OfbMode {
  name = 'OFB';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[] | null;
  _outBlock: number[];
  _partialOutput: ByteStringBuffer;
  _partialBytes: number;
  _iv?: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = null;
    this._outBlock = new Array(this._ints);
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
    if (input.length() === 0) {
      return true;
    }

    this.cipher.encrypt(this._inBlock!, this._outBlock);

    if (this._partialBytes === 0 && inputLength >= this.blockSize) {
      for (let i = 0; i < this._ints; ++i) {
        output.putInt32(input.getInt32() ^ this._outBlock[i]!);
        this._inBlock![i] = this._outBlock[i]!;
      }
      return;
    }

    let partialBytes = (this.blockSize - inputLength) % this.blockSize;
    if (partialBytes > 0) {
      partialBytes = this.blockSize - partialBytes;
    }

    this._partialOutput.clear();
    for (let i = 0; i < this._ints; ++i) {
      this._partialOutput.putInt32(input.getInt32() ^ this._outBlock[i]!);
    }

    if (partialBytes > 0) {
      input.read -= this.blockSize;
    } else {
      for (let i = 0; i < this._ints; ++i) {
        this._inBlock![i] = this._outBlock[i]!;
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
    return this.encrypt(input, output, finish);
  }
}

export default OfbMode;

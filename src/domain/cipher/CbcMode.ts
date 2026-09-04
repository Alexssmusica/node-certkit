import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import {
  BlockCipherApi,
  CipherModeOptions,
  CipherModeStartOptions,
  PadOptions,
  transformIV
} from './cipherModeUtils.js';

export class CbcMode {
  name = 'CBC';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[];
  _outBlock: number[];
  _iv?: number[];
  _prev?: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = new Array(this._ints);
    this._outBlock = new Array(this._ints);
  }

  start(options: CipherModeStartOptions): void {
    if (options.iv === null) {
      if (!this._prev) {
        throw new Error('Invalid IV parameter.');
      }
      this._iv = this._prev.slice(0);
    } else if (!('iv' in options)) {
      throw new Error('Invalid IV parameter.');
    } else {
      this._iv = transformIV(options.iv!, this.blockSize);
      this._prev = this._iv.slice(0);
    }
  }

  encrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    if (input.length() < this.blockSize && !(finish && input.length() > 0)) {
      return true;
    }

    for (let i = 0; i < this._ints; ++i) {
      this._inBlock[i] = this._prev![i]! ^ input.getInt32();
    }

    this.cipher.encrypt(this._inBlock, this._outBlock);

    for (let i = 0; i < this._ints; ++i) {
      output.putInt32(this._outBlock[i]!);
    }
    this._prev = this._outBlock;
  }

  decrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    if (input.length() < this.blockSize && !(finish && input.length() > 0)) {
      return true;
    }

    for (let i = 0; i < this._ints; ++i) {
      this._inBlock[i] = input.getInt32();
    }

    this.cipher.decrypt(this._inBlock, this._outBlock);

    for (let i = 0; i < this._ints; ++i) {
      output.putInt32(this._prev![i]! ^ this._outBlock[i]!);
    }
    this._prev = this._inBlock.slice(0);
  }

  pad(input: ByteStringBuffer, _options?: PadOptions): boolean {
    const padding = input.length() === this.blockSize ? this.blockSize : this.blockSize - input.length();
    input.fillWithByte(padding, padding);
    return true;
  }

  unpad(output: ByteStringBuffer, options: PadOptions): boolean {
    if (options.overflow! > 0) {
      return false;
    }

    const len = output.length();
    const count = output.at(len - 1);
    if (count > this.blockSize << 2) {
      return false;
    }

    output.truncate(count);
    return true;
  }
}

export default CbcMode;

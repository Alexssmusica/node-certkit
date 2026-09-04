import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { validatePkcs7Padding } from './cipherModeUtils.js';
import type { BlockCipherApi, CipherModeOptions, CipherModeStartOptions, PadOptions } from './CipherTypes.js';

export class EcbMode {
  name = 'ECB';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[];
  _outBlock: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = new Array(this._ints);
    this._outBlock = new Array(this._ints);
  }

  start(_options?: CipherModeStartOptions): void {}

  encrypt(input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean): boolean | void {
    if (input.length() < this.blockSize && !(finish && input.length() > 0)) {
      return true;
    }

    for (let i = 0; i < this._ints; ++i) {
      this._inBlock[i] = input.getInt32();
    }

    this.cipher.encrypt(this._inBlock, this._outBlock);

    for (let i = 0; i < this._ints; ++i) {
      output.putInt32(this._outBlock[i]!);
    }
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
      output.putInt32(this._outBlock[i]!);
    }
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

    return validatePkcs7Padding(output, this.blockSize);
  }
}

export default EcbMode;

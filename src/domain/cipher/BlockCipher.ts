import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';

export type CipherAlgorithm = {
  mode: {
    blockSize: number;
    name?: string;
    tag?: ByteStringBuffer;
    start: (options: Record<string, unknown>) => void;
    encrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    decrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    pad?: (input: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    unpad?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    afterFinish?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
  };
  initialize: (options: BlockCipherOptions) => void;
};

export type BlockCipherOptions = {
  algorithm: CipherAlgorithm;
  key: string | ByteStringBuffer;
  decrypt: boolean;
};

export type BlockCipherStartOptions = {
  iv?: string | ByteStringBuffer | number[] | null;
  additionalData?: string | ByteStringBuffer;
  tagLength?: number;
  tag?: string | ByteStringBuffer;
  output?: ByteStringBuffer;
};

export type PaddingFunction = (blockSize: number, buffer: ByteStringBuffer, decrypt: boolean) => boolean;

export class BlockCipher {
  algorithm: CipherAlgorithm;
  mode: BlockCipherOptions['algorithm']['mode'];
  blockSize: number;
  _finish: boolean;
  _input: ByteStringBuffer | null;
  output: ByteStringBuffer | null;
  _op: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
  _decrypt: boolean;

  constructor(options: BlockCipherOptions) {
    this.algorithm = options.algorithm;
    this.mode = this.algorithm.mode;
    this.blockSize = this.mode.blockSize;
    this._finish = false;
    this._input = null;
    this.output = null;
    this._op = options.decrypt ? this.mode.decrypt : this.mode.encrypt;
    this._decrypt = options.decrypt;
    this.algorithm.initialize(options);
  }

  start(options?: BlockCipherStartOptions): void {
    options = options || {};
    const opts: Record<string, unknown> = {};
    for (const key in options) {
      opts[key] = (options as Record<string, unknown>)[key];
    }
    opts.decrypt = this._decrypt;
    this._finish = false;
    this._input = new ByteStringBuffer();
    this.output = options.output || new ByteStringBuffer();
    this.mode.start(opts);
  }

  update(input?: ByteStringBuffer): void {
    if (input) {
      this._input!.putBuffer(input);
    }

    while (!this._op.call(this.mode, this._input!, this.output!, this._finish) && !this._finish) {}

    this._input!.compact();
  }

  finish(pad?: PaddingFunction): boolean {
    if (pad && (this.mode.name === 'ECB' || this.mode.name === 'CBC')) {
      this.mode.pad = (input: ByteStringBuffer) => {
        return pad(this.blockSize, input, false);
      };
      this.mode.unpad = (output: ByteStringBuffer) => {
        return pad(this.blockSize, output, true);
      };
    }

    const options: Record<string, unknown> = {};
    options.decrypt = this._decrypt;
    options.overflow = this._input!.length() % this.blockSize;

    if (!this._decrypt && this.mode.pad) {
      if (!this.mode.pad(this._input!, options)) {
        return false;
      }
    }

    this._finish = true;
    this.update();

    if (this._decrypt && this.mode.unpad) {
      if (!this.mode.unpad(this.output!, options)) {
        return false;
      }
    }

    if (this.mode.afterFinish) {
      if (!this.mode.afterFinish(this.output!, options)) {
        return false;
      }
    }

    return true;
  }
}

export default BlockCipher;

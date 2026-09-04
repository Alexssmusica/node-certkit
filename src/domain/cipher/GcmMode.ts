import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import {
  BlockCipherApi,
  CipherModeOptions,
  CipherModeStartOptions,
  PadOptions,
  from64To32,
  inc32
} from './cipherModeUtils.js';

export class GcmMode {
  name = 'GCM';
  cipher: BlockCipherApi;
  blockSize: number;
  _ints: number;
  _inBlock: number[];
  _outBlock: number[];
  _partialOutput: ByteStringBuffer;
  _partialBytes: number;
  _R: number;
  _cipherLength?: number;
  _tagLength?: number;
  _tag?: string | null;
  _hashBlock?: number[];
  tag: ByteStringBuffer | null = null;
  _hashSubkey?: number[];
  componentBits?: number;
  _m?: number[][][];
  _j0?: number[];
  _aDataLength?: [number, number];
  _s?: number[];

  constructor(options?: CipherModeOptions) {
    options = options || {};
    this.cipher = options.cipher!;
    this.blockSize = options.blockSize || 16;
    this._ints = this.blockSize / 4;
    this._inBlock = new Array(this._ints);
    this._outBlock = new Array(this._ints);
    this._partialOutput = new ByteStringBuffer();
    this._partialBytes = 0;
    this._R = 0xe1000000;
  }

  start(options: CipherModeStartOptions): void {
    if (!('iv' in options)) {
      throw new Error('Invalid IV parameter.');
    }
    const iv = new ByteStringBuffer(options.iv as string);

    this._cipherLength = 0;

    let additionalData: ByteStringBuffer;
    if ('additionalData' in options) {
      additionalData = new ByteStringBuffer(options.additionalData as string);
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
      this._tag = new ByteStringBuffer(options.tag!).getBytes();
      if (this._tag.length !== this._tagLength! / 8) {
        throw new Error('Authentication tag does not match tag length.');
      }
    }

    this._hashBlock = new Array(this._ints);
    this.tag = null;

    this._hashSubkey = new Array(this._ints);
    this.cipher.encrypt([0, 0, 0, 0], this._hashSubkey);

    this.componentBits = 4;
    this._m = this.generateHashTable(this._hashSubkey, this.componentBits);

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
    this._s = [0, 0, 0, 0];
    while (additionalData.length() > 0) {
      this._s = this.ghash(this._hashSubkey, this._s, [
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
        output.putInt32((this._outBlock[i]! ^= input.getInt32()));
      }
      this._cipherLength! += this.blockSize;
    } else {
      let partialBytes = (this.blockSize - inputLength) % this.blockSize;
      if (partialBytes > 0) {
        partialBytes = this.blockSize - partialBytes;
      }

      this._partialOutput.clear();
      for (let i = 0; i < this._ints; ++i) {
        this._partialOutput.putInt32(input.getInt32() ^ this._outBlock[i]!);
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

    this._s = this.ghash(this._hashSubkey!, this._s!, this._outBlock);
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
    this._s = this.ghash(this._hashSubkey!, this._s!, this._hashBlock!);

    for (let i = 0; i < this._ints; ++i) {
      output.putInt32(this._outBlock[i]! ^ this._hashBlock![i]!);
    }

    if (inputLength < this.blockSize) {
      this._cipherLength! += inputLength % this.blockSize;
    } else {
      this._cipherLength! += this.blockSize;
    }
  }

  afterFinish(output: ByteStringBuffer, options: PadOptions): boolean {
    let rval = true;

    if (options.decrypt && options.overflow) {
      output.truncate(this.blockSize - options.overflow);
    }

    this.tag = new ByteStringBuffer();
    const lengths = this._aDataLength!.concat(from64To32(this._cipherLength! * 8));
    this._s = this.ghash(this._hashSubkey!, this._s!, lengths);

    const tag: number[] = [];
    this.cipher.encrypt(this._j0!, tag);
    for (let i = 0; i < this._ints; ++i) {
      this.tag.putInt32(this._s![i]! ^ tag[i]!);
    }

    this.tag.truncate(this.tag.length() % (this._tagLength! / 8));

    if (options.decrypt && this.tag.bytes() !== this._tag) {
      rval = false;
    }

    return rval;
  }

  multiply(x: number[], y: number[]): number[] {
    const z_i = [0, 0, 0, 0];
    const v_i = y.slice(0);

    for (let i = 0; i < 128; ++i) {
      const x_i = x[(i / 32) | 0]! & (1 << (31 - (i % 32)));
      if (x_i) {
        z_i[0] ^= v_i[0]!;
        z_i[1] ^= v_i[1]!;
        z_i[2] ^= v_i[2]!;
        z_i[3] ^= v_i[3]!;
      }
      this.pow(v_i, v_i);
    }

    return z_i;
  }

  pow(x: number[], out: number[]): void {
    const lsb = x[3]! & 1;

    for (let i = 3; i > 0; --i) {
      out[i] = (x[i]! >>> 1) | ((x[i - 1]! & 1) << 31);
    }
    out[0] = x[0]! >>> 1;

    if (lsb) {
      out[0] ^= this._R;
    }
  }

  tableMultiply(x: number[]): number[] {
    const z = [0, 0, 0, 0];
    for (let i = 0; i < 32; ++i) {
      const idx = (i / 8) | 0;
      const x_i = (x[idx]! >>> ((7 - (i % 8)) * 4)) & 0xf;
      const ah = this._m![i]![x_i]!;
      z[0] ^= ah[0]!;
      z[1] ^= ah[1]!;
      z[2] ^= ah[2]!;
      z[3] ^= ah[3]!;
    }
    return z;
  }

  ghash(h: number[], y: number[], x: number[]): number[] {
    y[0] ^= x[0]!;
    y[1] ^= x[1]!;
    y[2] ^= x[2]!;
    y[3] ^= x[3]!;
    return this.tableMultiply(y);
  }

  generateHashTable(h: number[], bits: number): number[][][] {
    const multiplier = 8 / bits;
    const perInt = 4 * multiplier;
    const size = 16 * multiplier;
    const m: number[][][] = new Array(size);
    for (let i = 0; i < size; ++i) {
      const tmp = [0, 0, 0, 0];
      const idx = (i / perInt) | 0;
      const shft = (perInt - 1 - (i % perInt)) * bits;
      tmp[idx] = (1 << (bits - 1)) << shft;
      m[i] = this.generateSubHashTable(this.multiply(tmp, h), bits);
    }
    return m;
  }

  generateSubHashTable(mid: number[], bits: number): number[][] {
    const size = 1 << bits;
    const half = size >>> 1;
    const m: number[][] = new Array(size);
    m[half] = mid.slice(0);
    let i = half >>> 1;
    while (i > 0) {
      this.pow(m[2 * i]!, (m[i] = []));
      i >>= 1;
    }
    i = 2;
    while (i < half) {
      for (let j = 1; j < i; ++j) {
        const m_i = m[i]!;
        const m_j = m[j]!;
        m[i + j] = [m_i[0]! ^ m_j[0]!, m_i[1]! ^ m_j[1]!, m_i[2]! ^ m_j[2]!, m_i[3]! ^ m_j[3]!];
      }
      i *= 2;
    }
    m[0] = [0, 0, 0, 0];
    for (i = half + 1; i < size; ++i) {
      const c = m[i ^ half]!;
      m[i] = [mid[0]! ^ c[0]!, mid[1]! ^ c[1]!, mid[2]! ^ c[2]!, mid[3]! ^ c[3]!];
    }
    return m;
  }
}

export default GcmMode;

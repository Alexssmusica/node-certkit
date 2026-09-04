import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';

const piTable = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37,
  0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3,
  0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32, 0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0,
  0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14,
  0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6,
  0x26, 0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11,
  0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde, 0x80,
  0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf,
  0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55,
  0x97, 0x31, 0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9, 0xd3,
  0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
  0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c,
  0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
];

const s = [1, 2, 3, 5];

const rol = function (word: number, bits: number): number {
  return ((word << bits) & 0xffff) | ((word & 0xffff) >> (16 - bits));
};

const ror = function (word: number, bits: number): number {
  return ((word & 0xffff) >> bits) | ((word << (16 - bits)) & 0xffff);
};

export type Rc2CipherObject = {
  output?: ByteStringBuffer;
  start: (iv?: string | ByteStringBuffer | null, output?: ByteStringBuffer | null) => void;
  update: (input: ByteStringBuffer) => void;
  finish: (pad?: (blockSize: number, buffer: ByteStringBuffer, decrypt: boolean) => boolean) => boolean;
};

export type Rc2NamespaceObject = {
  expandKey: typeof Rc2Cipher.expandKey;
  startEncrypting: typeof Rc2Cipher.startEncrypting;
  createEncryptionCipher: typeof Rc2Cipher.createEncryptionCipher;
  startDecrypting: typeof Rc2Cipher.startDecrypting;
  createDecryptionCipher: typeof Rc2Cipher.createDecryptionCipher;
};

export class Rc2Cipher {
  static expandKey(key: string | ByteStringBuffer, effKeyBits?: number): ByteStringBuffer {
    if (typeof key === 'string') {
      key = new ByteStringBuffer(key);
    }
    effKeyBits = effKeyBits || 128;

    const L = key;
    const T = key.length();
    const T1 = effKeyBits;
    const T8 = Math.ceil(T1 / 8);
    const TM = 0xff >> (T1 & 0x07);
    let i: number;

    for (i = T; i < 128; i++) {
      L.putByte(piTable[(L.at(i - 1) + L.at(i - T)) & 0xff]!);
    }

    L.setAt(128 - T8, piTable[L.at(128 - T8) & TM]!);

    for (i = 127 - T8; i >= 0; i--) {
      L.setAt(i, piTable[L.at(i + 1) ^ L.at(i + T8)]!);
    }

    return L;
  }

  static createEncryptionCipher(key: string | ByteStringBuffer, bits?: number): Rc2CipherObject {
    return Rc2Cipher.createCipher(key, bits, true);
  }

  static createDecryptionCipher(key: string | ByteStringBuffer, bits?: number): Rc2CipherObject {
    return Rc2Cipher.createCipher(key, bits, false);
  }

  static startEncrypting(
    key: string | ByteStringBuffer,
    iv?: string | ByteStringBuffer | null,
    output?: ByteStringBuffer | null
  ): Rc2CipherObject {
    const cipher = Rc2Cipher.createEncryptionCipher(key, 128);
    cipher.start(iv, output);
    return cipher;
  }

  static startDecrypting(
    key: string | ByteStringBuffer,
    iv?: string | ByteStringBuffer | null,
    output?: ByteStringBuffer | null
  ): Rc2CipherObject {
    const cipher = Rc2Cipher.createDecryptionCipher(key, 128);
    cipher.start(iv, output);
    return cipher;
  }

  static createCertkitNamespace(): Rc2NamespaceObject {
    return {
      expandKey: Rc2Cipher.expandKey.bind(Rc2Cipher),
      startEncrypting: Rc2Cipher.startEncrypting.bind(Rc2Cipher),
      createEncryptionCipher: Rc2Cipher.createEncryptionCipher.bind(Rc2Cipher),
      startDecrypting: Rc2Cipher.startDecrypting.bind(Rc2Cipher),
      createDecryptionCipher: Rc2Cipher.createDecryptionCipher.bind(Rc2Cipher)
    };
  }

  private static createCipher(
    key: string | ByteStringBuffer,
    bits: number | undefined,
    encrypt: boolean
  ): Rc2CipherObject {
    let _finish = false;
    let _input: ByteStringBuffer | null = null;
    let _output: ByteStringBuffer | null = null;
    let _iv: ByteStringBuffer | null = null;
    let mixRound: (R: number[]) => void;
    let mashRound: (R: number[]) => void;
    let i: number;
    let j: number;
    const K: number[] = [];

    key = Rc2Cipher.expandKey(key, bits);
    for (i = 0; i < 64; i++) {
      K.push(key.getInt16Le());
    }

    if (encrypt) {
      mixRound = function (R: number[]) {
        for (i = 0; i < 4; i++) {
          R[i]! += K[j]! + (R[(i + 3) % 4]! & R[(i + 2) % 4]!) + (~R[(i + 3) % 4]! & R[(i + 1) % 4]!);
          R[i] = rol(R[i]!, s[i]!);
          j++;
        }
      };

      mashRound = function (R: number[]) {
        for (i = 0; i < 4; i++) {
          R[i]! += K[R[(i + 3) % 4]! & 63]!;
        }
      };
    } else {
      mixRound = function (R: number[]) {
        for (i = 3; i >= 0; i--) {
          R[i] = ror(R[i]!, s[i]!);
          R[i]! -= K[j]! + (R[(i + 3) % 4]! & R[(i + 2) % 4]!) + (~R[(i + 3) % 4]! & R[(i + 1) % 4]!);
          j--;
        }
      };

      mashRound = function (R: number[]) {
        for (i = 3; i >= 0; i--) {
          R[i]! -= K[R[(i + 3) % 4]! & 63]!;
        }
      };
    }

    const runPlan = function (plan: [number, (R: number[]) => void][]) {
      const R: number[] = [];

      for (i = 0; i < 4; i++) {
        let val = _input!.getInt16Le();

        if (_iv !== null) {
          if (encrypt) {
            val ^= _iv.getInt16Le();
          } else {
            _iv.putInt16Le(val);
          }
        }

        R.push(val & 0xffff);
      }

      j = encrypt ? 0 : 63;

      for (let ptr = 0; ptr < plan.length; ptr++) {
        for (let ctr = 0; ctr < plan[ptr]![0]; ctr++) {
          plan[ptr]![1](R);
        }
      }

      for (i = 0; i < 4; i++) {
        if (_iv !== null) {
          if (encrypt) {
            _iv.putInt16Le(R[i]!);
          } else {
            R[i]! ^= _iv.getInt16Le();
          }
        }

        _output!.putInt16Le(R[i]!);
      }
    };

    const cipher: Rc2CipherObject = {
      start(iv?: string | ByteStringBuffer | null, output?: ByteStringBuffer | null) {
        let ivBuffer: ByteStringBuffer | null = null;
        if (iv) {
          ivBuffer = typeof iv === 'string' ? new ByteStringBuffer(iv) : iv;
        }

        _finish = false;
        _input = new ByteStringBuffer();
        _output = output || new ByteStringBuffer();
        _iv = ivBuffer;
        cipher.output = _output;
      },
      update(input: ByteStringBuffer) {
        if (!_finish) {
          _input!.putBuffer(input);
        }

        while (_input!.length() >= 8) {
          runPlan([
            [5, mixRound],
            [1, mashRound],
            [6, mixRound],
            [1, mashRound],
            [5, mixRound]
          ]);
        }
      },
      finish(pad?) {
        let rval = true;

        if (encrypt) {
          if (pad) {
            rval = pad(8, _input!, !encrypt);
          } else {
            const padding = _input!.length() === 8 ? 8 : 8 - _input!.length();
            _input!.fillWithByte(padding, padding);
          }
        }

        if (rval) {
          _finish = true;
          cipher.update(new ByteStringBuffer());
        }

        if (!encrypt) {
          rval = _input!.length() === 0;
          if (rval) {
            if (pad) {
              rval = pad(8, _output!, !encrypt);
            } else {
              const len = _output!.length();
              const count = _output!.at(len - 1);

              if (count > len) {
                rval = false;
              } else {
                _output!.truncate(count);
              }
            }
          }
        }

        return rval;
      }
    };

    return cipher;
  }
}

export default Rc2Cipher;

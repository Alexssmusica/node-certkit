/* Migrated from lib/des.js */
import { UtilNamespace } from '../util/UtilNamespace.js';
import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { BlockCipherApi } from './cipherModeUtils.js';
import { CipherApi, CreateCipherOptions, ModeConstructor } from './CipherTypes.js';

type InitializeOptions = {
  key: string | ByteStringBuffer;
  decrypt?: boolean;
};

let cipherApi: CipherApi<DesAlgorithm['mode']>;

export type DesNamespaceObject = Record<string, unknown> & {
  startEncrypting: (...args: unknown[]) => unknown;
  createEncryptionCipher: (...args: unknown[]) => unknown;
  startDecrypting: (...args: unknown[]) => unknown;
  createDecryptionCipher: (...args: unknown[]) => unknown;
  Algorithm: typeof DesAlgorithm;
};

/**
 * DES (Data Encryption Standard) implementation.
 *
 * This implementation supports DES as well as 3DES-EDE in ECB and CBC mode.
 * It is based on the BSD-licensed implementation by Paul Tero:
 *
 * Paul Tero, July 2001
 * http://www.tero.co.uk/des/
 *
 * Optimised for performance with large blocks by
 * Michael Hayworth, November 2001
 * http://www.netdealing.com
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @author Stefan Siegl
 * @author Dave Longley
 *
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 * Copyright (c) 2012-2014 Digital Bazaar, Inc.
 */

/**
 * Deprecated. Instead, use:
 *
 * var cipher = cipherApi.createCipher('DES-<mode>', key);
 * cipher.start({iv: iv});
 *
 * Creates an DES cipher object to encrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as binary-encoded strings of bytes or
 * byte buffers.
 *
 * @param key the symmetric key to use (64 or 192 bits).
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC' if IV is
 *          given, 'ECB' if null).
 *
 * @return the cipher.
 */
function startEncrypting(key: unknown, iv: unknown, output: ByteStringBuffer | null, mode?: string) {
  const cipher = _createCipher({
    key: key,
    output: output,
    decrypt: false,
    mode: mode || (iv === null ? 'ECB' : 'CBC')
  });
  cipher.start(iv);
  return cipher;
}

/**
 * Deprecated. Instead, use:
 *
 * var cipher = cipherApi.createCipher('DES-<mode>', key);
 *
 * Creates an DES cipher object to encrypt data using the given symmetric key.
 *
 * The key may be given as a binary-encoded string of bytes or a byte buffer.
 *
 * @param key the symmetric key to use (64 or 192 bits).
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function createEncryptionCipher(key: unknown, mode?: string) {
  return _createCipher({
    key: key,
    output: null,
    decrypt: false,
    mode: mode
  });
}

/**
 * Deprecated. Instead, use:
 *
 * var decipher = cipherApi.createDecipher('DES-<mode>', key);
 * decipher.start({iv: iv});
 *
 * Creates an DES cipher object to decrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as binary-encoded strings of bytes or
 * byte buffers.
 *
 * @param key the symmetric key to use (64 or 192 bits).
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC' if IV is
 *          given, 'ECB' if null).
 *
 * @return the cipher.
 */
function startDecrypting(key: unknown, iv: unknown, output: ByteStringBuffer | null, mode?: string) {
  const cipher = _createCipher({
    key: key,
    output: output,
    decrypt: true,
    mode: mode || (iv === null ? 'ECB' : 'CBC')
  });
  cipher.start(iv);
  return cipher;
}

/**
 * Deprecated. Instead, use:
 *
 * var decipher = cipherApi.createDecipher('DES-<mode>', key);
 *
 * Creates an DES cipher object to decrypt data using the given symmetric key.
 *
 * The key may be given as a binary-encoded string of bytes or a byte buffer.
 *
 * @param key the symmetric key to use (64 or 192 bits).
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function createDecryptionCipher(key: unknown, mode?: string) {
  return _createCipher({
    key: key,
    output: null,
    decrypt: true,
    mode: mode
  });
}

/**
 * Deprecated. Instead, use:
 *
 * cipherApi.createCipher('DES-<mode>', key);
 * cipherApi.createDecipher('DES-<mode>', key);
 *
 * Creates a deprecated DES cipher object. This object's mode will default to
 * CBC (cipher-block-chaining).
 *
 * The key may be given as a binary-encoded string of bytes or a byte buffer.
 *
 * @param options the options to use.
 *          key the symmetric key to use (64 or 192 bits).
 *          output the buffer to write to.
 *          decrypt true for decryption, false for encryption.
 *          mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function _createCipher(options?: CreateCipherOptions) {
  options = options || {};
  const mode = (options.mode || 'CBC').toUpperCase();
  const algorithm = 'DES-' + mode;

  let cipher;
  if (options.decrypt) {
    cipher = cipherApi.createDecipher(algorithm, options.key);
  } else {
    cipher = cipherApi.createCipher(algorithm, options.key);
  }

  // backwards compatible start API
  const start = cipher.start;
  cipher.start = function (iv, options) {
    // backwards compatibility: support second arg as output buffer
    let output = null;
    if (options instanceof ByteStringBuffer) {
      output = options;
      options = {};
    }
    options = options || {};
    (options as Record<string, unknown>).output = output;
    (options as Record<string, unknown>).iv = iv;
    start.call(cipher, options);
  };

  return cipher;
}

function registerAlgorithm(name: string, mode: ModeConstructor<DesAlgorithm['mode']>): void {
  const factory = () => new DesAlgorithm(name, mode);
  cipherApi.registerAlgorithm(name, factory);
}

/**
 * DES (Data Encryption Standard) cipher algorithm.
 */
export class DesAlgorithm {
  static #spfunction1: number[] | null = null;
  static #spfunction2: number[] | null = null;
  static #spfunction3: number[] | null = null;
  static #spfunction4: number[] | null = null;
  static #spfunction5: number[] | null = null;
  static #spfunction6: number[] | null = null;
  static #spfunction7: number[] | null = null;
  static #spfunction8: number[] | null = null;
  static #pc2bytes0: number[] | null = null;
  static #pc2bytes1: number[] | null = null;
  static #pc2bytes2: number[] | null = null;
  static #pc2bytes3: number[] | null = null;
  static #pc2bytes4: number[] | null = null;
  static #pc2bytes5: number[] | null = null;
  static #pc2bytes6: number[] | null = null;
  static #pc2bytes7: number[] | null = null;
  static #pc2bytes8: number[] | null = null;
  static #pc2bytes9: number[] | null = null;
  static #pc2bytes10: number[] | null = null;
  static #pc2bytes11: number[] | null = null;
  static #pc2bytes12: number[] | null = null;
  static #pc2bytes13: number[] | null = null;
  static #initialized = false;

  static #ensureInit(): void {
    if (DesAlgorithm.#initialized) {
      return;
    }
    DesAlgorithm.#spfunction1 = [
      0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004,
      0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004,
      0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000,
      0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400,
      0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004
    ];
    DesAlgorithm.#spfunction2 = [
      -0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000,
      -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000,
      0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0,
      -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020,
      -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000,
      -0x7fefffe0, -0x7fef7fe0, 0x108000
    ];
    DesAlgorithm.#spfunction3 = [
      0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008,
      0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208,
      0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208,
      0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000,
      0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200
    ];
    DesAlgorithm.#spfunction4 = [
      0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001,
      0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81,
      0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80,
      0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000,
      0x802080
    ];
    DesAlgorithm.#spfunction5 = [
      0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100,
      0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100,
      0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000,
      0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100,
      0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000,
      0x2080100, 0x40000100
    ];
    DesAlgorithm.#spfunction6 = [
      0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010,
      0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0,
      0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010,
      0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0,
      0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010
    ];
    DesAlgorithm.#spfunction7 = [
      0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000,
      0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802,
      0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2,
      0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0,
      0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002
    ];
    DesAlgorithm.#spfunction8 = [
      0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000,
      0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0,
      0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040,
      0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000,
      0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000
    ];
    DesAlgorithm.#pc2bytes0 = [
      0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204,
      0x20010200, 0x20010204
    ];
    DesAlgorithm.#pc2bytes1 = [
      0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101,
      0x4100100, 0x4100101
    ];
    DesAlgorithm.#pc2bytes2 = [
      0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808
    ];
    DesAlgorithm.#pc2bytes3 = [
      0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000,
      0x8022000, 0x8222000
    ];
    DesAlgorithm.#pc2bytes4 = [
      0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010
    ];
    DesAlgorithm.#pc2bytes5 = [
      0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420
    ];
    DesAlgorithm.#pc2bytes6 = [
      0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002,
      0x80002, 0x10080002
    ];
    DesAlgorithm.#pc2bytes7 = [
      0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000,
      0x20030000, 0x20020800, 0x20030800
    ];
    DesAlgorithm.#pc2bytes8 = [
      0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002,
      0x2040002
    ];
    DesAlgorithm.#pc2bytes9 = [
      0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408,
      0x10000408
    ];
    DesAlgorithm.#pc2bytes10 = [
      0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020
    ];
    DesAlgorithm.#pc2bytes11 = [
      0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000,
      0x5200000, 0x4200200, 0x5200200
    ];
    DesAlgorithm.#pc2bytes12 = [
      0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010,
      0x8080010, 0x8081010
    ];
    DesAlgorithm.#pc2bytes13 = [0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105];
    DesAlgorithm.#initialized = true;
  }

  readonly name: string;
  readonly mode: {
    blockSize: number;
    name?: string;
    start: (options: Record<string, unknown>) => void;
    encrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    decrypt: (input: ByteStringBuffer, output: ByteStringBuffer, finish: boolean) => boolean | void;
    pad?: (input: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    unpad?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
    afterFinish?: (output: ByteStringBuffer, options: Record<string, unknown>) => boolean;
  };

  #keys: number[] | null = null;
  #init = false;

  constructor(name: string, mode: ModeConstructor<DesAlgorithm['mode']>) {
    DesAlgorithm.#ensureInit();
    this.name = name;
    this.mode = new mode({
      blockSize: 8,
      cipher: {
        encrypt: (inBlock: number[], outBlock: number[]) => {
          DesAlgorithm.#updateBlock(this.#keys!, inBlock, outBlock, false);
        },
        decrypt: (inBlock: number[], outBlock: number[]) => {
          DesAlgorithm.#updateBlock(this.#keys!, inBlock, outBlock, true);
        }
      } satisfies BlockCipherApi
    });
  }

  /**
   * Initializes this DES algorithm by expanding its key.
   *
   * @param options the options to use.
   *          key the key to use with this algorithm.
   *          decrypt true if the algorithm should be initialized for decryption,
   *            false for encryption.
   */
  initialize(options: InitializeOptions): void {
    if (this.#init) {
      return;
    }

    const key = UtilNamespace.createBuffer(options.key);
    if (this.name.indexOf('3DES') === 0) {
      if (key.length() !== 24) {
        throw new Error('Invalid Triple-DES key size: ' + key.length() * 8);
      }
    }

    // do key expansion to 16 or 48 subkeys (single or triple DES)
    this.#keys = DesAlgorithm.#createKeys(key);
    this.#init = true;
  }

  static #createKeys(key: ByteStringBuffer): number[] {
    DesAlgorithm.#ensureInit();

    // how many iterations (1 for des, 3 for triple des)
    // changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
    const iterations = key.length() > 8 ? 3 : 1;

    // stores the return keys
    const keys: number[] = [];

    // now define the left shifts which need to be done
    const shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];

    let n = 0;
    let tmp: number;
    for (let j = 0; j < iterations; j++) {
      let left = key.getInt32();
      let right = key.getInt32();

      tmp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
      right ^= tmp;
      left ^= tmp << 4;

      tmp = ((right >>> -16) ^ left) & 0x0000ffff;
      left ^= tmp;
      right ^= tmp << -16;

      tmp = ((left >>> 2) ^ right) & 0x33333333;
      right ^= tmp;
      left ^= tmp << 2;

      tmp = ((right >>> -16) ^ left) & 0x0000ffff;
      left ^= tmp;
      right ^= tmp << -16;

      tmp = ((left >>> 1) ^ right) & 0x55555555;
      right ^= tmp;
      left ^= tmp << 1;

      tmp = ((right >>> 8) ^ left) & 0x00ff00ff;
      left ^= tmp;
      right ^= tmp << 8;

      tmp = ((left >>> 1) ^ right) & 0x55555555;
      right ^= tmp;
      left ^= tmp << 1;

      // right needs to be shifted and OR'd with last four bits of left
      tmp = (left << 8) | ((right >>> 20) & 0x000000f0);

      // left needs to be put upside down
      left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
      right = tmp;

      // now go through and perform these shifts on the left and right keys
      for (let i = 0; i < shifts.length; ++i) {
        //shift the keys either one or two bits to the left
        if (shifts[i]) {
          left = (left << 2) | (left >>> 26);
          right = (right << 2) | (right >>> 26);
        } else {
          left = (left << 1) | (left >>> 27);
          right = (right << 1) | (right >>> 27);
        }
        left &= -0xf;
        right &= -0xf;

        // now apply PC-2, in such a way that E is easier when encrypting or
        // decrypting this conversion will look like PC-2 except only the last 6
        // bits of each byte are used rather than 48 consecutive bits and the
        // order of lines will be according to how the S selection functions will
        // be applied: S2, S4, S6, S8, S1, S3, S5, S7
        const lefttmp =
          DesAlgorithm.#pc2bytes0![left >>> 28]! |
          DesAlgorithm.#pc2bytes1![(left >>> 24) & 0xf]! |
          DesAlgorithm.#pc2bytes2![(left >>> 20) & 0xf]! |
          DesAlgorithm.#pc2bytes3![(left >>> 16) & 0xf]! |
          DesAlgorithm.#pc2bytes4![(left >>> 12) & 0xf]! |
          DesAlgorithm.#pc2bytes5![(left >>> 8) & 0xf]! |
          DesAlgorithm.#pc2bytes6![(left >>> 4) & 0xf]!;
        const righttmp =
          DesAlgorithm.#pc2bytes7![right >>> 28]! |
          DesAlgorithm.#pc2bytes8![(right >>> 24) & 0xf]! |
          DesAlgorithm.#pc2bytes9![(right >>> 20) & 0xf]! |
          DesAlgorithm.#pc2bytes10![(right >>> 16) & 0xf]! |
          DesAlgorithm.#pc2bytes11![(right >>> 12) & 0xf]! |
          DesAlgorithm.#pc2bytes12![(right >>> 8) & 0xf]! |
          DesAlgorithm.#pc2bytes13![(right >>> 4) & 0xf]!;
        tmp = ((righttmp >>> 16) ^ lefttmp) & 0x0000ffff;
        keys[n++] = lefttmp ^ tmp;
        keys[n++] = righttmp ^ (tmp << 16);
      }
    }

    return keys;
  }

  static #updateBlock(keys: number[], input: number[], output: number[], decrypt: boolean): void {
    DesAlgorithm.#ensureInit();

    // set up loops for single or triple DES
    const iterations = keys.length === 32 ? 3 : 9;
    let looping: number[];
    if (iterations === 3) {
      looping = decrypt ? [30, -2, -2] : [0, 32, 2];
    } else {
      looping = decrypt ? [94, 62, -2, 32, 64, 2, 30, -2, -2] : [0, 32, 2, 62, 30, -2, 64, 96, 2];
    }

    let tmp: number;

    let left = input[0]!;
    let right = input[1]!;

    // first each 64 bit chunk of the message must be permuted according to IP
    tmp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= tmp;
    left ^= tmp << 4;

    tmp = ((left >>> 16) ^ right) & 0x0000ffff;
    right ^= tmp;
    left ^= tmp << 16;

    tmp = ((right >>> 2) ^ left) & 0x33333333;
    left ^= tmp;
    right ^= tmp << 2;

    tmp = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= tmp;
    right ^= tmp << 8;

    tmp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= tmp;
    left ^= tmp << 1;

    // rotate left 1 bit
    left = (left << 1) | (left >>> 31);
    right = (right << 1) | (right >>> 31);

    for (let j = 0; j < iterations; j += 3) {
      const endloop = looping[j + 1]!;
      const loopinc = looping[j + 2]!;

      // now go through and perform the encryption or decryption
      for (let i = looping[j]!; i != endloop; i += loopinc) {
        const right1 = right ^ keys[i]!;
        const right2 = ((right >>> 4) | (right << 28)) ^ keys[i + 1]!;

        // passing these bytes through the S selection functions
        tmp = left;
        left = right;
        right =
          tmp ^
          (DesAlgorithm.#spfunction2![(right1 >>> 24) & 0x3f]! |
            DesAlgorithm.#spfunction4![(right1 >>> 16) & 0x3f]! |
            DesAlgorithm.#spfunction6![(right1 >>> 8) & 0x3f]! |
            DesAlgorithm.#spfunction8![right1 & 0x3f]! |
            DesAlgorithm.#spfunction1![(right2 >>> 24) & 0x3f]! |
            DesAlgorithm.#spfunction3![(right2 >>> 16) & 0x3f]! |
            DesAlgorithm.#spfunction5![(right2 >>> 8) & 0x3f]! |
            DesAlgorithm.#spfunction7![right2 & 0x3f]!);
      }
      // unreverse left and right
      tmp = left;
      left = right;
      right = tmp;
    }

    // rotate right 1 bit
    left = (left >>> 1) | (left << 31);
    right = (right >>> 1) | (right << 31);

    // now perform IP-1, which is IP in the opposite direction
    tmp = ((left >>> 1) ^ right) & 0x55555555;
    right ^= tmp;
    left ^= tmp << 1;

    tmp = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= tmp;
    right ^= tmp << 8;

    tmp = ((right >>> 2) ^ left) & 0x33333333;
    left ^= tmp;
    right ^= tmp << 2;

    tmp = ((left >>> 16) ^ right) & 0x0000ffff;
    right ^= tmp;
    left ^= tmp << 16;

    tmp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= tmp;
    left ^= tmp << 4;

    output[0] = left;
    output[1] = right;
  }

  static registerAlgorithms(cipher: CipherApi<DesAlgorithm['mode']>): void {
    cipherApi = cipher;
    registerAlgorithm('DES-ECB', cipherApi.modes.ecb);
    registerAlgorithm('DES-CBC', cipherApi.modes.cbc);
    registerAlgorithm('DES-CFB', cipherApi.modes.cfb);
    registerAlgorithm('DES-OFB', cipherApi.modes.ofb);
    registerAlgorithm('DES-CTR', cipherApi.modes.ctr);

    registerAlgorithm('3DES-ECB', cipherApi.modes.ecb);
    registerAlgorithm('3DES-CBC', cipherApi.modes.cbc);
    registerAlgorithm('3DES-CFB', cipherApi.modes.cfb);
    registerAlgorithm('3DES-OFB', cipherApi.modes.ofb);
    registerAlgorithm('3DES-CTR', cipherApi.modes.ctr);
  }

  static createCertkitNamespace(): DesNamespaceObject {
    return {
      startEncrypting,
      createEncryptionCipher,
      startDecrypting,
      createDecryptionCipher,
      Algorithm: DesAlgorithm
    } as DesNamespaceObject;
  }
}

export default DesAlgorithm;

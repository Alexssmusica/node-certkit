/* Migrated from lib/aes.js */
import { UtilNamespace } from '../util/UtilNamespace.js';
import { isArray } from '../util/typeChecks.js';
import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { BlockCipherApi } from './CipherTypes.js';
import { CipherApi, CreateCipherOptions, ModeConstructor, type AesNamespaceObject } from './CipherTypes.js';
import { ensureAesTables } from './AesTables.js';

type InitializeOptions = {
  key: string | number[] | ByteStringBuffer | unknown;
  decrypt?: boolean;
};

let cipherApi: CipherApi<AesAlgorithm['mode']>;

const Nb = 4;

/**
 * Advanced Encryption Standard (AES) implementation.
 *
 * This implementation is based on the public domain library 'jscrypto' which
 * was written by:
 *
 * Emily Stark (estark@stanford.edu)
 * Mike Hamburg (mhamburg@stanford.edu)
 * Dan Boneh (dabo@cs.stanford.edu)
 *
 * Parts of this code are based on the OpenSSL implementation of AES:
 * http://www.openssl.org
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */

/**
 * Deprecated. Instead, use:
 *
 * var cipher = cipherApi.createCipher('AES-<mode>', key);
 * cipher.start({iv: iv});
 *
 * Creates an AES cipher object to encrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as a string of bytes, an array of bytes,
 * a byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function startEncrypting(key: unknown, iv: unknown, output: ByteStringBuffer | null, mode?: string) {
  const cipher = _createCipher({
    key: key,
    output: output,
    decrypt: false,
    mode: mode
  });
  cipher.start(iv);
  return cipher;
}

/**
 * Deprecated. Instead, use:
 *
 * var cipher = cipherApi.createCipher('AES-<mode>', key);
 *
 * Creates an AES cipher object to encrypt data using the given symmetric key.
 *
 * The key may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
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
 * var decipher = cipherApi.createDecipher('AES-<mode>', key);
 * decipher.start({iv: iv});
 *
 * Creates an AES cipher object to decrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as a string of bytes, an array of bytes,
 * a byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function startDecrypting(key: unknown, iv: unknown, output: ByteStringBuffer | null, mode?: string) {
  const cipher = _createCipher({
    key: key,
    output: output,
    decrypt: true,
    mode: mode
  });
  cipher.start(iv);
  return cipher;
}

/**
 * Deprecated. Instead, use:
 *
 * var decipher = cipherApi.createDecipher('AES-<mode>', key);
 *
 * Creates an AES cipher object to decrypt data using the given symmetric key.
 *
 * The key may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
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
 * cipherApi.createCipher('AES-<mode>', key);
 * cipherApi.createDecipher('AES-<mode>', key);
 *
 * Creates a deprecated AES cipher object. This object's mode will default to
 * CBC (cipher-block-chaining).
 *
 * The key and iv may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words.
 *
 * @param options the options to use.
 *          key the symmetric key to use.
 *          output the buffer to write to.
 *          decrypt true for decryption, false for encryption.
 *          mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
function _createCipher(options?: CreateCipherOptions) {
  options = options || {};
  const mode = (options.mode || 'CBC').toUpperCase();
  const algorithm = 'AES-' + mode;

  let cipher;
  if (options.decrypt) {
    cipher = cipherApi.createDecipher(algorithm, options.key);
  } else {
    cipher = cipherApi.createCipher(algorithm, options.key);
  }

  // backwards compatible start API
  const start = cipher.start;
  cipher.start = function (iv: unknown, startOptions: unknown) {
    // backwards compatibility: support second arg as output buffer
    let output: ByteStringBuffer | null = null;
    let opts: Record<string, unknown>;
    if (startOptions instanceof ByteStringBuffer) {
      output = startOptions;
      opts = {};
    } else {
      opts = (startOptions as Record<string, unknown>) || {};
    }
    opts.output = output;
    opts.iv = iv;
    start.call(cipher, opts);
  };

  return cipher;
}

function registerAlgorithm(name: string, mode: ModeConstructor<AesAlgorithm['mode']>): void {
  const factory = () => new AesAlgorithm(name, mode);
  cipherApi.registerAlgorithm(name, factory);
}

/**
 * Advanced Encryption Standard (AES) cipher algorithm.
 */
export class AesAlgorithm {
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

  #w: number[] | null = null;
  #init = false;

  constructor(name: string, mode: ModeConstructor<AesAlgorithm['mode']>) {
    ensureAesTables();
    this.name = name;
    this.mode = new mode({
      blockSize: 16,
      cipher: {
        encrypt: (inBlock: number[], outBlock: number[]) => {
          AesAlgorithm.#updateBlock(this.#w!, inBlock, outBlock, false);
        },
        decrypt: (inBlock: number[], outBlock: number[]) => {
          AesAlgorithm.#updateBlock(this.#w!, inBlock, outBlock, true);
        }
      } satisfies BlockCipherApi
    });
  }

  /**
   * Initializes this AES algorithm by expanding its key.
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

    let key: string | number[] | ByteStringBuffer | unknown = options.key;
    let tmp: number[] | ByteStringBuffer;

    /* Note: The key may be a string of bytes, an array of bytes, a byte
      buffer, or an array of 32-bit integers. If the key is in bytes, then
      it must be 16, 24, or 32 bytes in length. If it is in 32-bit
      integers, it must be 4, 6, or 8 integers long. */

    if (typeof key === 'string' && (key.length === 16 || key.length === 24 || key.length === 32)) {
      key = UtilNamespace.createBuffer(key);
    } else if (isArray(key) && (key.length === 16 || key.length === 24 || key.length === 32)) {
      tmp = key as number[];
      key = UtilNamespace.createBuffer();
      for (let i = 0; i < tmp.length; ++i) {
        (key as ByteStringBuffer).putByte(tmp[i]!);
      }
    }

    let keyWords: number[];
    if (!isArray(key)) {
      tmp = key as ByteStringBuffer;
      keyWords = [];

      const len = tmp.length();
      if (len === 16 || len === 24 || len === 32) {
        const wordCount = len >>> 2;
        for (let i = 0; i < wordCount; ++i) {
          keyWords.push(tmp.getInt32());
        }
      } else {
        keyWords = [];
      }
    } else {
      keyWords = key as number[];
    }

    if (!isArray(keyWords) || !(keyWords.length === 4 || keyWords.length === 6 || keyWords.length === 8)) {
      throw new Error('Invalid key parameter.');
    }

    const modeName = this.mode.name;
    const encryptOp = ['CFB', 'OFB', 'CTR', 'GCM'].indexOf(modeName!) !== -1;

    this.#w = AesAlgorithm.#expandKey(keyWords, !!(options.decrypt && !encryptOp));
    this.#init = true;
  }

  static #expandKey(key: number[], decrypt: boolean): number[] {
    const { sbox, rcon, imix } = ensureAesTables();

    // copy the key's words to initialize the key schedule
    let w = key.slice(0);

    /* RotWord() will rotate a word, moving the first byte to the last
    byte's position (shifting the other bytes left).

    We will be getting the value of Rcon at i / Nk. 'i' will iterate
    from Nk to (Nb * Nr+1). Nk = 4 (4 byte key), Nb = 4 (4 words in
    a block), Nr = Nk + 6 (10). Therefore 'i' will iterate from
    4 to 44 (exclusive). Each time we iterate 4 times, i / Nk will
    increase by 1. We use a counter iNk to keep track of this.
   */

    // go through the rounds expanding the key
    let temp,
      iNk = 1;
    const Nk = w.length;
    const Nr1 = Nk + 6 + 1;
    let end = Nb * Nr1;
    for (let i = Nk; i < end; ++i) {
      temp = w[i - 1];
      if (i % Nk === 0) {
        // temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk]
        temp =
          (sbox[(temp >>> 16) & 255] << 24) ^
          (sbox[(temp >>> 8) & 255] << 16) ^
          (sbox[temp & 255] << 8) ^
          sbox[temp >>> 24] ^
          (rcon[iNk] << 24);
        iNk++;
      } else if (Nk > 6 && i % Nk === 4) {
        // temp = SubWord(temp)
        temp =
          (sbox[temp >>> 24] << 24) ^
          (sbox[(temp >>> 16) & 255] << 16) ^
          (sbox[(temp >>> 8) & 255] << 8) ^
          sbox[temp & 255];
      }
      w[i] = w[i - Nk] ^ temp;
    }

    /* When we are updating a cipher block we always use the code path for
     encryption whether we are decrypting or not (to shorten code and
     simplify the generation of look up tables). However, because there
     are differences in the decryption algorithm, other than just swapping
     in different look up tables, we must transform our key schedule to
     account for these changes:

     1. The decryption algorithm gets its key rounds in reverse order.
     2. The decryption algorithm adds the round key before mixing columns
       instead of afterwards.

     We don't need to modify our key schedule to handle the first case,
     we can just traverse the key schedule in reverse order when decrypting.

     The second case requires a little work.

     The tables we built for performing rounds will take an input and then
     perform SubBytes() and MixColumns() or, for the decrypt version,
     InvSubBytes() and InvMixColumns(). But the decrypt algorithm requires
     us to AddRoundKey() before InvMixColumns(). This means we'll need to
     apply some transformations to the round key to inverse-mix its columns
     so they'll be correct for moving AddRoundKey() to after the state has
     had its columns inverse-mixed.

     To inverse-mix the columns of the state when we're decrypting we use a
     lookup table that will apply InvSubBytes() and InvMixColumns() at the
     same time. However, the round key's bytes are not inverse-substituted
     in the decryption algorithm. To get around this problem, we can first
     substitute the bytes in the round key so that when we apply the
     transformation via the InvSubBytes()+InvMixColumns() table, it will
     undo our substitution leaving us with the original value that we
     want -- and then inverse-mix that value.

     This change will correctly alter our key schedule so that we can XOR
     each round key with our already transformed decryption state. This
     allows us to use the same code path as the encryption algorithm.

     We make one more change to the decryption key. Since the decryption
     algorithm runs in reverse from the encryption algorithm, we reverse
     the order of the round keys to avoid having to iterate over the key
     schedule backwards when running the encryption algorithm later in
     decryption mode. In addition to reversing the order of the round keys,
     we also swap each round key's 2nd and 4th rows. See the comments
     section where rounds are performed for more details about why this is
     done. These changes are done inline with the other substitution
     described above.
  */
    if (decrypt) {
      let tmp;
      const m0 = imix[0];
      const m1 = imix[1];
      const m2 = imix[2];
      const m3 = imix[3];
      const wnew = w.slice(0);
      end = w.length;
      for (let i = 0, wi = end - Nb; i < end; i += Nb, wi -= Nb) {
        // do not sub the first or last round key (round keys are Nb
        // words) as no column mixing is performed before they are added,
        // but do change the key order
        if (i === 0 || i === end - Nb) {
          wnew[i] = w[wi];
          wnew[i + 1] = w[wi + 3];
          wnew[i + 2] = w[wi + 2];
          wnew[i + 3] = w[wi + 1];
        } else {
          // substitute each round key byte because the inverse-mix
          // table will inverse-substitute it (effectively cancel the
          // substitution because round key bytes aren't sub'd in
          // decryption mode) and swap indexes 3 and 1
          for (let n = 0; n < Nb; ++n) {
            tmp = w[wi + n];
            wnew[i + (3 & -n)] =
              m0[sbox[tmp >>> 24]] ^ m1[sbox[(tmp >>> 16) & 255]] ^ m2[sbox[(tmp >>> 8) & 255]] ^ m3[sbox[tmp & 255]];
          }
        }
      }
      w = wnew;
    }

    return w;
  }

  static #updateBlock(w: number[], input: number[], output: number[], decrypt: boolean): void {
    const { sbox, isbox, mix, imix } = ensureAesTables();

    /*
  Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte state[4,Nb]
    state = in
    AddRoundKey(state, w[0, Nb-1])
    for round = 1 step 1 to Nr-1
      SubBytes(state)
      ShiftRows(state)
      MixColumns(state)
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    end for
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    out = state
  end

  InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte state[4,Nb]
    state = in
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    for round = Nr-1 step -1 downto 1
      InvShiftRows(state)
      InvSubBytes(state)
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
      InvMixColumns(state)
    end for
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, w[0, Nb-1])
    out = state
  end
  */

    // Encrypt: AddRoundKey(state, w[0, Nb-1])
    // Decrypt: AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    const Nr = w.length / 4 - 1;
    let m0, m1, m2, m3, sub;
    if (decrypt) {
      m0 = imix[0];
      m1 = imix[1];
      m2 = imix[2];
      m3 = imix[3];
      sub = isbox;
    } else {
      m0 = mix[0];
      m1 = mix[1];
      m2 = mix[2];
      m3 = mix[3];
      sub = sbox;
    }
    let a, b, c, d, a2, b2, c2;
    a = input[0] ^ w[0];
    b = input[decrypt ? 3 : 1] ^ w[1];
    c = input[2] ^ w[2];
    d = input[decrypt ? 1 : 3] ^ w[3];
    let i = 3;

    /* In order to share code we follow the encryption algorithm when both
    encrypting and decrypting. To account for the changes required in the
    decryption algorithm, we use different lookup tables when decrypting
    and use a modified key schedule to account for the difference in the
    order of transformations applied when performing rounds. We also get
    key rounds in reverse order (relative to encryption). */
    for (let round = 1; round < Nr; ++round) {
      /* As described above, we'll be using table lookups to perform the
      column mixing. Each column is stored as a word in the state (the
      array 'input' has one column as a word at each index). In order to
      AesAlgorithm.#mix! a column, we perform these transformations on each row in c,
      which is 1 byte in each word. The new column for c0 is c'0:

               m0      m1      m2      m3
      r0,c'0 = 2*r0,c0 + 3*r1,c0 + 1*r2,c0 + 1*r3,c0
      r1,c'0 = 1*r0,c0 + 2*r1,c0 + 3*r2,c0 + 1*r3,c0
      r2,c'0 = 1*r0,c0 + 1*r1,c0 + 2*r2,c0 + 3*r3,c0
      r3,c'0 = 3*r0,c0 + 1*r1,c0 + 1*r2,c0 + 2*r3,c0

      So using AesAlgorithm.#mix! tables where c0 is a word with r0 being its upper
      8 bits and r3 being its lower 8 bits:

      m0[c0 >> 24] will yield this word: [2*r0,1*r0,1*r0,3*r0]
      ...
      m3[c0 & 255] will yield this word: [1*r3,1*r3,3*r3,2*r3]

      Therefore to AesAlgorithm.#mix! the columns in each word in the state we
      do the following (& 255 omitted for brevity):
      c'0,r0 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r1 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r2 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r3 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]

      However, before mixing, the algorithm requires us to perform
      ShiftRows(). The ShiftRows() transformation cyclically shifts the
      last 3 rows of the state over different offsets. The first row
      (r = 0) is not shifted.

      s'_r,c = s_r,(c + shift(r, Nb) mod Nb
      for 0 < r < 4 and 0 <= c < Nb and
      shift(1, 4) = 1
      shift(2, 4) = 2
      shift(3, 4) = 3.

      This causes the first byte in r = 1 to be moved to the end of
      the row, the first 2 bytes in r = 2 to be moved to the end of
      the row, the first 3 bytes in r = 3 to be moved to the end of
      the row:

      r1: [c0 c1 c2 c3] => [c1 c2 c3 c0]
      r2: [c0 c1 c2 c3]    [c2 c3 c0 c1]
      r3: [c0 c1 c2 c3]    [c3 c0 c1 c2]

      We can make these substitutions inline with our column mixing to
      generate an updated set of equations to produce each word in the
      state (note the columns have changed positions):

      c0 c1 c2 c3 => c0 c1 c2 c3
      c0 c1 c2 c3    c1 c2 c3 c0  (cycled 1 byte)
      c0 c1 c2 c3    c2 c3 c0 c1  (cycled 2 bytes)
      c0 c1 c2 c3    c3 c0 c1 c2  (cycled 3 bytes)

      Therefore:

      c'0 = 2*r0,c0 + 3*r1,c1 + 1*r2,c2 + 1*r3,c3
      c'0 = 1*r0,c0 + 2*r1,c1 + 3*r2,c2 + 1*r3,c3
      c'0 = 1*r0,c0 + 1*r1,c1 + 2*r2,c2 + 3*r3,c3
      c'0 = 3*r0,c0 + 1*r1,c1 + 1*r2,c2 + 2*r3,c3

      c'1 = 2*r0,c1 + 3*r1,c2 + 1*r2,c3 + 1*r3,c0
      c'1 = 1*r0,c1 + 2*r1,c2 + 3*r2,c3 + 1*r3,c0
      c'1 = 1*r0,c1 + 1*r1,c2 + 2*r2,c3 + 3*r3,c0
      c'1 = 3*r0,c1 + 1*r1,c2 + 1*r2,c3 + 2*r3,c0

      ... and so forth for c'2 and c'3. The important distinction is
      that the columns are cycling, with c0 being used with the m0
      map when calculating c0, but c1 being used with the m0 map when
      calculating c1 ... and so forth.

      When performing the inverse we transform the mirror image and
      skip the bottom row, instead of the top one, and move upwards:

      c3 c2 c1 c0 => c0 c3 c2 c1  (cycled 3 bytes) *same as encryption
      c3 c2 c1 c0    c1 c0 c3 c2  (cycled 2 bytes)
      c3 c2 c1 c0    c2 c1 c0 c3  (cycled 1 byte)  *same as encryption
      c3 c2 c1 c0    c3 c2 c1 c0

      If you compare the resulting matrices for ShiftRows()+MixColumns()
      and for InvShiftRows()+InvMixColumns() the 2nd and 4th columns are
      different (in encrypt mode vs. decrypt mode). So in order to use
      the same code to handle both encryption and decryption, we will
      need to do some mapping.

      If in encryption mode we let a=c0, b=c1, c=c2, d=c3, and r<N> be
      a row number in the state, then the resulting matrix in encryption
      mode for applying the above transformations would be:

      r1: a b c d
      r2: b c d a
      r3: c d a b
      r4: d a b c

      If we did the same in decryption mode we would get:

      r1: a d c b
      r2: b a d c
      r3: c b a d
      r4: d c b a

      If instead we swap d and b (set b=c3 and d=c1), then we get:

      r1: a b c d
      r2: d a b c
      r3: c d a b
      r4: b c d a

      Now the 1st and 3rd rows are the same as the encryption matrix. All
      we need to do then to make the mapping exactly the same is to swap
      the 2nd and 4th rows when in decryption mode. To do this without
      having to do it on each iteration, we swapped the 2nd and 4th rows
      in the decryption key schedule. We also have to do the swap above
      when we first pull in the input and when we set the final output. */
      a2 = m0[a >>> 24] ^ m1[(b >>> 16) & 255] ^ m2[(c >>> 8) & 255] ^ m3[d & 255] ^ w[++i];
      b2 = m0[b >>> 24] ^ m1[(c >>> 16) & 255] ^ m2[(d >>> 8) & 255] ^ m3[a & 255] ^ w[++i];
      c2 = m0[c >>> 24] ^ m1[(d >>> 16) & 255] ^ m2[(a >>> 8) & 255] ^ m3[b & 255] ^ w[++i];
      d = m0[d >>> 24] ^ m1[(a >>> 16) & 255] ^ m2[(b >>> 8) & 255] ^ m3[c & 255] ^ w[++i];
      a = a2;
      b = b2;
      c = c2;
    }

    /*
    Encrypt:
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])

    Decrypt:
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, w[0, Nb-1])
   */
    // Note: rows are shifted inline
    output[0] =
      (sub[a >>> 24] << 24) ^ (sub[(b >>> 16) & 255] << 16) ^ (sub[(c >>> 8) & 255] << 8) ^ sub[d & 255] ^ w[++i];
    output[decrypt ? 3 : 1] =
      (sub[b >>> 24] << 24) ^ (sub[(c >>> 16) & 255] << 16) ^ (sub[(d >>> 8) & 255] << 8) ^ sub[a & 255] ^ w[++i];
    output[2] =
      (sub[c >>> 24] << 24) ^ (sub[(d >>> 16) & 255] << 16) ^ (sub[(a >>> 8) & 255] << 8) ^ sub[b & 255] ^ w[++i];
    output[decrypt ? 1 : 3] =
      (sub[d >>> 24] << 24) ^ (sub[(a >>> 16) & 255] << 16) ^ (sub[(b >>> 8) & 255] << 8) ^ sub[c & 255] ^ w[++i];
  }

  static registerAlgorithms(cipher: CipherApi<AesAlgorithm['mode']>): void {
    cipherApi = cipher;
    registerAlgorithm('AES-ECB', cipherApi.modes.ecb);
    registerAlgorithm('AES-CBC', cipherApi.modes.cbc);
    registerAlgorithm('AES-CFB', cipherApi.modes.cfb);
    registerAlgorithm('AES-OFB', cipherApi.modes.ofb);
    registerAlgorithm('AES-CTR', cipherApi.modes.ctr);
    registerAlgorithm('AES-GCM', cipherApi.modes.gcm);
  }

  static createCertkitNamespace(): AesNamespaceObject {
    return {
      startEncrypting,
      createEncryptionCipher,
      startDecrypting,
      createDecryptionCipher,
      Algorithm: AesAlgorithm,
      _expandKey: (key: number[], decrypt: boolean) => AesAlgorithm.#expandKey(key, decrypt),
      _updateBlock: (w: number[], input: number[], output: number[], decrypt: boolean) =>
        AesAlgorithm.#updateBlock(w, input, output, decrypt)
    } as AesNamespaceObject;
  }
}

export default AesAlgorithm;

/**
 * Base-N/Base-X encoding and decoding.
 */
type ByteBufferLike = {
  length(): number;
  at(i: number): number;
};

export class BaseNCodec {
  static #reverseAlphabets: Record<string, number[]> = {};

  static encode(input: Uint8Array | ByteBufferLike, alphabet: string, maxline?: number): string {
    if (typeof alphabet !== 'string') {
      throw new TypeError('"alphabet" must be a string.');
    }
    if (maxline !== undefined && typeof maxline !== 'number') {
      throw new TypeError('"maxline" must be a number.');
    }

    let output = '';

    if (!(input instanceof Uint8Array)) {
      output = BaseNCodec.#encodeWithByteBuffer(input, alphabet);
    } else {
      let i = 0;
      const base = alphabet.length;
      const first = alphabet.charAt(0);
      const digits = [0];
      for (i = 0; i < input.length; ++i) {
        let carry = input[i]!;
        for (let j = 0; j < digits.length; ++j) {
          carry += digits[j]! << 8;
          digits[j] = carry % base;
          carry = (carry / base) | 0;
        }

        while (carry > 0) {
          digits.push(carry % base);
          carry = (carry / base) | 0;
        }
      }

      for (i = 0; input[i] === 0 && i < input.length - 1; ++i) {
        output += first;
      }
      for (i = digits.length - 1; i >= 0; --i) {
        output += alphabet[digits[i]!];
      }
    }

    if (maxline) {
      const regex = new RegExp('.{1,' + maxline + '}', 'g');
      output = output.match(regex)!.join('\r\n');
    }

    return output;
  }

  static decode(input: string, alphabet: string): Buffer | Uint8Array | undefined {
    if (typeof input !== 'string') {
      throw new TypeError('"input" must be a string.');
    }
    if (typeof alphabet !== 'string') {
      throw new TypeError('"alphabet" must be a string.');
    }

    let table = BaseNCodec.#reverseAlphabets[alphabet];
    if (!table) {
      table = BaseNCodec.#reverseAlphabets[alphabet] = [];
      for (let i = 0; i < alphabet.length; ++i) {
        table[alphabet.charCodeAt(i)] = i;
      }
    }

    input = input.replace(/\s/g, '');

    const base = alphabet.length;
    const first = alphabet.charAt(0);
    const bytes = [0];
    for (let i = 0; i < input.length; i++) {
      const value = table[input.charCodeAt(i)];
      if (value === undefined) {
        return;
      }

      let carry = value;
      for (let j = 0; j < bytes.length; ++j) {
        carry += bytes[j]! * base;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }

      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }

    for (let k = 0; input[k] === first && k < input.length - 1; ++k) {
      bytes.push(0);
    }

    return Buffer.from(bytes.reverse());
  }

  static #encodeWithByteBuffer(input: ByteBufferLike, alphabet: string): string {
    let i = 0;
    const base = alphabet.length;
    const first = alphabet.charAt(0);
    const digits = [0];
    for (i = 0; i < input.length(); ++i) {
      let carry = input.at(i);
      for (let j = 0; j < digits.length; ++j) {
        carry += digits[j]! << 8;
        digits[j] = carry % base;
        carry = (carry / base) | 0;
      }

      while (carry > 0) {
        digits.push(carry % base);
        carry = (carry / base) | 0;
      }
    }

    let output = '';

    for (i = 0; input.at(i) === 0 && i < input.length() - 1; ++i) {
      output += first;
    }
    for (i = digits.length - 1; i >= 0; --i) {
      output += alphabet[digits[i]!];
    }

    return output;
  }
}

/** Flat namespace matching legacy baseN module.exports shape. */
export function createBaseNNamespace(): { encode: typeof BaseNCodec.encode; decode: typeof BaseNCodec.decode } {
  return {
    encode: BaseNCodec.encode.bind(BaseNCodec),
    decode: BaseNCodec.decode.bind(BaseNCodec)
  };
}

export default BaseNCodec;

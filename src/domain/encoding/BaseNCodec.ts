/**
 * Base-N/Base-X encoding and decoding.
 */
type ByteBufferLike = {
  length(): number;
  at(index: number): number;
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
      const base = alphabet.length;
      const first = alphabet.charAt(0);
      const digits = [0];
      for (let index = 0; index < input.length; ++index) {
        let carry = input[index];
        for (let innerIndex = 0; innerIndex < digits.length; ++innerIndex) {
          carry += digits[innerIndex] << 8;
          digits[innerIndex] = carry % base;
          carry = (carry / base) | 0;
        }

        while (carry > 0) {
          digits.push(carry % base);
          carry = (carry / base) | 0;
        }
      }

      for (let index = 0; input[index] === 0 && index < input.length - 1; ++index) {
        output += first;
      }
      for (let index = digits.length - 1; index >= 0; --index) {
        output += alphabet[digits[index]];
      }
    }

    if (maxline) {
      const regex = new RegExp('.{1,' + maxline + '}', 'g');
      output = output.match(regex)!.join('\r\n');
    }

    return output;
  }

  static decode(input: string, alphabet: string): Uint8Array | undefined {
    if (typeof input !== 'string') {
      throw new TypeError('"input" must be a string.');
    }
    if (typeof alphabet !== 'string') {
      throw new TypeError('"alphabet" must be a string.');
    }

    let table = BaseNCodec.#reverseAlphabets[alphabet];
    if (!table) {
      table = BaseNCodec.#reverseAlphabets[alphabet] = [];
      for (let index = 0; index < alphabet.length; ++index) {
        table[alphabet.charCodeAt(index)] = index;
      }
    }

    input = input.replace(/\s/g, '');

    const base = alphabet.length;
    const first = alphabet.charAt(0);
    const bytes = [0];
    for (let index = 0; index < input.length; index++) {
      const value = table[input.charCodeAt(index)];
      if (value === undefined) {
        return;
      }

      let carry = value;
      for (let innerIndex = 0; innerIndex < bytes.length; ++innerIndex) {
        carry += bytes[innerIndex] * base;
        bytes[innerIndex] = carry & 0xff;
        carry >>= 8;
      }

      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }

    for (let limbIndex = 0; input[limbIndex] === first && limbIndex < input.length - 1; ++limbIndex) {
      bytes.push(0);
    }

    return Buffer.from(bytes.reverse());
  }

  static #encodeWithByteBuffer(input: ByteBufferLike, alphabet: string): string {
    const base = alphabet.length;
    const first = alphabet.charAt(0);
    const digits = [0];
    for (let index = 0; index < input.length(); ++index) {
      let carry = input.at(index);
      for (let innerIndex = 0; innerIndex < digits.length; ++innerIndex) {
        carry += digits[innerIndex] << 8;
        digits[innerIndex] = carry % base;
        carry = (carry / base) | 0;
      }

      while (carry > 0) {
        digits.push(carry % base);
        carry = (carry / base) | 0;
      }
    }

    let output = '';

    for (let index = 0; input.at(index) === 0 && index < input.length() - 1; ++index) {
      output += first;
    }
    for (let index = digits.length - 1; index >= 0; --index) {
      output += alphabet[digits[index]];
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

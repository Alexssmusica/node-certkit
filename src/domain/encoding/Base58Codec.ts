import { BaseNCodec } from './BaseNCodec.js';
import { BASE58 } from './Base58Alphabet.js';

export class Base58Codec {
  static encode(input: Uint8Array | { length(): number; at(i: number): number }, maxline?: number): string {
    return BaseNCodec.encode(input, BASE58, maxline);
  }

  static decode(input: string, maxline?: number): Uint8Array | undefined {
    void maxline;
    return BaseNCodec.decode(input, BASE58);
  }
}

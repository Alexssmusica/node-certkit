export class RawCodec {
  static encode(bytes: Uint8Array): string {
    return String.fromCharCode.apply(null, Array.from(bytes));
  }

  static decode(str: string | Uint8Array): Uint8Array;
  static decode(str: string | Uint8Array, output: Uint8Array, offset?: number): number;
  static decode(str: string | Uint8Array, output?: Uint8Array, offset?: number): Uint8Array | number {
    let out = output;
    if (!out) {
      out = new Uint8Array((str as string).length);
    }
    const off = offset || 0;
    let j = off;
    const s = str as string;
    for (let i = 0; i < s.length; ++i) {
      out[j++] = s.charCodeAt(i);
    }
    return output ? j - off : out;
  }
}

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
    let innerIndex = off;
    const rawString = str as string;
    for (let index = 0; index < rawString.length; ++index) {
      out[innerIndex++] = rawString.charCodeAt(index);
    }
    return output ? innerIndex - off : out;
  }
}

export class HexCodec {
  static decode(hex: string): Uint8Array;
  static decode(hex: string, output: Uint8Array, offset?: number): number;
  static decode(hex: string, output?: Uint8Array, offset?: number): Uint8Array | number {
    let out = output;
    if (!out) {
      out = new Uint8Array(Math.ceil(hex.length / 2));
    }
    const off = offset || 0;
    let i = 0;
    let j = off;
    if (hex.length & 1) {
      i = 1;
      out[j++] = parseInt(hex[0]!, 16);
    }
    for (; i < hex.length; i += 2) {
      out[j++] = parseInt(hex.substr(i, 2), 16);
    }
    return output ? j - off : out;
  }

  static decodeToString(hex: string): string {
    let rval = '';
    let i = 0;
    if (hex.length & 1) {
      i = 1;
      rval += String.fromCharCode(parseInt(hex[0]!, 16));
    }
    for (; i < hex.length; i += 2) {
      rval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return rval;
  }

  static encode(bytes: Uint8Array): string {
    let rval = '';
    for (let i = 0; i < bytes.length; ++i) {
      const b = bytes[i]!;
      if (b < 16) {
        rval += '0';
      }
      rval += b.toString(16);
    }
    return rval;
  }
}

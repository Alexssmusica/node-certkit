export class HexCodec {
  static decode(hex: string): Uint8Array;
  static decode(hex: string, output: Uint8Array, offset?: number): number;
  static decode(hex: string, output?: Uint8Array, offset?: number): Uint8Array | number {
    let out = output;
    if (!out) {
      out = new Uint8Array(Math.ceil(hex.length / 2));
    }
    const off = offset || 0;
    let index = 0;
    let innerIndex = off;
    if (hex.length & 1) {
      index = 1;
      out[innerIndex++] = parseInt(hex[0], 16);
    }
    for (; index < hex.length; index += 2) {
      out[innerIndex++] = parseInt(hex.substr(index, 2), 16);
    }
    return output ? innerIndex - off : out;
  }

  static decodeToString(hex: string): string {
    const chars: string[] = [];
    let index = 0;
    if (hex.length & 1) {
      index = 1;
      chars.push(String.fromCharCode(parseInt(hex[0], 16)));
    }
    for (; index < hex.length; index += 2) {
      chars.push(String.fromCharCode(parseInt(hex.substr(index, 2), 16)));
    }
    return chars.join('');
  }

  static encode(bytes: Uint8Array): string {
    const hex: string[] = [];
    for (let index = 0; index < bytes.length; ++index) {
      const byteValue = bytes[index];
      hex.push((byteValue < 16 ? '0' : '') + byteValue.toString(16));
    }
    return hex.join('');
  }
}

import { BASE64, BASE64_IDX } from './Base64Tables.js';

export class Base64Codec {
  static encodeString(input: string, maxline?: number): string {
    let line = '';
    let output = '';
    let i = 0;
    while (i < input.length) {
      const chr1 = input.charCodeAt(i++);
      const chr2 = input.charCodeAt(i++);
      const chr3 = input.charCodeAt(i++);

      line += BASE64.charAt(chr1 >> 2);
      line += BASE64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
      if (isNaN(chr2)) {
        line += '==';
      } else {
        line += BASE64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
        line += isNaN(chr3) ? '=' : BASE64.charAt(chr3 & 63);
      }

      if (maxline && line.length > maxline) {
        output += line.substr(0, maxline) + '\r\n';
        line = line.substr(maxline);
      }
    }
    output += line;
    return output;
  }

  static decodeString(input: string): string {
    input = input.replace(/[^A-Za-z0-9+/=]/g, '');

    const chunks: string[] = [];
    let i = 0;

    while (i < input.length) {
      const enc1 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc2 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc3 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc4 = BASE64_IDX[input.charCodeAt(i++) - 43]!;

      chunks.push(String.fromCharCode((enc1 << 2) | (enc2 >> 4)));
      if (enc3 !== 64) {
        chunks.push(String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2)));
        if (enc4 !== 64) {
          chunks.push(String.fromCharCode(((enc3 & 3) << 6) | enc4));
        }
      }
    }

    return chunks.join('');
  }

  static encode(input: Uint8Array, maxline?: number): string {
    let line = '';
    let output = '';
    let i = 0;
    while (i < input.byteLength) {
      const chr1 = input[i++]!;
      const chr2 = input[i++]!;
      const chr3 = input[i++]!;

      line += BASE64.charAt(chr1 >> 2);
      line += BASE64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
      if (isNaN(chr2)) {
        line += '==';
      } else {
        line += BASE64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
        line += isNaN(chr3) ? '=' : BASE64.charAt(chr3 & 63);
      }

      if (maxline && line.length > maxline) {
        output += line.substr(0, maxline) + '\r\n';
        line = line.substr(maxline);
      }
    }
    output += line;
    return output;
  }

  static decode(input: string): Uint8Array;
  static decode(input: string, output: Uint8Array, offset?: number): number;
  static decode(input: string, output?: Uint8Array, offset?: number): Uint8Array | number {
    let out = output;
    if (!out) {
      out = new Uint8Array(Math.ceil(input.length / 4) * 3);
    }

    input = input.replace(/[^A-Za-z0-9+/=]/g, '');

    const off = offset || 0;
    let i = 0;
    let j = off;

    while (i < input.length) {
      const enc1 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc2 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc3 = BASE64_IDX[input.charCodeAt(i++) - 43]!;
      const enc4 = BASE64_IDX[input.charCodeAt(i++) - 43]!;

      out[j++] = (enc1 << 2) | (enc2 >> 4);
      if (enc3 !== 64) {
        out[j++] = ((enc2 & 15) << 4) | (enc3 >> 2);
        if (enc4 !== 64) {
          out[j++] = ((enc3 & 3) << 6) | enc4;
        }
      }
    }

    return output ? j - off : out.subarray(0, j);
  }
}

import { Base64Codec } from '../encoding/Base64Codec.js';
import type { PemDekInfo, PemEncodeOptions, PemHeader, PemMessage, PemProcType } from './PemTypes.js';

export class PemCodec {
  /** Maximum PEM input size accepted by decode (16 MiB). */
  static MAX_DECODE_INPUT_LENGTH = 16 * 1024 * 1024;

  static encode(msg: PemMessage, options?: PemEncodeOptions): string {
    options = options || {};
    let rval = '-----BEGIN ' + msg.type + '-----\r\n';

    let header: PemHeader;
    if (msg.procType) {
      header = {
        name: 'Proc-Type',
        values: [String(msg.procType.version), msg.procType.type]
      };
      rval += PemCodec.foldHeader(header);
    }
    if (msg.contentDomain) {
      header = { name: 'Content-Domain', values: [msg.contentDomain] };
      rval += PemCodec.foldHeader(header);
    }
    if (msg.dekInfo) {
      header = { name: 'DEK-Info', values: [msg.dekInfo.algorithm] };
      if (msg.dekInfo.parameters) {
        header.values.push(msg.dekInfo.parameters);
      }
      rval += PemCodec.foldHeader(header);
    }

    if (msg.headers) {
      for (let i = 0; i < msg.headers.length; ++i) {
        rval += PemCodec.foldHeader(msg.headers[i]!);
      }
    }

    if (msg.procType) {
      rval += '\r\n';
    }

    rval += Base64Codec.encodeString(msg.body, options.maxline || 64) + '\r\n';
    rval += '-----END ' + msg.type + '-----\r\n';
    return rval;
  }

  static decode(str: string): PemMessage[] {
    if (str.length > PemCodec.MAX_DECODE_INPUT_LENGTH) {
      throw new Error('PEM input exceeds maximum allowed size.');
    }

    const rval: PemMessage[] = [];
    const BEGIN_MARKER = '-----BEGIN ';
    const END_PREFIX = '-----END ';
    let pos = 0;

    while (pos < str.length) {
      while (pos < str.length && /\s/.test(str.charAt(pos))) {
        ++pos;
      }
      if (pos >= str.length) {
        break;
      }

      const beginIdx = str.indexOf(BEGIN_MARKER, pos);
      if (beginIdx === -1) {
        break;
      }

      const typeStart = beginIdx + BEGIN_MARKER.length;
      const typeEnd = str.indexOf('-----', typeStart);
      if (typeEnd === -1) {
        throw new Error('Invalid PEM formatted message.');
      }

      let type = str.substring(typeStart, typeEnd);
      const endType = type;
      if (type === 'NEW CERTIFICATE REQUEST') {
        type = 'CERTIFICATE REQUEST';
      }

      let contentStart = typeEnd + 5;
      if (str.charAt(contentStart) === '\r') {
        ++contentStart;
      }
      if (str.charAt(contentStart) === '\n') {
        ++contentStart;
      }

      const endMarker = END_PREFIX + endType + '-----';
      const endIdx = str.indexOf(endMarker, contentStart);
      if (endIdx === -1) {
        throw new Error('Invalid PEM formatted message.');
      }

      const blockContent = str.substring(contentStart, endIdx);
      let headerPart = '';
      let bodyPart = blockContent;

      const headerBodySplit = /\r?\n\r?\n/.exec(blockContent);
      if (headerBodySplit && headerBodySplit.index !== undefined) {
        headerPart = blockContent.substring(0, headerBodySplit.index);
        bodyPart = blockContent.substring(headerBodySplit.index + headerBodySplit[0].length);
      }

      const msg: PemMessage = {
        type,
        procType: null,
        contentDomain: null,
        dekInfo: null,
        headers: [],
        body: Base64Codec.decodeString(bodyPart)
      };
      rval.push(msg);

      if (headerPart.length > 0) {
        PemCodec.parseHeaders(msg, headerPart);
      }

      pos = endIdx + endMarker.length;
    }

    if (rval.length === 0) {
      throw new Error('Invalid PEM formatted message.');
    }

    return rval;
  }

  private static parseHeaders(msg: PemMessage, headerPart: string): void {
    const rHeader = /^([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/;
    const lines = headerPart.split(/\r?\n/);
    let li = 0;

    while (li < lines.length) {
      let line = lines[li]!.replace(/\s+$/, '');

      for (let nl = li + 1; nl < lines.length; ++nl) {
        const next = lines[nl]!;
        if (!/\s/.test(next.charAt(0))) {
          break;
        }
        line += next;
        li = nl;
      }

      const match = rHeader.exec(line);
      if (match) {
        const header: PemHeader = { name: match[1]!, values: [] };
        const values = match[2]!.split(',');
        for (let vi = 0; vi < values.length; ++vi) {
          header.values.push(PemCodec.ltrim(values[vi]!));
        }

        if (!msg.procType) {
          if (header.name !== 'Proc-Type') {
            throw new Error('Invalid PEM formatted message. The first ' + 'encapsulated header must be "Proc-Type".');
          } else if (header.values.length !== 2) {
            throw new Error('Invalid PEM formatted message. The "Proc-Type" ' + 'header must have two subfields.');
          }
          msg.procType = { version: values[0]!, type: values[1]! };
        } else if (!msg.contentDomain && header.name === 'Content-Domain') {
          msg.contentDomain = values[0] || '';
        } else if (!msg.dekInfo && header.name === 'DEK-Info') {
          if (header.values.length === 0) {
            throw new Error(
              'Invalid PEM formatted message. The "DEK-Info" ' + 'header must have at least one subfield.'
            );
          }
          msg.dekInfo = { algorithm: values[0]!, parameters: values[1] || null };
        } else {
          msg.headers.push(header);
        }
      }

      ++li;
    }

    if ((msg.procType as unknown) === 'ENCRYPTED' && !msg.dekInfo) {
      throw new Error(
        'Invalid PEM formatted message. The "DEK-Info" ' + 'header must be present if "Proc-Type" is "ENCRYPTED".'
      );
    }
  }

  static createCertkitNamespace(): { encode: typeof PemCodec.encode; decode: typeof PemCodec.decode } {
    return {
      encode: PemCodec.encode.bind(PemCodec),
      decode: PemCodec.decode.bind(PemCodec)
    };
  }

  private static foldHeader(header: PemHeader): string {
    let rval = header.name + ': ';

    const values: string[] = [];
    const insertSpace = (_match: string, $1: string) => {
      return ' ' + $1;
    };
    for (let i = 0; i < header.values.length; ++i) {
      values.push(header.values[i]!.replace(/^(\S+\r\n)/, insertSpace));
    }
    rval += values.join(',') + '\r\n';

    let length = 0;
    let candidate = -1;
    for (let i = 0; i < rval.length; ++i, ++length) {
      if (length > 65 && candidate !== -1) {
        const insert = rval[candidate];
        if (insert === ',') {
          ++candidate;
          rval = rval.substr(0, candidate) + '\r\n ' + rval.substr(candidate);
        } else {
          rval = rval.substr(0, candidate) + '\r\n' + insert + rval.substr(candidate + 1);
        }
        length = i - candidate - 1;
        candidate = -1;
        ++i;
      } else if (rval[i] === ' ' || rval[i] === '\t' || rval[i] === ',') {
        candidate = i;
      }
    }

    return rval;
  }

  private static ltrim(str: string): string {
    return str.replace(/^\s+/, '');
  }
}

export default PemCodec;

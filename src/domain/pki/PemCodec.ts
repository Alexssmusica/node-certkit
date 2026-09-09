import { Base64Codec } from '../encoding/Base64Codec.js';
import type { PemDekInfo, PemEncodeOptions, PemHeader, PemMessage, PemProcType } from './PemTypes.js';

export class PemCodec {
  /** Maximum PEM input size accepted by decode (16 MiB). */
  static MAX_DECODE_INPUT_LENGTH = 16 * 1024 * 1024;

  static encode(pemMessage: PemMessage, options?: PemEncodeOptions): string {
    options = options || {};
    let pemText = '-----BEGIN ' + pemMessage.type + '-----\r\n';

    let header: PemHeader;
    if (pemMessage.procType) {
      header = {
        name: 'Proc-Type',
        values: [String(pemMessage.procType.version), pemMessage.procType.type]
      };
      pemText += PemCodec.foldHeader(header);
    }
    if (pemMessage.contentDomain) {
      header = { name: 'Content-Domain', values: [pemMessage.contentDomain] };
      pemText += PemCodec.foldHeader(header);
    }
    if (pemMessage.dekInfo) {
      header = { name: 'DEK-Info', values: [pemMessage.dekInfo.algorithm] };
      if (pemMessage.dekInfo.parameters) {
        header.values.push(pemMessage.dekInfo.parameters);
      }
      pemText += PemCodec.foldHeader(header);
    }

    if (pemMessage.headers) {
      for (let i = 0; i < pemMessage.headers.length; ++i) {
        pemText += PemCodec.foldHeader(pemMessage.headers[i]!);
      }
    }

    if (pemMessage.procType) {
      pemText += '\r\n';
    }

    pemText += Base64Codec.encodeString(pemMessage.body, options.maxline || 64) + '\r\n';
    pemText += '-----END ' + pemMessage.type + '-----\r\n';
    return pemText;
  }

  static decode(str: string): PemMessage[] {
    if (str.length > PemCodec.MAX_DECODE_INPUT_LENGTH) {
      throw new Error('PEM input exceeds maximum allowed size.');
    }

    const pemMessages: PemMessage[] = [];
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

      const pemMessage: PemMessage = {
        type,
        procType: null,
        contentDomain: null,
        dekInfo: null,
        headers: [],
        body: Base64Codec.decodeString(bodyPart)
      };
      pemMessages.push(pemMessage);

      if (headerPart.length > 0) {
        PemCodec.parseHeaders(pemMessage, headerPart);
      }

      pos = endIdx + endMarker.length;
    }

    if (pemMessages.length === 0) {
      throw new Error('Invalid PEM formatted message.');
    }

    return pemMessages;
  }

  private static parseHeaders(pemMessage: PemMessage, headerPart: string): void {
    const rHeader = /^([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/;
    const lines = headerPart.split(/\r?\n/);
    let lineIndex = 0;

    while (lineIndex < lines.length) {
      let line = lines[lineIndex]!.replace(/\s+$/, '');

      for (let nextLineIndex = lineIndex + 1; nextLineIndex < lines.length; ++nextLineIndex) {
        const next = lines[nextLineIndex]!;
        if (!/\s/.test(next.charAt(0))) {
          break;
        }
        line += next;
        lineIndex = nextLineIndex;
      }

      const match = rHeader.exec(line);
      if (match) {
        const header: PemHeader = { name: match[1]!, values: [] };
        const values = match[2]!.split(',');
        for (let valueIndex = 0; valueIndex < values.length; ++valueIndex) {
          header.values.push(PemCodec.ltrim(values[valueIndex]!));
        }

        if (!pemMessage.procType) {
          if (header.name !== 'Proc-Type') {
            throw new Error('Invalid PEM formatted message. The first ' + 'encapsulated header must be "Proc-Type".');
          } else if (header.values.length !== 2) {
            throw new Error('Invalid PEM formatted message. The "Proc-Type" ' + 'header must have two subfields.');
          }
          pemMessage.procType = { version: values[0]!, type: values[1]! };
        } else if (!pemMessage.contentDomain && header.name === 'Content-Domain') {
          pemMessage.contentDomain = values[0] || '';
        } else if (!pemMessage.dekInfo && header.name === 'DEK-Info') {
          if (header.values.length === 0) {
            throw new Error(
              'Invalid PEM formatted message. The "DEK-Info" ' + 'header must have at least one subfield.'
            );
          }
          pemMessage.dekInfo = { algorithm: values[0]!, parameters: values[1] || null };
        } else {
          pemMessage.headers.push(header);
        }
      }

      ++lineIndex;
    }

    if ((pemMessage.procType as unknown) === 'ENCRYPTED' && !pemMessage.dekInfo) {
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
    let headerLine = header.name + ': ';

    const values: string[] = [];
    const insertSpace = (_match: string, $1: string) => {
      return ' ' + $1;
    };
    for (let i = 0; i < header.values.length; ++i) {
      values.push(header.values[i]!.replace(/^(\S+\r\n)/, insertSpace));
    }
    headerLine += values.join(',') + '\r\n';

    let length = 0;
    let candidate = -1;
    for (let i = 0; i < headerLine.length; ++i, ++length) {
      if (length > 65 && candidate !== -1) {
        const insert = headerLine[candidate];
        if (insert === ',') {
          ++candidate;
          headerLine = headerLine.substr(0, candidate) + '\r\n ' + headerLine.substr(candidate);
        } else {
          headerLine = headerLine.substr(0, candidate) + '\r\n' + insert + headerLine.substr(candidate + 1);
        }
        length = i - candidate - 1;
        candidate = -1;
        ++i;
      } else if (headerLine[i] === ' ' || headerLine[i] === '\t' || headerLine[i] === ',') {
        candidate = i;
      }
    }

    return headerLine;
  }

  private static ltrim(str: string): string {
    return str.replace(/^\s+/, '');
  }
}

export default PemCodec;

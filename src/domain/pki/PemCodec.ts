import { Base64Codec } from '../encoding/Base64Codec.js';

export type PemProcType = {
  version: string;
  type: string;
};

export type PemDekInfo = {
  algorithm: string;
  parameters: string | null;
};

export type PemHeader = {
  name: string;
  values: string[];
};

export type PemMessage = {
  type: string;
  procType: PemProcType | null;
  contentDomain: string | null;
  dekInfo: PemDekInfo | null;
  headers: PemHeader[];
  body: string;
};

export type PemEncodeOptions = {
  maxline?: number;
};

export class PemCodec {
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
    const rval: PemMessage[] = [];

    const rMessage = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g;
    const rHeader = /([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/;
    const rCRLF = /\r?\n/;
    let match: RegExpExecArray | null;
    while (true) {
      match = rMessage.exec(str);
      if (!match) {
        break;
      }

      let type = match[1]!;
      if (type === 'NEW CERTIFICATE REQUEST') {
        type = 'CERTIFICATE REQUEST';
      }

      const msg: PemMessage = {
        type,
        procType: null,
        contentDomain: null,
        dekInfo: null,
        headers: [],
        body: Base64Codec.decodeString(match[3]!)
      };
      rval.push(msg);

      if (!match[2]) {
        continue;
      }

      const lines = match[2].split(rCRLF);
      let li = 0;
      while (match && li < lines.length) {
        let line = lines[li]!.replace(/\s+$/, '');

        for (let nl = li + 1; nl < lines.length; ++nl) {
          const next = lines[nl]!;
          if (!/\s/.test(next[0]!)) {
            break;
          }
          line += next;
          li = nl;
        }

        match = rHeader.exec(line);
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
              throw new Error('Invalid PEM formatted message. The "DEK-Info" ' + 'header must have at least one subfield.');
            }
            msg.dekInfo = { algorithm: values[0]!, parameters: values[1] || null };
          } else {
            msg.headers.push(header);
          }
        }

        ++li;
      }

      if ((msg.procType as unknown) === 'ENCRYPTED' && !msg.dekInfo) {
        throw new Error('Invalid PEM formatted message. The "DEK-Info" ' + 'header must be present if "Proc-Type" is "ENCRYPTED".');
      }
    }

    if (rval.length === 0) {
      throw new Error('Invalid PEM formatted message.');
    }

    return rval;
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

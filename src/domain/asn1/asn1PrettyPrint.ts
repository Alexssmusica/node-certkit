import { decodeUtf8 } from '../encoding/Utf8Codec.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import { Asn1Codec } from './Asn1Codec.js';
import type { Asn1Object } from './Asn1Types.js';

const nonLatinRegex = /[^\u0000-\u00ff]/;

let pkiOids: Record<string, string> | undefined;

export function setPrettyPrintPkiOids(oids?: Record<string, string>): void {
  pkiOids = oids;
}

export function prettyPrintAsn1(obj: Asn1Object, level?: number, indentation?: number): string {
  const indentLevel = level || 0;
  if (indentLevel >= Asn1Codec.maxDepth) {
    throw new Error('ASN.1 pretty print error: Max depth exceeded.');
  }

  let output = '';
  const indentSize = indentation || 2;

  // start new line for deep levels
  if (indentLevel > 0) {
    output += '\n';
  }

  // create indent
  let indent = '';
  for (let i = 0; i < indentLevel * indentSize; ++i) {
    indent += ' ';
  }

  // print class:type
  output += indent + 'Tag: ';
  switch (obj.tagClass) {
    case Asn1Codec.Class.UNIVERSAL:
      output += 'Universal:';
      break;
    case Asn1Codec.Class.APPLICATION:
      output += 'Application:';
      break;
    case Asn1Codec.Class.CONTEXT_SPECIFIC:
      output += 'Context-Specific:';
      break;
    case Asn1Codec.Class.PRIVATE:
      output += 'Private:';
      break;
  }

  if (obj.tagClass === Asn1Codec.Class.UNIVERSAL) {
    output += obj.type;

    // known types
    switch (obj.type) {
      case Asn1Codec.Type.NONE:
        output += ' (None)';
        break;
      case Asn1Codec.Type.BOOLEAN:
        output += ' (Boolean)';
        break;
      case Asn1Codec.Type.INTEGER:
        output += ' (Integer)';
        break;
      case Asn1Codec.Type.BITSTRING:
        output += ' (Bit string)';
        break;
      case Asn1Codec.Type.OCTETSTRING:
        output += ' (Octet string)';
        break;
      case Asn1Codec.Type.NULL:
        output += ' (Null)';
        break;
      case Asn1Codec.Type.OID:
        output += ' (Object Identifier)';
        break;
      case Asn1Codec.Type.ODESC:
        output += ' (Object Descriptor)';
        break;
      case Asn1Codec.Type.EXTERNAL:
        output += ' (External or Instance of)';
        break;
      case Asn1Codec.Type.REAL:
        output += ' (Real)';
        break;
      case Asn1Codec.Type.ENUMERATED:
        output += ' (Enumerated)';
        break;
      case Asn1Codec.Type.EMBEDDED:
        output += ' (Embedded PDV)';
        break;
      case Asn1Codec.Type.UTF8:
        output += ' (UTF8)';
        break;
      case Asn1Codec.Type.ROID:
        output += ' (Relative Object Identifier)';
        break;
      case Asn1Codec.Type.SEQUENCE:
        output += ' (Sequence)';
        break;
      case Asn1Codec.Type.SET:
        output += ' (Set)';
        break;
      case Asn1Codec.Type.PRINTABLESTRING:
        output += ' (Printable String)';
        break;
      case Asn1Codec.Type.IA5STRING:
        output += ' (IA5String (ASCII))';
        break;
      case Asn1Codec.Type.UTCTIME:
        output += ' (UTC time)';
        break;
      case Asn1Codec.Type.GENERALIZEDTIME:
        output += ' (Generalized time)';
        break;
      case Asn1Codec.Type.BMPSTRING:
        output += ' (BMP String)';
        break;
    }
  } else {
    output += obj.type;
  }

  output += '\n';
  output += indent + 'Constructed: ' + obj.constructed + '\n';

  if (obj.composed) {
    let subvalues = 0;
    let sub = '';
    const children = obj.value as Asn1Object[];
    for (let i = 0; i < children.length; ++i) {
      if (children[i] !== undefined) {
        subvalues += 1;
        sub += prettyPrintAsn1(children[i]!, indentLevel + 1, indentSize);
        if (i + 1 < children.length) {
          sub += ',';
        }
      }
    }
    output += indent + 'Sub values: ' + subvalues + sub;
  } else {
    output += indent + 'Value: ';
    const primitive = obj.value as string;
    if (obj.type === Asn1Codec.Type.OID) {
      const oid = Asn1Codec.derToOid(primitive);
      output += oid;
      if (pkiOids && oid in pkiOids) {
        output += ' (' + pkiOids[oid] + ') ';
      }
    }
    if (obj.type === Asn1Codec.Type.INTEGER) {
      try {
        output += Asn1Codec.derToInteger(primitive);
      } catch {
        output += '0x' + UtilNamespace.bytesToHex(primitive);
      }
    } else if (obj.type === Asn1Codec.Type.BITSTRING) {
      // TODO: shift bits as needed to display without padding
      if (primitive.length > 1) {
        // remove unused bits field
        output += '0x' + UtilNamespace.bytesToHex(primitive.slice(1));
      } else {
        output += '(none)';
      }
      // show unused bit count
      if (primitive.length > 0) {
        const unused = primitive.charCodeAt(0);
        if (unused == 1) {
          output += ' (1 unused bit shown)';
        } else if (unused > 1) {
          output += ' (' + unused + ' unused bits shown)';
        }
      }
    } else if (obj.type === Asn1Codec.Type.OCTETSTRING) {
      if (!nonLatinRegex.test(primitive)) {
        output += '(' + primitive + ') ';
      }
      output += '0x' + UtilNamespace.bytesToHex(primitive);
    } else if (obj.type === Asn1Codec.Type.UTF8) {
      try {
        output += decodeUtf8(primitive);
      } catch (e: unknown) {
        if (e instanceof Error && e.message === 'URI malformed') {
          output += '0x' + UtilNamespace.bytesToHex(primitive) + ' (malformed UTF8)';
        } else {
          throw e;
        }
      }
    } else if (obj.type === Asn1Codec.Type.PRINTABLESTRING || obj.type === Asn1Codec.Type.IA5STRING) {
      output += primitive;
    } else if (nonLatinRegex.test(primitive)) {
      output += '0x' + UtilNamespace.bytesToHex(primitive);
    } else if (primitive.length === 0) {
      output += '[null]';
    } else {
      output += primitive;
    }
  }

  return output;
}

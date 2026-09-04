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

  let rval = '';
  const indentSize = indentation || 2;

  // start new line for deep levels
  if (indentLevel > 0) {
    rval += '\n';
  }

  // create indent
  let indent = '';
  for (let i = 0; i < indentLevel * indentSize; ++i) {
    indent += ' ';
  }

  // print class:type
  rval += indent + 'Tag: ';
  switch (obj.tagClass) {
    case Asn1Codec.Class.UNIVERSAL:
      rval += 'Universal:';
      break;
    case Asn1Codec.Class.APPLICATION:
      rval += 'Application:';
      break;
    case Asn1Codec.Class.CONTEXT_SPECIFIC:
      rval += 'Context-Specific:';
      break;
    case Asn1Codec.Class.PRIVATE:
      rval += 'Private:';
      break;
  }

  if (obj.tagClass === Asn1Codec.Class.UNIVERSAL) {
    rval += obj.type;

    // known types
    switch (obj.type) {
      case Asn1Codec.Type.NONE:
        rval += ' (None)';
        break;
      case Asn1Codec.Type.BOOLEAN:
        rval += ' (Boolean)';
        break;
      case Asn1Codec.Type.INTEGER:
        rval += ' (Integer)';
        break;
      case Asn1Codec.Type.BITSTRING:
        rval += ' (Bit string)';
        break;
      case Asn1Codec.Type.OCTETSTRING:
        rval += ' (Octet string)';
        break;
      case Asn1Codec.Type.NULL:
        rval += ' (Null)';
        break;
      case Asn1Codec.Type.OID:
        rval += ' (Object Identifier)';
        break;
      case Asn1Codec.Type.ODESC:
        rval += ' (Object Descriptor)';
        break;
      case Asn1Codec.Type.EXTERNAL:
        rval += ' (External or Instance of)';
        break;
      case Asn1Codec.Type.REAL:
        rval += ' (Real)';
        break;
      case Asn1Codec.Type.ENUMERATED:
        rval += ' (Enumerated)';
        break;
      case Asn1Codec.Type.EMBEDDED:
        rval += ' (Embedded PDV)';
        break;
      case Asn1Codec.Type.UTF8:
        rval += ' (UTF8)';
        break;
      case Asn1Codec.Type.ROID:
        rval += ' (Relative Object Identifier)';
        break;
      case Asn1Codec.Type.SEQUENCE:
        rval += ' (Sequence)';
        break;
      case Asn1Codec.Type.SET:
        rval += ' (Set)';
        break;
      case Asn1Codec.Type.PRINTABLESTRING:
        rval += ' (Printable String)';
        break;
      case Asn1Codec.Type.IA5STRING:
        rval += ' (IA5String (ASCII))';
        break;
      case Asn1Codec.Type.UTCTIME:
        rval += ' (UTC time)';
        break;
      case Asn1Codec.Type.GENERALIZEDTIME:
        rval += ' (Generalized time)';
        break;
      case Asn1Codec.Type.BMPSTRING:
        rval += ' (BMP String)';
        break;
    }
  } else {
    rval += obj.type;
  }

  rval += '\n';
  rval += indent + 'Constructed: ' + obj.constructed + '\n';

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
    rval += indent + 'Sub values: ' + subvalues + sub;
  } else {
    rval += indent + 'Value: ';
    const primitive = obj.value as string;
    if (obj.type === Asn1Codec.Type.OID) {
      const oid = Asn1Codec.derToOid(primitive);
      rval += oid;
      if (pkiOids && oid in pkiOids) {
        rval += ' (' + pkiOids[oid] + ') ';
      }
    }
    if (obj.type === Asn1Codec.Type.INTEGER) {
      try {
        rval += Asn1Codec.derToInteger(primitive);
      } catch {
        rval += '0x' + UtilNamespace.bytesToHex(primitive);
      }
    } else if (obj.type === Asn1Codec.Type.BITSTRING) {
      // TODO: shift bits as needed to display without padding
      if (primitive.length > 1) {
        // remove unused bits field
        rval += '0x' + UtilNamespace.bytesToHex(primitive.slice(1));
      } else {
        rval += '(none)';
      }
      // show unused bit count
      if (primitive.length > 0) {
        const unused = primitive.charCodeAt(0);
        if (unused == 1) {
          rval += ' (1 unused bit shown)';
        } else if (unused > 1) {
          rval += ' (' + unused + ' unused bits shown)';
        }
      }
    } else if (obj.type === Asn1Codec.Type.OCTETSTRING) {
      if (!nonLatinRegex.test(primitive)) {
        rval += '(' + primitive + ') ';
      }
      rval += '0x' + UtilNamespace.bytesToHex(primitive);
    } else if (obj.type === Asn1Codec.Type.UTF8) {
      try {
        rval += decodeUtf8(primitive);
      } catch (e: unknown) {
        if (e instanceof Error && e.message === 'URI malformed') {
          rval += '0x' + UtilNamespace.bytesToHex(primitive) + ' (malformed UTF8)';
        } else {
          throw e;
        }
      }
    } else if (obj.type === Asn1Codec.Type.PRINTABLESTRING || obj.type === Asn1Codec.Type.IA5STRING) {
      rval += primitive;
    } else if (nonLatinRegex.test(primitive)) {
      rval += '0x' + UtilNamespace.bytesToHex(primitive);
    } else if (primitive.length === 0) {
      rval += '[null]';
    } else {
      rval += primitive;
    }
  }

  return rval;
}

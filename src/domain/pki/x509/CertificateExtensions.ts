import type { Asn1Object } from '../../asn1/Asn1Types.js';
import type { CertificateExtensionFromAsn1Options, GeneralName, X509Extension } from './X509Types.js';

/**
 * Converts an ASN.1 extensions object (with extension sequences as its
 * values) into an array of extension objects with types and values.
 *
 * Supported extensions:
 *
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 * KeyUsage ::= BIT STRING {
 *   digitalSignature        (0),
 *   nonRepudiation          (1),
 *   keyEncipherment         (2),
 *   dataEncipherment        (3),
 *   keyAgreement            (4),
 *   keyCertSign             (5),
 *   cRLSign                 (6),
 *   encipherOnly            (7),
 *   decipherOnly            (8)
 * }
 *
 * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 * BasicConstraints ::= SEQUENCE {
 *   cA                      BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL
 * }
 *
 * subjectAltName EXTENSION ::= {
 *   SYNTAX GeneralNames
 *   IDENTIFIED BY id-ce-subjectAltName
 * }
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *   otherName      [0] INSTANCE OF OTHER-NAME,
 *   rfc822Name     [1] IA5String,
 *   dNSName        [2] IA5String,
 *   x400Address    [3] ORAddress,
 *   directoryName  [4] Name,
 *   ediPartyName   [5] EDIPartyName,
 *   uniformResourceIdentifier [6] IA5String,
 *   IPAddress      [7] OCTET STRING,
 *   registeredID   [8] OBJECT IDENTIFIER
 * }
 *
 * OTHER-NAME ::= TYPE-IDENTIFIER
 *
 * EDIPartyName ::= SEQUENCE {
 *   nameAssigner [0] DirectoryString {ub-name} OPTIONAL,
 *   partyName    [1] DirectoryString {ub-name}
 * }
 *
 * @param exts the extensions ASN.1 with extension sequences to parse.
 *
 * @return the array.
 */
export function certificateExtensionsFromAsn1(
  exts: Asn1Object,
  options?: CertificateExtensionFromAsn1Options
): X509Extension[] {
  const parsedExtensions: X509Extension[] = [];
  const sequences = exts.value as Asn1Object[];
  for (let index = 0; index < sequences.length; ++index) {
    const extseq = sequences[index];
    const extensionList = extseq.value as Asn1Object[];
    for (let extensionIndex = 0; extensionIndex < extensionList.length; ++extensionIndex) {
      parsedExtensions.push(certificateExtensionFromAsn1(extensionList[extensionIndex], options));
    }
  }

  return parsedExtensions;
}

/**
 * Parses a single certificate extension from ASN.1.
 *
 * @param ext the extension in ASN.1 format.
 *
 * @return the parsed extension as an object.
 */
export function certificateExtensionFromAsn1(
  ext: Asn1Object,
  options?: CertificateExtensionFromAsn1Options
): X509Extension {
  const ctx = options!.ctx;
  const asn1 = ctx.asn1;
  const oids = ctx.oids;
  const util = ctx.util;

  // an extension has:
  // [0] extnID      OBJECT IDENTIFIER
  // [1] critical    BOOLEAN DEFAULT FALSE
  // [2] extnValue   OCTET STRING
  const extension: X509Extension = {};
  const fields = ext.value as Asn1Object[];
  extension.id = asn1.derToOid(fields[0].value as string);
  extension.critical = false;
  if (fields[1].type === asn1.Type.BOOLEAN) {
    extension.critical = (fields[1].value as string).charCodeAt(0) !== 0x00;
    extension.value = fields[2].value as string;
  } else {
    extension.value = fields[1].value as string;
  }
  if (extension.id && extension.id in oids) {
    extension.name = oids[extension.id];
    const rawValue = extension.value;

    if (extension.name === 'keyUsage') {
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      const bits = extensionValueAsn1.value as string;
      let bitStringByte2 = 0x00;
      let bitStringByte3 = 0x00;
      if (bits.length > 1) {
        bitStringByte2 = bits.charCodeAt(1);
        bitStringByte3 = bits.length > 2 ? bits.charCodeAt(2) : 0;
      }
      extension.digitalSignature = (bitStringByte2 & 0x80) === 0x80;
      extension.nonRepudiation = (bitStringByte2 & 0x40) === 0x40;
      extension.keyEncipherment = (bitStringByte2 & 0x20) === 0x20;
      extension.dataEncipherment = (bitStringByte2 & 0x10) === 0x10;
      extension.keyAgreement = (bitStringByte2 & 0x08) === 0x08;
      extension.keyCertSign = (bitStringByte2 & 0x04) === 0x04;
      extension.cRLSign = (bitStringByte2 & 0x02) === 0x02;
      extension.encipherOnly = (bitStringByte2 & 0x01) === 0x01;
      extension.decipherOnly = (bitStringByte3 & 0x80) === 0x80;
    } else if (extension.name === 'basicConstraints') {
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      const seq = extensionValueAsn1.value as Asn1Object[];
      if (seq.length > 0 && seq[0].type === asn1.Type.BOOLEAN) {
        extension.cA = (seq[0].value as string).charCodeAt(0) !== 0x00;
      } else {
        extension.cA = false;
      }
      let value: string | null = null;
      if (seq.length > 0 && seq[0].type === asn1.Type.INTEGER) {
        value = seq[0].value as string;
      } else if (seq.length > 1) {
        value = seq[1].value as string;
      }
      if (value !== null) {
        extension.pathLenConstraint = asn1.derToInteger(value);
      }
    } else if (extension.name === 'extKeyUsage') {
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      const usages = extensionValueAsn1.value as Asn1Object[];
      for (let usageIndex = 0; usageIndex < usages.length; ++usageIndex) {
        const oid = asn1.derToOid(usages[usageIndex].value as string);
        if (oid in oids) {
          extension[oids[oid]] = true;
        } else {
          extension[oid] = true;
        }
      }
    } else if (extension.name === 'nsCertType') {
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      const bits = extensionValueAsn1.value as string;
      let bitStringByte2 = 0x00;
      if (bits.length > 1) {
        bitStringByte2 = bits.charCodeAt(1);
      }
      extension.client = (bitStringByte2 & 0x80) === 0x80;
      extension.server = (bitStringByte2 & 0x40) === 0x40;
      extension.email = (bitStringByte2 & 0x20) === 0x20;
      extension.objsign = (bitStringByte2 & 0x10) === 0x10;
      extension.reserved = (bitStringByte2 & 0x08) === 0x08;
      extension.sslCA = (bitStringByte2 & 0x04) === 0x04;
      extension.emailCA = (bitStringByte2 & 0x02) === 0x02;
      extension.objCA = (bitStringByte2 & 0x01) === 0x01;
    } else if (extension.name === 'subjectAltName' || extension.name === 'issuerAltName') {
      extension.altNames = [];

      let generalNameAsn1: Asn1Object;
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      const names = extensionValueAsn1.value as Asn1Object[];
      for (let limbCount = 0; limbCount < names.length; ++limbCount) {
        generalNameAsn1 = names[limbCount]!;

        const altName: GeneralName = {
          type: generalNameAsn1.type,
          value: generalNameAsn1.value as string
        };
        extension.altNames.push(altName);

        switch (generalNameAsn1.type) {
          case 1:
          case 2:
          case 6:
            break;
          case 7:
            altName.ip = util.bytesToIP(generalNameAsn1.value as string);
            break;
          case 8:
            altName.oid = asn1.derToOid(generalNameAsn1.value as string);
            break;
          default:
            break;
        }
      }
    } else if (extension.name === 'subjectKeyIdentifier') {
      const extensionValueAsn1 = asn1.fromDer(rawValue);
      extension.subjectKeyIdentifier = util.bytesToHex(extensionValueAsn1.value as string);
    }
  }
  return extension;
}

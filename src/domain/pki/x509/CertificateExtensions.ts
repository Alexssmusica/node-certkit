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
  const rval: X509Extension[] = [];
  const sequences = exts.value as Asn1Object[];
  for (let i = 0; i < sequences.length; ++i) {
    const extseq = sequences[i]!;
    const extensions = extseq.value as Asn1Object[];
    for (let ei = 0; ei < extensions.length; ++ei) {
      rval.push(certificateExtensionFromAsn1(extensions[ei]!, options));
    }
  }

  return rval;
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
  const e: X509Extension = {};
  const fields = ext.value as Asn1Object[];
  e.id = asn1.derToOid(fields[0]!.value as string);
  e.critical = false;
  if (fields[1]!.type === asn1.Type.BOOLEAN) {
    e.critical = (fields[1]!.value as string).charCodeAt(0) !== 0x00;
    e.value = fields[2]!.value as string;
  } else {
    e.value = fields[1]!.value as string;
  }
  if (e.id && e.id in oids) {
    e.name = oids[e.id];
    const rawValue = e.value as string;

    if (e.name === 'keyUsage') {
      const ev = asn1.fromDer(rawValue);
      const bits = ev.value as string;
      let b2 = 0x00;
      let b3 = 0x00;
      if (bits.length > 1) {
        b2 = bits.charCodeAt(1);
        b3 = bits.length > 2 ? bits.charCodeAt(2) : 0;
      }
      e.digitalSignature = (b2 & 0x80) === 0x80;
      e.nonRepudiation = (b2 & 0x40) === 0x40;
      e.keyEncipherment = (b2 & 0x20) === 0x20;
      e.dataEncipherment = (b2 & 0x10) === 0x10;
      e.keyAgreement = (b2 & 0x08) === 0x08;
      e.keyCertSign = (b2 & 0x04) === 0x04;
      e.cRLSign = (b2 & 0x02) === 0x02;
      e.encipherOnly = (b2 & 0x01) === 0x01;
      e.decipherOnly = (b3 & 0x80) === 0x80;
    } else if (e.name === 'basicConstraints') {
      const ev = asn1.fromDer(rawValue);
      const seq = ev.value as Asn1Object[];
      if (seq.length > 0 && seq[0]!.type === asn1.Type.BOOLEAN) {
        e.cA = (seq[0]!.value as string).charCodeAt(0) !== 0x00;
      } else {
        e.cA = false;
      }
      let value: string | null = null;
      if (seq.length > 0 && seq[0]!.type === asn1.Type.INTEGER) {
        value = seq[0]!.value as string;
      } else if (seq.length > 1) {
        value = seq[1]!.value as string;
      }
      if (value !== null) {
        e.pathLenConstraint = asn1.derToInteger(value);
      }
    } else if (e.name === 'extKeyUsage') {
      const ev = asn1.fromDer(rawValue);
      const usages = ev.value as Asn1Object[];
      for (let vi = 0; vi < usages.length; ++vi) {
        const oid = asn1.derToOid(usages[vi]!.value as string);
        if (oid in oids) {
          e[oids[oid]] = true;
        } else {
          e[oid] = true;
        }
      }
    } else if (e.name === 'nsCertType') {
      const ev = asn1.fromDer(rawValue);
      const bits = ev.value as string;
      let b2 = 0x00;
      if (bits.length > 1) {
        b2 = bits.charCodeAt(1);
      }
      e.client = (b2 & 0x80) === 0x80;
      e.server = (b2 & 0x40) === 0x40;
      e.email = (b2 & 0x20) === 0x20;
      e.objsign = (b2 & 0x10) === 0x10;
      e.reserved = (b2 & 0x08) === 0x08;
      e.sslCA = (b2 & 0x04) === 0x04;
      e.emailCA = (b2 & 0x02) === 0x02;
      e.objCA = (b2 & 0x01) === 0x01;
    } else if (e.name === 'subjectAltName' || e.name === 'issuerAltName') {
      e.altNames = [];

      let gn: Asn1Object;
      const ev = asn1.fromDer(rawValue);
      const names = ev.value as Asn1Object[];
      for (let n = 0; n < names.length; ++n) {
        gn = names[n]!;

        const altName: GeneralName = {
          type: gn.type,
          value: gn.value as string
        };
        e.altNames.push(altName);

        switch (gn.type) {
          case 1:
          case 2:
          case 6:
            break;
          case 7:
            altName.ip = util.bytesToIP(gn.value as string);
            break;
          case 8:
            altName.oid = asn1.derToOid(gn.value as string);
            break;
          default:
            break;
        }
      }
    } else if (e.name === 'subjectKeyIdentifier') {
      const ev = asn1.fromDer(rawValue);
      e.subjectKeyIdentifier = util.bytesToHex(ev.value as string);
    }
  }
  return e;
}

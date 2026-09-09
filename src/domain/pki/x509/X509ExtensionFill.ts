import type { Asn1Object } from '../../asn1/Asn1Codec.js';
import type {
  DerError,
  DnAttribute,
  ExtensionFillDeps,
  FillMissingExtensionFields,
  X509Certificate,
  X509Extension
} from './X509Types.js';

export function createFillMissingExtensionFields(deps: ExtensionFillDeps): FillMissingExtensionFields {
  const { asn1, oids, util, dnToAsn1 } = deps;

  /**
   * Fills in missing fields in certificate extensions.
   *
   * @param e the extension.
   * @param [options] the options to use.
   *          [cert] the certificate the extensions are for.
   *
   * @return the extension.
   */
  return function fillMissingExtensionFields(e: X509Extension, options?: { cert?: X509Certificate }): X509Extension {
    options = options || {};

    if (typeof e.name === 'undefined') {
      if (e.id && e.id in oids) {
        e.name = oids[e.id];
      }
    }

    if (typeof e.id === 'undefined') {
      if (e.name && e.name in oids) {
        e.id = oids[e.name];
      } else {
        const error = new Error('Extension ID not specified.') as DerError;
        error.extension = e;
        throw error;
      }
    }

    if (typeof e.value !== 'undefined') {
      return e;
    }

    if (e.name === 'keyUsage') {
      let unused = 0;
      let keyUsageByte1 = 0x00;
      let keyUsageByte2 = 0x00;
      if (e.digitalSignature) {
        keyUsageByte1 |= 0x80;
        unused = 7;
      }
      if (e.nonRepudiation) {
        keyUsageByte1 |= 0x40;
        unused = 6;
      }
      if (e.keyEncipherment) {
        keyUsageByte1 |= 0x20;
        unused = 5;
      }
      if (e.dataEncipherment) {
        keyUsageByte1 |= 0x10;
        unused = 4;
      }
      if (e.keyAgreement) {
        keyUsageByte1 |= 0x08;
        unused = 3;
      }
      if (e.keyCertSign) {
        keyUsageByte1 |= 0x04;
        unused = 2;
      }
      if (e.cRLSign) {
        keyUsageByte1 |= 0x02;
        unused = 1;
      }
      if (e.encipherOnly) {
        keyUsageByte1 |= 0x01;
        unused = 0;
      }
      if (e.decipherOnly) {
        keyUsageByte2 |= 0x80;
        unused = 7;
      }

      let value = String.fromCharCode(unused);
      if (keyUsageByte2 !== 0) {
        value += String.fromCharCode(keyUsageByte1) + String.fromCharCode(keyUsageByte2);
      } else if (keyUsageByte1 !== 0) {
        value += String.fromCharCode(keyUsageByte1);
      }
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
    } else if (e.name === 'basicConstraints') {
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const bcSeq = e.value.value as Asn1Object[];
      if (e.cA) {
        bcSeq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)));
      }
      if ('pathLenConstraint' in e) {
        bcSeq.push(
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.INTEGER,
            false,
            asn1.integerToDer(e.pathLenConstraint!).getBytes()
          )
        );
      }
    } else if (e.name === 'extKeyUsage') {
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = e.value.value as Asn1Object[];
      for (const key in e) {
        if (e[key] !== true) {
          continue;
        }
        if (key in oids) {
          seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids[key]).getBytes()));
        } else if (key.indexOf('.') !== -1) {
          seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(key).getBytes()));
        }
      }
    } else if (e.name === 'nsCertType') {
      let unused = 0;
      let certTypeByte = 0x00;

      if (e.client) {
        certTypeByte |= 0x80;
        unused = 7;
      }
      if (e.server) {
        certTypeByte |= 0x40;
        unused = 6;
      }
      if (e.email) {
        certTypeByte |= 0x20;
        unused = 5;
      }
      if (e.objsign) {
        certTypeByte |= 0x10;
        unused = 4;
      }
      if (e.reserved) {
        certTypeByte |= 0x08;
        unused = 3;
      }
      if (e.sslCA) {
        certTypeByte |= 0x04;
        unused = 2;
      }
      if (e.emailCA) {
        certTypeByte |= 0x02;
        unused = 1;
      }
      if (e.objCA) {
        certTypeByte |= 0x01;
        unused = 0;
      }

      let value = String.fromCharCode(unused);
      if (certTypeByte !== 0) {
        value += String.fromCharCode(certTypeByte);
      }
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
    } else if (e.name === 'subjectAltName' || e.name === 'issuerAltName') {
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const altNameSeq = e.value.value as Asn1Object[];

      for (let n = 0; n < e.altNames!.length; ++n) {
        const altName = e.altNames![n]!;
        let value: string = altName.value ?? '';
        if (altName.type === 7 && altName.ip) {
          value = util.bytesFromIP(altName.ip) ?? '';
          if (value === '') {
            const error = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.') as DerError;
            error.extension = e;
            throw error;
          }
        } else if (altName.type === 8) {
          if (altName.oid) {
            value = asn1.oidToDer(altName.oid).getBytes();
          } else {
            value = asn1.oidToDer(value).getBytes();
          }
        }
        altNameSeq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, altName.type, false, value));
      }
    } else if (e.name === 'nsComment' && options.cert && e.comment) {
      if (!/^[\x00-\x7F]*$/.test(e.comment) || e.comment.length < 1 || e.comment.length > 128) {
        throw new Error('Invalid "nsComment" content.');
      }
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false, e.comment);
    } else if (e.name === 'subjectKeyIdentifier' && options.cert) {
      const skiDigest = options.cert.generateSubjectKeyIdentifier();
      e.subjectKeyIdentifier = skiDigest.toHex();
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, skiDigest.getBytes());
    } else if (e.name === 'authorityKeyIdentifier' && options.cert) {
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = e.value.value as Asn1Object[];

      if (e.keyIdentifier) {
        const keyIdentifier =
          e.keyIdentifier === true ? options.cert.generateSubjectKeyIdentifier().getBytes() : e.keyIdentifier;
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false, keyIdentifier));
      }

      if (e.authorityCertIssuer) {
        const authorityCertIssuer = [
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 4, true, [
            dnToAsn1(e.authorityCertIssuer === true ? options.cert.issuer : e.authorityCertIssuer)
          ])
        ];
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, authorityCertIssuer));
      }

      if (e.serialNumber) {
        const serialNumber = util.hexToBytes(e.serialNumber === true ? options.cert.serialNumber : e.serialNumber);
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, false, serialNumber));
      }
    } else if (e.name === 'cRLDistributionPoints') {
      e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = e.value.value as Asn1Object[];

      const subSeq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

      const fullNameGeneralNames = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, []);
      let altName;
      for (let n = 0; n < e.altNames!.length; ++n) {
        altName = e.altNames![n];
        let value: string = altName!.value ?? '';
        if (altName!.type === 7 && altName!.ip) {
          value = util.bytesFromIP(altName!.ip) ?? '';
          if (value === '') {
            const error = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.') as DerError;
            error.extension = e;
            throw error;
          }
        } else if (altName!.type === 8) {
          if (altName!.oid) {
            value = asn1.oidToDer(altName!.oid).getBytes();
          } else {
            value = asn1.oidToDer(value).getBytes();
          }
        }
        (fullNameGeneralNames.value as Asn1Object[]).push(
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, altName!.type, false, value)
        );
      }

      (subSeq.value as Asn1Object[]).push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [fullNameGeneralNames]));
      seq.push(subSeq);
    }

    if (typeof e.value === 'undefined') {
      const error = new Error('Extension value not specified.') as DerError;
      error.extension = e;
      throw error;
    }

    return e;
  };
}

import type { Asn1Object } from '../../asn1/Asn1Codec.js';
import type {
  DerError,
  ExtensionFillDeps,
  FillMissingExtensionFields,
  X509Certificate,
  X509Extension
} from './X509Types.js';

function isAsciiString(text: string, maxCodePoint: number): boolean {
  for (let index = 0; index < text.length; ++index) {
    if (text.charCodeAt(index) > maxCodePoint) {
      return false;
    }
  }
  return true;
}

export function createFillMissingExtensionFields(deps: ExtensionFillDeps): FillMissingExtensionFields {
  const { asn1, oids, util, dnToAsn1 } = deps;

  /**
   * Fills in missing fields in certificate extensions.
   *
   * @param extension the extension.
   * @param [options] the options to use.
   *          [cert] the certificate the extensions are for.
   *
   * @return the extension.
   */
  return function fillMissingExtensionFields(
    extension: X509Extension,
    options?: { cert?: X509Certificate }
  ): X509Extension {
    options = options || {};

    if (typeof extension.name === 'undefined') {
      if (extension.id && extension.id in oids) {
        extension.name = oids[extension.id];
      }
    }

    if (typeof extension.id === 'undefined') {
      if (extension.name && extension.name in oids) {
        extension.id = oids[extension.name];
      } else {
        const error = new Error('Extension ID not specified.') as DerError;
        error.extension = extension;
        throw error;
      }
    }

    if (typeof extension.value !== 'undefined') {
      return extension;
    }

    if (extension.name === 'keyUsage') {
      let unused = 0;
      let keyUsageByte1 = 0x00;
      let keyUsageByte2 = 0x00;
      if (extension.digitalSignature) {
        keyUsageByte1 |= 0x80;
        unused = 7;
      }
      if (extension.nonRepudiation) {
        keyUsageByte1 |= 0x40;
        unused = 6;
      }
      if (extension.keyEncipherment) {
        keyUsageByte1 |= 0x20;
        unused = 5;
      }
      if (extension.dataEncipherment) {
        keyUsageByte1 |= 0x10;
        unused = 4;
      }
      if (extension.keyAgreement) {
        keyUsageByte1 |= 0x08;
        unused = 3;
      }
      if (extension.keyCertSign) {
        keyUsageByte1 |= 0x04;
        unused = 2;
      }
      if (extension.cRLSign) {
        keyUsageByte1 |= 0x02;
        unused = 1;
      }
      if (extension.encipherOnly) {
        keyUsageByte1 |= 0x01;
        unused = 0;
      }
      if (extension.decipherOnly) {
        keyUsageByte2 |= 0x80;
        unused = 7;
      }

      let value = String.fromCharCode(unused);
      if (keyUsageByte2 !== 0) {
        value += String.fromCharCode(keyUsageByte1) + String.fromCharCode(keyUsageByte2);
      } else if (keyUsageByte1 !== 0) {
        value += String.fromCharCode(keyUsageByte1);
      }
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
    } else if (extension.name === 'basicConstraints') {
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const bcSeq = extension.value.value as Asn1Object[];
      if (extension.cA) {
        bcSeq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)));
      }
      if ('pathLenConstraint' in extension) {
        bcSeq.push(
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.INTEGER,
            false,
            asn1.integerToDer(extension.pathLenConstraint!).getBytes()
          )
        );
      }
    } else if (extension.name === 'extKeyUsage') {
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = extension.value.value as Asn1Object[];
      for (const key in extension) {
        if (extension[key] !== true) {
          continue;
        }
        if (key in oids) {
          seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids[key]).getBytes()));
        } else if (key.indexOf('.') !== -1) {
          seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(key).getBytes()));
        }
      }
    } else if (extension.name === 'nsCertType') {
      let unused = 0;
      let certTypeByte = 0x00;

      if (extension.client) {
        certTypeByte |= 0x80;
        unused = 7;
      }
      if (extension.server) {
        certTypeByte |= 0x40;
        unused = 6;
      }
      if (extension.email) {
        certTypeByte |= 0x20;
        unused = 5;
      }
      if (extension.objsign) {
        certTypeByte |= 0x10;
        unused = 4;
      }
      if (extension.reserved) {
        certTypeByte |= 0x08;
        unused = 3;
      }
      if (extension.sslCA) {
        certTypeByte |= 0x04;
        unused = 2;
      }
      if (extension.emailCA) {
        certTypeByte |= 0x02;
        unused = 1;
      }
      if (extension.objCA) {
        certTypeByte |= 0x01;
        unused = 0;
      }

      let value = String.fromCharCode(unused);
      if (certTypeByte !== 0) {
        value += String.fromCharCode(certTypeByte);
      }
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
    } else if (extension.name === 'subjectAltName' || extension.name === 'issuerAltName') {
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const altNameSeq = extension.value.value as Asn1Object[];

      for (let n = 0; n < extension.altNames!.length; ++n) {
        const altName = extension.altNames![n];
        let value: string = altName.value ?? '';
        if (altName.type === 7 && altName.ip) {
          value = util.bytesFromIP(altName.ip) ?? '';
          if (value === '') {
            const error = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.') as DerError;
            error.extension = extension;
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
    } else if (extension.name === 'nsComment' && options.cert && extension.comment) {
      if (!isAsciiString(extension.comment, 0x7f) || extension.comment.length < 1 || extension.comment.length > 128) {
        throw new Error('Invalid "nsComment" content.');
      }
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false, extension.comment);
    } else if (extension.name === 'subjectKeyIdentifier' && options.cert) {
      const skiDigest = options.cert.generateSubjectKeyIdentifier();
      extension.subjectKeyIdentifier = skiDigest.toHex();
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, skiDigest.getBytes());
    } else if (extension.name === 'authorityKeyIdentifier' && options.cert) {
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = extension.value.value as Asn1Object[];

      if (extension.keyIdentifier) {
        const keyIdentifier =
          extension.keyIdentifier === true
            ? options.cert.generateSubjectKeyIdentifier().getBytes()
            : extension.keyIdentifier;
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false, keyIdentifier));
      }

      if (extension.authorityCertIssuer) {
        const authorityCertIssuer = [
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 4, true, [
            dnToAsn1(extension.authorityCertIssuer === true ? options.cert.issuer : extension.authorityCertIssuer)
          ])
        ];
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, authorityCertIssuer));
      }

      if (extension.serialNumber) {
        const serialNumber = util.hexToBytes(
          extension.serialNumber === true ? options.cert.serialNumber : extension.serialNumber
        );
        seq.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, false, serialNumber));
      }
    } else if (extension.name === 'cRLDistributionPoints') {
      extension.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      const seq = extension.value.value as Asn1Object[];

      const subSeq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

      const fullNameGeneralNames = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, []);
      let altName;
      for (let n = 0; n < extension.altNames!.length; ++n) {
        altName = extension.altNames![n];
        let value: string = altName.value ?? '';
        if (altName.type === 7 && altName.ip) {
          value = util.bytesFromIP(altName.ip) ?? '';
          if (value === '') {
            const error = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.') as DerError;
            error.extension = extension;
            throw error;
          }
        } else if (altName.type === 8) {
          if (altName.oid) {
            value = asn1.oidToDer(altName.oid).getBytes();
          } else {
            value = asn1.oidToDer(value).getBytes();
          }
        }
        (fullNameGeneralNames.value as Asn1Object[]).push(
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, altName.type, false, value)
        );
      }

      (subSeq.value as Asn1Object[]).push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [fullNameGeneralNames]));
      seq.push(subSeq);
    }

    if (typeof extension.value === 'undefined') {
      const error = new Error('Extension value not specified.') as DerError;
      error.extension = extension;
      throw error;
    }

    return extension;
  };
}

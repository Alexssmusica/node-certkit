import type { Asn1Validator } from '../../asn1/Asn1Types.js';
import type { X509Runtime } from './X509Runtime.js';

export type X509Validators = {
  shortNames: Record<string, string>;
  x509CertificateValidator: Asn1Validator;
  certificationRequestValidator: Asn1Validator;
  certificationRequestInfoValidator: Asn1Validator;
  rsassaPssParameterValidator: Asn1Validator;
  rdnValidator: Asn1Validator;
};

export class X509Asn1 {
  static create(ctx: X509Runtime): X509Validators {
    const asn1 = ctx.asn1 as {
      Class: Record<string, number>;
      Type: Record<string, number>;
    };
    const oids = ctx.oids;
    const publicKeyValidator = (ctx.rsa as { publicKeyValidator: Asn1Validator }).publicKeyValidator;

    const shortNames: Record<string, string> = {
      CN: oids['commonName']!,
      commonName: 'CN',
      C: oids['countryName']!,
      countryName: 'C',
      L: oids['localityName']!,
      localityName: 'L',
      ST: oids['stateOrProvinceName']!,
      stateOrProvinceName: 'ST',
      O: oids['organizationName']!,
      organizationName: 'O',
      OU: oids['organizationalUnitName']!,
      organizationalUnitName: 'OU',
      E: oids['emailAddress']!,
      emailAddress: 'E'
    };

    const rdnValidator: Asn1Validator = {
      name: 'RDNSequence',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'rdn'
    };

    // validator for an SubjectPublicKeyInfo structure
    // Note: Currently only works with an RSA public key
    // validator for an X.509v3 certificate
    const x509CertificateValidator = {
      name: 'Certificate',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [
        {
          name: 'Certificate.TBSCertificate',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          captureAsn1: 'tbsCertificate',
          value: [
            {
              name: 'Certificate.TBSCertificate.version',
              tagClass: asn1.Class.CONTEXT_SPECIFIC,
              type: 0,
              constructed: true,
              optional: true,
              value: [
                {
                  name: 'Certificate.TBSCertificate.version.integer',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.INTEGER,
                  constructed: false,
                  capture: 'certVersion'
                }
              ]
            },
            {
              name: 'Certificate.TBSCertificate.serialNumber',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.INTEGER,
              constructed: false,
              capture: 'certSerialNumber'
            },
            {
              name: 'Certificate.TBSCertificate.signature',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.SEQUENCE,
              constructed: true,
              value: [
                {
                  name: 'Certificate.TBSCertificate.signature.algorithm',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.OID,
                  constructed: false,
                  capture: 'certinfoSignatureOid'
                },
                {
                  name: 'Certificate.TBSCertificate.signature.parameters',
                  tagClass: asn1.Class.UNIVERSAL,
                  optional: true,
                  captureAsn1: 'certinfoSignatureParams'
                }
              ]
            },
            {
              name: 'Certificate.TBSCertificate.issuer',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.SEQUENCE,
              constructed: true,
              captureAsn1: 'certIssuer'
            },
            {
              name: 'Certificate.TBSCertificate.validity',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.SEQUENCE,
              constructed: true,
              // Note: UTC and generalized times may both appear so the capture
              // names are based on their detected order, the names used below
              // are only for the common case, which validity time really means
              // "notBefore" and which means "notAfter" will be determined by order
              value: [
                {
                  // notBefore (Time) (UTC time case)
                  name: 'Certificate.TBSCertificate.validity.notBefore (utc)',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.UTCTIME,
                  constructed: false,
                  optional: true,
                  capture: 'certValidity1UTCTime'
                },
                {
                  // notBefore (Time) (generalized time case)
                  name: 'Certificate.TBSCertificate.validity.notBefore (generalized)',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.GENERALIZEDTIME,
                  constructed: false,
                  optional: true,
                  capture: 'certValidity2GeneralizedTime'
                },
                {
                  // notAfter (Time) (only UTC time is supported)
                  name: 'Certificate.TBSCertificate.validity.notAfter (utc)',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.UTCTIME,
                  constructed: false,
                  optional: true,
                  capture: 'certValidity3UTCTime'
                },
                {
                  // notAfter (Time) (only UTC time is supported)
                  name: 'Certificate.TBSCertificate.validity.notAfter (generalized)',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.GENERALIZEDTIME,
                  constructed: false,
                  optional: true,
                  capture: 'certValidity4GeneralizedTime'
                }
              ]
            },
            {
              // Name (subject) (RDNSequence)
              name: 'Certificate.TBSCertificate.subject',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.SEQUENCE,
              constructed: true,
              captureAsn1: 'certSubject'
            },
            // SubjectPublicKeyInfo
            publicKeyValidator,
            {
              // issuerUniqueID (optional)
              name: 'Certificate.TBSCertificate.issuerUniqueID',
              tagClass: asn1.Class.CONTEXT_SPECIFIC,
              type: 1,
              constructed: true,
              optional: true,
              value: [
                {
                  name: 'Certificate.TBSCertificate.issuerUniqueID.id',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.BITSTRING,
                  constructed: false,
                  // TODO: support arbitrary bit length ids
                  captureBitStringValue: 'certIssuerUniqueId'
                }
              ]
            },
            {
              // subjectUniqueID (optional)
              name: 'Certificate.TBSCertificate.subjectUniqueID',
              tagClass: asn1.Class.CONTEXT_SPECIFIC,
              type: 2,
              constructed: true,
              optional: true,
              value: [
                {
                  name: 'Certificate.TBSCertificate.subjectUniqueID.id',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.BITSTRING,
                  constructed: false,
                  // TODO: support arbitrary bit length ids
                  captureBitStringValue: 'certSubjectUniqueId'
                }
              ]
            },
            {
              // Extensions (optional)
              name: 'Certificate.TBSCertificate.extensions',
              tagClass: asn1.Class.CONTEXT_SPECIFIC,
              type: 3,
              constructed: true,
              captureAsn1: 'certExtensions',
              optional: true
            }
          ]
        },
        {
          // AlgorithmIdentifier (signature algorithm)
          name: 'Certificate.signatureAlgorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          value: [
            {
              // algorithm
              name: 'Certificate.signatureAlgorithm.algorithm',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.OID,
              constructed: false,
              capture: 'certSignatureOid'
            },
            {
              name: 'Certificate.TBSCertificate.signature.parameters',
              tagClass: asn1.Class.UNIVERSAL,
              optional: true,
              captureAsn1: 'certSignatureParams'
            }
          ]
        },
        {
          // SignatureValue
          name: 'Certificate.signatureValue',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.BITSTRING,
          constructed: false,
          captureBitStringValue: 'certSignature'
        }
      ]
    };

    const rsassaPssParameterValidator = {
      name: 'rsapss',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [
        {
          name: 'rsapss.hashAlgorithm',
          tagClass: asn1.Class.CONTEXT_SPECIFIC,
          type: 0,
          constructed: true,
          value: [
            {
              name: 'rsapss.hashAlgorithm.AlgorithmIdentifier',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Class.SEQUENCE,
              constructed: true,
              optional: true,
              value: [
                {
                  name: 'rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.OID,
                  constructed: false,
                  capture: 'hashOid'
                  /* parameter block omitted, for SHA1 NULL anyhow. */
                }
              ]
            }
          ]
        },
        {
          name: 'rsapss.maskGenAlgorithm',
          tagClass: asn1.Class.CONTEXT_SPECIFIC,
          type: 1,
          constructed: true,
          value: [
            {
              name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Class.SEQUENCE,
              constructed: true,
              optional: true,
              value: [
                {
                  name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.OID,
                  constructed: false,
                  capture: 'maskGenOid'
                },
                {
                  name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.SEQUENCE,
                  constructed: true,
                  value: [
                    {
                      name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm',
                      tagClass: asn1.Class.UNIVERSAL,
                      type: asn1.Type.OID,
                      constructed: false,
                      capture: 'maskGenHashOid'
                      /* parameter block omitted, for SHA1 NULL anyhow. */
                    }
                  ]
                }
              ]
            }
          ]
        },
        {
          name: 'rsapss.saltLength',
          tagClass: asn1.Class.CONTEXT_SPECIFIC,
          type: 2,
          optional: true,
          value: [
            {
              name: 'rsapss.saltLength.saltLength',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Class.INTEGER,
              constructed: false,
              capture: 'saltLength'
            }
          ]
        },
        {
          name: 'rsapss.trailerField',
          tagClass: asn1.Class.CONTEXT_SPECIFIC,
          type: 3,
          optional: true,
          value: [
            {
              name: 'rsapss.trailer.trailer',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Class.INTEGER,
              constructed: false,
              capture: 'trailer'
            }
          ]
        }
      ]
    };

    // validator for a CertificationRequestInfo structure
    const certificationRequestInfoValidator = {
      name: 'CertificationRequestInfo',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'certificationRequestInfo',
      value: [
        {
          name: 'CertificationRequestInfo.integer',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.INTEGER,
          constructed: false,
          capture: 'certificationRequestInfoVersion'
        },
        {
          // Name (subject) (RDNSequence)
          name: 'CertificationRequestInfo.subject',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          captureAsn1: 'certificationRequestInfoSubject'
        },
        // SubjectPublicKeyInfo
        publicKeyValidator,
        {
          name: 'CertificationRequestInfo.attributes',
          tagClass: asn1.Class.CONTEXT_SPECIFIC,
          type: 0,
          constructed: true,
          optional: true,
          capture: 'certificationRequestInfoAttributes',
          value: [
            {
              name: 'CertificationRequestInfo.attributes',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.SEQUENCE,
              constructed: true,
              value: [
                {
                  name: 'CertificationRequestInfo.attributes.type',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.OID,
                  constructed: false
                },
                {
                  name: 'CertificationRequestInfo.attributes.value',
                  tagClass: asn1.Class.UNIVERSAL,
                  type: asn1.Type.SET,
                  constructed: true
                }
              ]
            }
          ]
        }
      ]
    };

    // validator for a CertificationRequest structure
    const certificationRequestValidator = {
      name: 'CertificationRequest',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'csr',
      value: [
        certificationRequestInfoValidator,
        {
          // AlgorithmIdentifier (signature algorithm)
          name: 'CertificationRequest.signatureAlgorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          value: [
            {
              // algorithm
              name: 'CertificationRequest.signatureAlgorithm.algorithm',
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.OID,
              constructed: false,
              capture: 'csrSignatureOid'
            },
            {
              name: 'CertificationRequest.signatureAlgorithm.parameters',
              tagClass: asn1.Class.UNIVERSAL,
              optional: true,
              captureAsn1: 'csrSignatureParams'
            }
          ]
        },
        {
          // signature
          name: 'CertificationRequest.signature',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.BITSTRING,
          constructed: false,
          captureBitStringValue: 'csrSignature'
        }
      ]
    };

    /**
     * Converts an RDNSequence of ASN.1 DER-encoded RelativeDistinguishedName
     * sets into an array with objects that have type and value properties.
     *
     * @param rdn the RDNSequence to convert.
     * @param md a message digest to append type and value to if provided.
     */

    return {
      shortNames,
      rdnValidator,
      x509CertificateValidator,
      certificationRequestValidator,
      certificationRequestInfoValidator,
      rsassaPssParameterValidator
    };
  }
}

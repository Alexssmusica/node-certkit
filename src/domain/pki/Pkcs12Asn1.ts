import type { Asn1NamespaceObject, Asn1Validator } from '../asn1/Asn1Types.js';
import type { Pkcs12Validators } from './Pkcs12Types.js';

export function createPkcs12Validators(asn1: Asn1NamespaceObject): Pkcs12Validators {
  const contentInfoValidator = {
    name: 'ContentInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE, // a ContentInfo
    constructed: true,
    value: [
      {
        name: 'ContentInfo.contentType',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'contentType'
      },
      {
        name: 'ContentInfo.content',
        tagClass: asn1.Class.CONTEXT_SPECIFIC,
        constructed: true,
        captureAsn1: 'content'
      }
    ]
  };

  const pfxValidator = {
    name: 'PFX',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'PFX.version',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'version'
      },
      contentInfoValidator,
      {
        name: 'PFX.macData',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        optional: true,
        captureAsn1: 'mac',
        value: [
          {
            name: 'PFX.macData.mac',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE, // DigestInfo
            constructed: true,
            value: [
              {
                name: 'PFX.macData.mac.digestAlgorithm',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.SEQUENCE, // DigestAlgorithmIdentifier
                constructed: true,
                value: [
                  {
                    name: 'PFX.macData.mac.digestAlgorithm.algorithm',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OID,
                    constructed: false,
                    capture: 'macAlgorithm'
                  },
                  {
                    name: 'PFX.macData.mac.digestAlgorithm.parameters',
                    optional: true,
                    tagClass: asn1.Class.UNIVERSAL,
                    captureAsn1: 'macAlgorithmParameters'
                  }
                ]
              },
              {
                name: 'PFX.macData.mac.digest',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.OCTETSTRING,
                constructed: false,
                capture: 'macDigest'
              }
            ]
          },
          {
            name: 'PFX.macData.macSalt',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OCTETSTRING,
            constructed: false,
            capture: 'macSalt'
          },
          {
            name: 'PFX.macData.iterations',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.INTEGER,
            constructed: false,
            optional: true,
            capture: 'macIterations'
          }
        ]
      }
    ]
  };

  const safeBagValidator = {
    name: 'SafeBag',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'SafeBag.bagId',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'bagId'
      },
      {
        name: 'SafeBag.bagValue',
        tagClass: asn1.Class.CONTEXT_SPECIFIC,
        constructed: true,
        captureAsn1: 'bagValue'
      },
      {
        name: 'SafeBag.bagAttributes',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SET,
        constructed: true,
        optional: true,
        capture: 'bagAttributes'
      }
    ]
  };

  const attributeValidator = {
    name: 'Attribute',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'Attribute.attrId',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'oid'
      },
      {
        name: 'Attribute.attrValues',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SET,
        constructed: true,
        capture: 'values'
      }
    ]
  };

  const certBagValidator = {
    name: 'CertBag',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'CertBag.certId',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'certId'
      },
      {
        name: 'CertBag.certValue',
        tagClass: asn1.Class.CONTEXT_SPECIFIC,
        constructed: true,
        /* So far we only support X.509 certificates (which are wrapped in
         an OCTET STRING, hence hard code that here). */
        value: [
          {
            name: 'CertBag.certValue[0]',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OCTETSTRING,
            constructed: false,
            capture: 'cert'
          }
        ]
      }
    ]
  };

  return {
    contentInfoValidator,
    pfxValidator,
    safeBagValidator,
    attributeValidator,
    certBagValidator
  };
}

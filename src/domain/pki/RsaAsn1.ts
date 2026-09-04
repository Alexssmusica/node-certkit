import type { Asn1NamespaceObject, Asn1Validator } from '../asn1/Asn1Types.js';
import type { RsaValidators } from './RsaTypes.js';

export function createRsaValidators(asn1: Asn1NamespaceObject): RsaValidators {
  const privateKeyValidator: Asn1Validator = {
    name: 'PrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'PrivateKeyInfo.version',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyVersion'
      },
      {
        name: 'PrivateKeyInfo.privateKeyAlgorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'AlgorithmIdentifier.algorithm',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'privateKeyOid'
          }
        ]
      },
      {
        name: 'PrivateKeyInfo',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'privateKey'
      }
    ]
  };

  const rsaPrivateKeyValidator: Asn1Validator = {
    name: 'RSAPrivateKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'RSAPrivateKey.version',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyVersion'
      },
      {
        name: 'RSAPrivateKey.modulus',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyModulus'
      },
      {
        name: 'RSAPrivateKey.publicExponent',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyPublicExponent'
      },
      {
        name: 'RSAPrivateKey.privateExponent',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyPrivateExponent'
      },
      {
        name: 'RSAPrivateKey.prime1',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyPrime1'
      },
      {
        name: 'RSAPrivateKey.prime2',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyPrime2'
      },
      {
        name: 'RSAPrivateKey.exponent1',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyExponent1'
      },
      {
        name: 'RSAPrivateKey.exponent2',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyExponent2'
      },
      {
        name: 'RSAPrivateKey.coefficient',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'privateKeyCoefficient'
      }
    ]
  };

  const rsaPublicKeyValidator: Asn1Validator = {
    name: 'RSAPublicKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'RSAPublicKey.modulus',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'publicKeyModulus'
      },
      {
        name: 'RSAPublicKey.exponent',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'publicKeyExponent'
      }
    ]
  };

  const publicKeyValidator: Asn1Validator = {
    name: 'SubjectPublicKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'subjectPublicKeyInfo',
    value: [
      {
        name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'AlgorithmIdentifier.algorithm',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'publicKeyOid'
          }
        ]
      },
      {
        name: 'SubjectPublicKeyInfo.subjectPublicKey',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        value: [
          {
            name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            optional: true,
            captureAsn1: 'rsaPublicKey'
          }
        ]
      }
    ]
  };

  const digestInfoValidator: Asn1Validator = {
    name: 'DigestInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'DigestInfo.DigestAlgorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'DigestInfo.DigestAlgorithm.algorithmIdentifier',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'algorithmIdentifier'
          },
          {
            name: 'DigestInfo.DigestAlgorithm.parameters',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.NULL,
            capture: 'parameters',
            optional: true,
            constructed: false
          }
        ]
      },
      {
        name: 'DigestInfo.digest',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'digest'
      }
    ]
  };

  return {
    privateKeyValidator,
    rsaPrivateKeyValidator,
    rsaPublicKeyValidator,
    publicKeyValidator,
    digestInfoValidator
  };
}

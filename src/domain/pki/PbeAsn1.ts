import type { Asn1NamespaceObject, Asn1Validator } from '../asn1/Asn1Types.js';
import type { PbeValidators } from './PbeTypes.js';

export function createPbeValidators(asn1: Asn1NamespaceObject): PbeValidators {
  const encryptedPrivateKeyValidator = {
    name: 'EncryptedPrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'EncryptedPrivateKeyInfo.encryptionAlgorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'AlgorithmIdentifier.algorithm',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'encryptionOid'
          },
          {
            name: 'AlgorithmIdentifier.parameters',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            captureAsn1: 'encryptionParams'
          }
        ]
      },
      {
        // encryptedData
        name: 'EncryptedPrivateKeyInfo.encryptedData',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'encryptedData'
      }
    ]
  };

  // validator for a PBES2Algorithms structure
  // Note: Currently only works w/PBKDF2 + AES encryption schemes
  const PBES2AlgorithmsValidator = {
    name: 'PBES2Algorithms',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'PBES2Algorithms.keyDerivationFunc',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'PBES2Algorithms.keyDerivationFunc.oid',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'kdfOid'
          },
          {
            name: 'PBES2Algorithms.params',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            value: [
              {
                name: 'PBES2Algorithms.params.salt',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.OCTETSTRING,
                constructed: false,
                capture: 'kdfSalt'
              },
              {
                name: 'PBES2Algorithms.params.iterationCount',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.INTEGER,
                constructed: false,
                capture: 'kdfIterationCount'
              },
              {
                name: 'PBES2Algorithms.params.keyLength',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.INTEGER,
                constructed: false,
                optional: true,
                capture: 'keyLength'
              },
              {
                // prf
                name: 'PBES2Algorithms.params.prf',
                tagClass: asn1.Class.UNIVERSAL,
                type: asn1.Type.SEQUENCE,
                constructed: true,
                optional: true,
                value: [
                  {
                    name: 'PBES2Algorithms.params.prf.algorithm',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OID,
                    constructed: false,
                    capture: 'prfOid'
                  }
                ]
              }
            ]
          }
        ]
      },
      {
        name: 'PBES2Algorithms.encryptionScheme',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [
          {
            name: 'PBES2Algorithms.encryptionScheme.oid',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'encOid'
          },
          {
            name: 'PBES2Algorithms.encryptionScheme.iv',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OCTETSTRING,
            constructed: false,
            capture: 'encIv'
          }
        ]
      }
    ]
  };

  const pkcs12PbeParamsValidator = {
    name: 'pkcs-12PbeParams',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        name: 'pkcs-12PbeParams.salt',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'salt'
      },
      {
        name: 'pkcs-12PbeParams.iterations',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'iterations'
      }
    ]
  };

  return {
    encryptedPrivateKeyValidator,
    PBES2AlgorithmsValidator,
    pkcs12PbeParamsValidator
  };
}

import type { Asn1Object } from '../../asn1/Asn1Codec.js';
import type { CertkitMgfNamespace } from '../../../presentation/CertkitTypes.js';
import type { MdRegistry } from '../../digest/DigestTypes.js';
import type { MessageDigest as MgfMessageDigest } from '../MgfTypes.js';
import type {
  DerError,
  MdDigestKey,
  MessageDigest,
  SignatureDeps,
  SignatureParameters,
  X509Certificate,
  X509CertificationRequest,
  X509SignatureHelpers,
  X509Validators
} from './X509Types.js';

function resolveMdDigestKey(
  oids: Record<string, string>,
  md: MdRegistry,
  algorithmOid: string,
  errorMessage: string
): MdDigestKey {
  const name = oids[algorithmOid];
  if (name === undefined || name === 'algorithms' || !(name in md)) {
    const error = new Error(errorMessage) as DerError;
    error.oid = algorithmOid;
    error.name = name;
    throw error;
  }
  return name as MdDigestKey;
}

function resolveMgfCreate(
  oids: Record<string, string>,
  mgf: CertkitMgfNamespace,
  algorithmOid: string
): (md: MgfMessageDigest) => { generate: (seed: string, maskLen: number) => string } {
  const mgfScheme = oids[algorithmOid];
  if (mgfScheme === undefined || !(mgfScheme in mgf)) {
    const error = new Error('Unsupported MGF function.') as DerError;
    error.oid = algorithmOid;
    error.name = mgfScheme;
    throw error;
  }
  const factory = mgf[mgfScheme as keyof CertkitMgfNamespace];
  if (!factory || typeof factory !== 'object' || !('create' in factory)) {
    const error = new Error('Unsupported MGF function.') as DerError;
    error.oid = algorithmOid;
    error.name = mgfScheme;
    throw error;
  }
  return factory.create as (md: MgfMessageDigest) => { generate: (seed: string, maskLen: number) => string };
}

export function createX509SignatureHelpers(deps: SignatureDeps, validators: X509Validators): X509SignatureHelpers {
  const { asn1, oids, md, pss, mgf } = deps;

  /**
   * Converts signature parameters from ASN.1 structure.
   *
   * Currently only RSASSA-PSS supported.  The PKCS#1 v1.5 signature scheme had
   * no parameters.
   *
   * RSASSA-PSS-params  ::=  SEQUENCE  {
   *   hashAlgorithm      [0] HashAlgorithm DEFAULT
   *                             sha1Identifier,
   *   maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
   *                             mgf1SHA1Identifier,
   *   saltLength         [2] INTEGER DEFAULT 20,
   *   trailerField       [3] INTEGER DEFAULT 1
   * }
   *
   * HashAlgorithm  ::=  AlgorithmIdentifier
   *
   * MaskGenAlgorithm  ::=  AlgorithmIdentifier
   *
   * AlgorithmIdentifer ::= SEQUENCE {
   *   algorithm OBJECT IDENTIFIER,
   *   parameters ANY DEFINED BY algorithm OPTIONAL
   * }
   *
   * @param oid The OID specifying the signature algorithm
   * @param obj The ASN.1 structure holding the parameters
   * @param fillDefaults Whether to use return default values where omitted
   * @return signature parameter object
   */
  const readSignatureParameters = function (oid: string, obj: Asn1Object, fillDefaults: boolean): SignatureParameters {
    let params: SignatureParameters = {};

    if (oid !== oids['RSASSA-PSS']) {
      return params;
    }

    if (fillDefaults) {
      params = {
        hash: {
          algorithmOid: oids['sha1']
        },
        mgf: {
          algorithmOid: oids['mgf1'],
          hash: {
            algorithmOid: oids['sha1']
          }
        },
        saltLength: 20
      };
    }

    const capture: Record<string, unknown> = {};
    const errors: string[] = [];
    if (!asn1.validate(obj, validators.rsassaPssParameterValidator, capture, errors)) {
      const error = new Error('Cannot read RSASSA-PSS parameter block.') as DerError;
      error.errors = errors;
      throw error;
    }

    if (capture.hashOid !== undefined) {
      params.hash = params.hash || {};
      params.hash.algorithmOid = asn1.derToOid(capture.hashOid as string);
    }

    if (capture.maskGenOid !== undefined) {
      params.mgf = params.mgf || {};
      params.mgf.algorithmOid = asn1.derToOid(capture.maskGenOid as string);
      params.mgf.hash = params.mgf.hash || {};
      params.mgf.hash.algorithmOid = asn1.derToOid(capture.maskGenHashOid as string);
    }

    if (capture.saltLength !== undefined) {
      params.saltLength = (capture.saltLength as string).charCodeAt(0);
    }

    return params;
  };

  /**
   * Create signature digest for OID.
   *
   * @param options
   *   signatureOid: the OID specifying the signature algorithm.
   *   type: a human readable type for error messages
   * @return a created md instance. throws if unknown oid.
   */
  const createSignatureDigest = function (options: { signatureOid: string; type: string }): MessageDigest {
    switch (oids[options.signatureOid]) {
      case 'sha1WithRSAEncryption':
      case 'sha1WithRSASignature':
        return md.sha1.create() as MessageDigest;
      case 'md5WithRSAEncryption':
        return md.md5.create() as MessageDigest;
      case 'sha256WithRSAEncryption':
        return md.sha256.create() as MessageDigest;
      case 'sha384WithRSAEncryption':
        return md.sha384.create() as MessageDigest;
      case 'sha512WithRSAEncryption':
        return md.sha512.create() as MessageDigest;
      case 'RSASSA-PSS':
        return md.sha256.create() as MessageDigest;
      default:
        const error = new Error(
          'Could not compute ' + options.type + ' digest. ' + 'Unknown signature OID.'
        ) as DerError;
        error.signatureOid = options.signatureOid;
        throw error;
    }
  };

  /**
   * Verify signature on certificate or CSR.
   *
   * @param options:
   *   certificate the certificate or CSR to verify.
   *   md the signature digest.
   *   signature the signature
   * @return a created md instance. throws if unknown oid.
   */
  const verifySignature = function (options: {
    certificate: X509Certificate | X509CertificationRequest;
    subject?: X509Certificate | X509CertificationRequest;
    md: MessageDigest;
    signature: string | null;
  }) {
    const issuer = options.certificate;
    const subject = options.subject || options.certificate;
    let scheme;

    switch (subject.signatureOid) {
      case oids.sha1WithRSAEncryption:
      case oids.sha1WithRSASignature:
        break;
      case oids['RSASSA-PSS']: {
        const signatureParameters = subject.signatureParameters;
        if (
          !signatureParameters?.mgf?.hash?.algorithmOid ||
          !signatureParameters.mgf.algorithmOid ||
          !signatureParameters.hash?.algorithmOid
        ) {
          throw new Error('Missing RSASSA-PSS signature parameters.');
        }

        const mgfHashKey = resolveMdDigestKey(
          oids,
          md,
          signatureParameters.mgf.hash.algorithmOid,
          'Unsupported MGF hash function.'
        );

        const mgfCreate = resolveMgfCreate(oids, mgf, signatureParameters.mgf.algorithmOid);
        const mgfScheme = mgfCreate(md[mgfHashKey].create() as MgfMessageDigest);

        const hashKey = resolveMdDigestKey(
          oids,
          md,
          signatureParameters.hash.algorithmOid,
          'Unsupported RSASSA-PSS hash function.'
        );

        scheme = pss.create({
          md: md[hashKey].create() as MgfMessageDigest,
          mgf: mgfScheme,
          saltLength: signatureParameters.saltLength
        });
        break;
      }
    }

    if (!issuer.publicKey) {
      throw new Error('Certificate is missing a public key.');
    }

    return issuer.publicKey.verify(options.md.digest().getBytes(), options.signature as string, scheme);
  };

  /**
   * Convert signature parameters object to ASN.1
   *
   * @param {String} oid Signature algorithm OID
   * @param params The signature parameters object
   * @return ASN.1 object representing signature parameters
   */
  function signatureParametersToAsn1(oid: string, params: SignatureParameters) {
    switch (oid) {
      case oids['RSASSA-PSS']: {
        const parts = [];

        if (params.hash?.algorithmOid !== undefined) {
          parts.push(
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(
                  asn1.Class.UNIVERSAL,
                  asn1.Type.OID,
                  false,
                  asn1.oidToDer(params.hash.algorithmOid).getBytes()
                ),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
              ])
            ])
          );
        }

        if (params.mgf?.algorithmOid !== undefined) {
          parts.push(
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(
                  asn1.Class.UNIVERSAL,
                  asn1.Type.OID,
                  false,
                  asn1.oidToDer(params.mgf.algorithmOid).getBytes()
                ),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                  asn1.create(
                    asn1.Class.UNIVERSAL,
                    asn1.Type.OID,
                    false,
                    asn1.oidToDer(params.mgf.hash!.algorithmOid!).getBytes()
                  ),
                  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                ])
              ])
            ])
          );
        }

        if (params.saltLength !== undefined) {
          parts.push(
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
              asn1.create(
                asn1.Class.UNIVERSAL,
                asn1.Type.INTEGER,
                false,
                asn1.integerToDer(params.saltLength).getBytes()
              )
            ])
          );
        }

        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, parts);
      }

      default:
        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '');
    }
  }

  return {
    readSignatureParameters,
    createSignatureDigest,
    verifySignature,
    signatureParametersToAsn1
  };
}

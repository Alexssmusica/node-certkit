import type { Asn1Object } from '../../asn1/Asn1Codec.js';
import type { X509Validators } from './X509Asn1.js';
import type { DerError, MessageDigest, X509Certificate, X509CertificationRequest } from './X509Types.js';

export type SignatureDeps = {
  asn1: Record<string, any>;
  oids: Record<string, string>;
  md: Record<string, { create: () => MessageDigest }>;
  pss: { create: (...args: unknown[]) => unknown };
  mgf: Record<string, any>;
};

export type X509SignatureHelpers = {
  readSignatureParameters: (oid: string, obj: Asn1Object, fillDefaults: boolean) => any;
  createSignatureDigest: (options: { signatureOid: string; type: string }) => MessageDigest;
  verifySignature: (options: {
    certificate: X509Certificate | X509CertificationRequest;
    subject?: X509Certificate | X509CertificationRequest;
    md: MessageDigest;
    signature: string | null;
  }) => boolean;
  signatureParametersToAsn1: (oid: string, params: any) => Asn1Object;
};

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
  const readSignatureParameters = function (oid: any, obj: any, fillDefaults: any) {
    let params: any = {};

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

    const capture: any = {};
    const errors: string[] = [];
    if (!asn1.validate(obj, validators.rsassaPssParameterValidator, capture, errors)) {
      const error = new Error('Cannot read RSASSA-PSS parameter block.') as DerError;
      error.errors = errors;
      throw error;
    }

    if (capture.hashOid !== undefined) {
      params.hash = params.hash || {};
      params.hash.algorithmOid = asn1.derToOid(capture.hashOid);
    }

    if (capture.maskGenOid !== undefined) {
      params.mgf = params.mgf || {};
      params.mgf.algorithmOid = asn1.derToOid(capture.maskGenOid);
      params.mgf.hash = params.mgf.hash || {};
      params.mgf.hash.algorithmOid = asn1.derToOid(capture.maskGenHashOid);
    }

    if (capture.saltLength !== undefined) {
      params.saltLength = capture.saltLength.charCodeAt(0);
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
  const createSignatureDigest = function (options: any) {
    switch (oids[options.signatureOid]) {
      case 'sha1WithRSAEncryption':
      case 'sha1WithRSASignature':
        return md.sha1.create();
      case 'md5WithRSAEncryption':
        return md.md5.create();
      case 'sha256WithRSAEncryption':
        return md.sha256.create();
      case 'sha384WithRSAEncryption':
        return md.sha384.create();
      case 'sha512WithRSAEncryption':
        return md.sha512.create();
      case 'RSASSA-PSS':
        return md.sha256.create();
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
    const subject = (options.subject || options.certificate) as X509Certificate;
    let scheme;

    switch (subject.signatureOid) {
      case oids.sha1WithRSAEncryption:
      case oids.sha1WithRSASignature:
        break;
      case oids['RSASSA-PSS']: {
        let hash, mgfScheme;
        const signatureParameters = subject.signatureParameters as unknown as {
          mgf: { hash: { algorithmOid: string }; algorithmOid: string };
          hash: { algorithmOid: string };
          saltLength: number;
        };

        hash = oids[signatureParameters.mgf.hash.algorithmOid];
        if (hash === undefined || md[hash] === undefined) {
          const error = new Error('Unsupported MGF hash function.') as DerError;
          error.oid = signatureParameters.mgf.hash.algorithmOid;
          error.name = hash;
          throw error;
        }

        mgfScheme = oids[signatureParameters.mgf.algorithmOid];
        if (mgfScheme === undefined || mgf[mgfScheme] === undefined) {
          const error = new Error('Unsupported MGF function.') as DerError;
          error.oid = signatureParameters.mgf.algorithmOid;
          error.name = mgfScheme;
          throw error;
        }

        mgfScheme = mgf[mgfScheme].create(md[hash].create());

        hash = oids[signatureParameters.hash.algorithmOid];
        if (hash === undefined || md[hash] === undefined) {
          const error = new Error('Unsupported RSASSA-PSS hash function.') as DerError;
          error.oid = signatureParameters.hash.algorithmOid;
          error.name = hash;
          throw error;
        }

        scheme = pss.create(md[hash].create(), mgfScheme, signatureParameters.saltLength);
        break;
      }
    }

    if (!issuer.publicKey) {
      throw new Error('Certificate is missing a public key.');
    }

    return issuer.publicKey.verify(
      options.md.digest().getBytes() as unknown as Parameters<typeof issuer.publicKey.verify>[0],
      options.signature as string,
      scheme
    );
  };

  /**
   * Convert signature parameters object to ASN.1
   *
   * @param {String} oid Signature algorithm OID
   * @param params The signature parameters object
   * @return ASN.1 object representing signature parameters
   */
  function signatureParametersToAsn1(oid: any, params: any) {
    switch (oid) {
      case oids['RSASSA-PSS']: {
        const parts = [];

        if (params.hash.algorithmOid !== undefined) {
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

        if (params.mgf.algorithmOid !== undefined) {
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
                    asn1.oidToDer(params.mgf.hash.algorithmOid).getBytes()
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

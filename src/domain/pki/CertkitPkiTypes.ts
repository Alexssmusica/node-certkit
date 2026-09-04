import type { Asn1Object, Asn1Validator } from '../asn1/Asn1Types.js';
import type { BigInteger } from '../math/BigInteger.js';
import type { RsaKeyPair, RsaPrivateKey, RsaPublicKey } from './RsaTypes.js';
import type {
  CertificateErrorMap,
  DnAttribute,
  VerifyCallback,
  VerifyOptions,
  X509CaStore,
  X509Certificate,
  X509CertificationRequest
} from './x509/X509Types.js';

export type CertkitRsaNamespace = {
  encrypt: (data: string, key: RsaPublicKey, scheme?: unknown, schemeOptions?: unknown) => string;
  decrypt: (data: string, key: RsaPrivateKey, scheme?: unknown, schemeOptions?: unknown) => string;
  createKeyPairGenerationState: (bits: number, e?: number, options?: unknown) => Record<string, unknown>;
  stepKeyPairGenerationState: (state: Record<string, unknown>, callback: (err: Error | null, keypair?: RsaKeyPair) => void) => void;
  generateKeyPair: (...args: unknown[]) => RsaKeyPair | void;
  setPublicKey: (n: BigInteger, e: BigInteger) => RsaPublicKey;
  setPrivateKey: (
    n: BigInteger,
    e: BigInteger,
    d: BigInteger,
    p?: BigInteger,
    q?: BigInteger,
    dP?: BigInteger,
    dQ?: BigInteger,
    qInv?: BigInteger
  ) => RsaPrivateKey;
  publicKeyValidator: Asn1Validator;
};

export type CertkitPbeNamespace = {
  generatePkcs12Key: (password: string | null | undefined, salt: unknown, id: number, iter: number, n: number, md?: unknown) => unknown;
  getCipher: (oid: string, params: unknown, password: string) => unknown;
  getCipherForPBES2: (oid: string, params: unknown, password: string) => unknown;
  getCipherForPKCS12PBE: (oid: string, params: unknown, password: string) => unknown;
  opensslDeriveBytes: (password: string, salt: unknown, dkLen: number, md?: unknown) => unknown;
};

export type CertkitPkcs12Namespace = {
  pkcs12FromAsn1: (obj: unknown, strict?: boolean, password?: string) => unknown;
  toPkcs12Asn1: (key: unknown, cert: unknown | unknown[], password: string, options?: unknown) => unknown;
  generateKey: CertkitPbeNamespace['generatePkcs12Key'];
};

/** Assembled certkit.pki namespace built by mutation across RSA, PBE, X509, and finalize. */
export type CertkitPki = {
  oids: Record<string, string>;
  rsa: CertkitRsaNamespace;
  pbe: CertkitPbeNamespace;
  setRsaPublicKey: CertkitRsaNamespace['setPublicKey'];
  setRsaPrivateKey: CertkitRsaNamespace['setPrivateKey'];
  wrapRsaPrivateKey: (key: unknown) => Asn1Object;
  privateKeyFromAsn1: (obj: unknown) => RsaPrivateKey;
  privateKeyToAsn1: (key: RsaPrivateKey) => Asn1Object;
  privateKeyToRSAPrivateKey: (key: RsaPrivateKey) => Asn1Object;
  publicKeyFromAsn1: (obj: unknown) => RsaPublicKey;
  publicKeyToAsn1: (key: RsaPublicKey) => Asn1Object;
  publicKeyToSubjectPublicKeyInfo: (key: RsaPublicKey) => Asn1Object;
  publicKeyToRSAPublicKey: (key: RsaPublicKey) => Asn1Object;
  encryptPrivateKeyInfo: (obj: unknown, password: string, options?: unknown) => unknown;
  decryptPrivateKeyInfo: (obj: unknown, password: string) => unknown;
  encryptedPrivateKeyToPem: (epki: unknown, maxline?: number) => string;
  encryptedPrivateKeyFromPem: (pem: string) => unknown;
  encryptRsaPrivateKey: (rsaKey: RsaPrivateKey, password: string, options?: unknown) => string;
  decryptRsaPrivateKey: (pem: string, password: string) => RsaPrivateKey;
  certificateFromPem: (pem: string, computeHash?: boolean, strict?: boolean) => X509Certificate;
  certificateToPem: (cert: X509Certificate, maxline?: number) => string;
  publicKeyFromPem: (pem: string) => RsaPublicKey;
  publicKeyToPem: (key: RsaPublicKey, maxline?: number) => string;
  publicKeyToRSAPublicKeyPem: (key: RsaPublicKey, maxline?: number) => string;
  getPublicKeyFingerprint: (key: RsaPublicKey, options?: unknown) => unknown;
  certificationRequestFromPem: (pem: string, computeHash?: boolean, strict?: boolean) => X509CertificationRequest;
  certificationRequestToPem: (csr: X509CertificationRequest, maxline?: number) => string;
  createCertificate: () => X509Certificate;
  certificateFromAsn1: (obj: unknown, computeHash?: boolean) => X509Certificate;
  certificateExtensionsFromAsn1: (exts: unknown) => unknown[];
  certificateExtensionFromAsn1: (ext: unknown) => unknown;
  getTBSCertificate: (cert: X509Certificate) => Asn1Object;
  distinguishedNameToAsn1: (dn: unknown) => Asn1Object;
  certificateToAsn1: (cert: X509Certificate) => Asn1Object;
  certificateExtensionsToAsn1: (exts: unknown[]) => Asn1Object;
  certificateExtensionToAsn1: (ext: unknown) => Asn1Object;
  certificationRequestToAsn1: (csr: X509CertificationRequest) => Asn1Object;
  certificationRequestFromAsn1: (obj: unknown, computeHash?: boolean) => X509CertificationRequest;
  createCertificationRequest: () => X509CertificationRequest;
  getCertificationRequestInfo: (csr: X509CertificationRequest) => Asn1Object;
  createCaStore: (certs?: Array<X509Certificate | string>) => X509CaStore;
  certificateError: CertificateErrorMap;
  verifyCertificateChain: (caStore: X509CaStore, chain: X509Certificate[], options?: VerifyCallback | VerifyOptions) => boolean;
  RDNAttributesAsArray: (rdn: unknown, md: unknown) => DnAttribute[];
  CRIAttributesAsArray: (attributes: unknown) => DnAttribute[];
  pemToDer: (pem: string) => unknown;
  privateKeyFromPem: (pem: string) => RsaPrivateKey;
  privateKeyToPem: (key: RsaPrivateKey, maxline?: number) => string;
  privateKeyInfoToPem: (keyInfo: unknown, maxline?: number) => string;
};

export type CertkitPkiPbeMethods = Pick<
  CertkitPki,
  | 'encryptPrivateKeyInfo'
  | 'decryptPrivateKeyInfo'
  | 'encryptedPrivateKeyToPem'
  | 'encryptedPrivateKeyFromPem'
  | 'encryptRsaPrivateKey'
  | 'decryptRsaPrivateKey'
>;

export type CertkitPkiRsaAttach = Pick<
  CertkitPki,
  | 'rsa'
  | 'setRsaPublicKey'
  | 'setRsaPrivateKey'
  | 'wrapRsaPrivateKey'
  | 'privateKeyFromAsn1'
  | 'privateKeyToAsn1'
  | 'privateKeyToRSAPrivateKey'
  | 'publicKeyFromAsn1'
  | 'publicKeyToAsn1'
  | 'publicKeyToSubjectPublicKeyInfo'
  | 'publicKeyToRSAPublicKey'
>;

export type CertkitPkiFinalizeMethods = Pick<CertkitPki, 'pemToDer' | 'privateKeyFromPem' | 'privateKeyToPem' | 'privateKeyInfoToPem'>;

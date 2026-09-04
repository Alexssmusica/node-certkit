import type { Asn1NamespaceObject } from '../asn1/Asn1Types.js';
import type {
  AesNamespaceObject,
  CipherNamespaceObject,
  DesNamespaceObject,
  Rc2NamespaceObject
} from '../cipher/CipherTypes.js';
import type { MdRegistry } from '../digest/DigestTypes.js';
import type { UtilNamespaceObject } from '../util/UtilTypes.js';
import type { FortunaRandomNamespace } from '../../infrastructure/random/RandomTypes.js';
import type { PemKeyCodec } from '../ports/index.js';
import type { Pbkdf2Function } from './Pbkdf2Types.js';
import type {
  CertkitHmacNamespace,
  CertkitMgfNamespace,
  CertkitPkcs5Namespace,
  CertkitPkcs7Namespace,
  CertkitPssNamespace
} from '../../presentation/CertkitTypes.js';
import type { PemCodec } from './PemCodec.js';
import type { Asn1Object, Asn1Validator } from '../asn1/Asn1Types.js';
import type { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { BigInteger } from '../math/BigInteger.js';
import type { Pkcs12CreateOptions, Pkcs12Pfx } from './Pkcs12Types.js';
import type { RsaKeyPair, RsaPrivateKey, RsaPublicKey } from './RsaTypes.js';
import type {
  CertificateErrorMap,
  DnAttribute,
  MessageDigest,
  VerifyCallback,
  VerifyOptions,
  X509CaStore,
  X509Certificate,
  X509CertificationRequest,
  X509Extension
} from './x509/X509Types.js';

export type PkiFacadeDeps = {
  asn1: Asn1NamespaceObject;
  oids: Record<string, string>;
  md: MdRegistry;
  util: UtilNamespaceObject;
  pem: ReturnType<typeof PemCodec.createCertkitNamespace>;
  aes: AesNamespaceObject;
  des: DesNamespaceObject;
  rc2: Rc2NamespaceObject;
  random: FortunaRandomNamespace;
  pbkdf2: Pbkdf2Function;
  pkcs5: CertkitPkcs5Namespace;
  cipher: CipherNamespaceObject;
  hmac: CertkitHmacNamespace;
  pss: CertkitPssNamespace;
  mgf: CertkitMgfNamespace;
  pkcs7: CertkitPkcs7Namespace;
  pki: Partial<CertkitPki>;
};

export type PkiFinalizeDeps = PkiFacadeDeps & {
  rsaService: { setPemKeyCodec(codec: PemKeyCodec): void };
};

export type CertkitRsaNamespace = {
  encrypt: (data: string, key: RsaPublicKey, scheme?: unknown, schemeOptions?: unknown) => string;
  decrypt: (data: string, key: RsaPrivateKey, scheme?: unknown, schemeOptions?: unknown) => string;
  createKeyPairGenerationState: (bits: number, e?: number, options?: unknown) => Record<string, unknown>;
  stepKeyPairGenerationState: (
    state: Record<string, unknown>,
    callback: (err: Error | null, keypair?: RsaKeyPair) => void
  ) => void;
  generateKeyPair(bits?: number, e?: number, options?: unknown): RsaKeyPair;
  generateKeyPair(
    bits: number,
    e: number | undefined,
    options: unknown,
    callback: (err: Error | null, keypair?: RsaKeyPair) => void
  ): void;
  generateKeyPair(bits: number, callback: (err: Error | null, keypair?: RsaKeyPair) => void): void;
  generateKeyPair(options: Record<string, unknown>, callback: (err: Error | null, keypair?: RsaKeyPair) => void): void;
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
  generatePkcs12Key: (
    password: string | null | undefined,
    salt: unknown,
    id: number,
    iter: number,
    n: number,
    md?: unknown
  ) => unknown;
  getCipher: (oid: string, params: unknown, password: string) => unknown;
  getCipherForPBES2: (oid: string, params: unknown, password: string) => unknown;
  getCipherForPKCS12PBE: (oid: string, params: unknown, password: string) => unknown;
  opensslDeriveBytes: (password: string, salt: unknown, dkLen: number, md?: unknown) => unknown;
};

export type PublicKeyFingerprintOptions = {
  md?: MessageDigest;
  type?: 'RSAPublicKey' | 'SubjectPublicKeyInfo';
  encoding?: 'hex' | 'binary';
  delimiter?: string;
};

export type PublicKeyFingerprint = string | ReturnType<MessageDigest['digest']>;

export type EncryptPrivateKeyInfoOptions = {
  saltSize?: number;
  count?: number;
  algorithm?: string;
  prfAlgorithm?: string;
};

export type CertkitPkcs12Namespace = {
  pkcs12FromAsn1: (obj: Asn1Object, strict?: boolean | string, password?: string) => Pkcs12Pfx;
  toPkcs12Asn1: (
    key: RsaPrivateKey | null,
    cert: X509Certificate | X509Certificate[] | string | string[] | null,
    password: string | null,
    options?: Pkcs12CreateOptions
  ) => Asn1Object;
  generateKey: CertkitPbeNamespace['generatePkcs12Key'];
};

/** Assembled certkit.pki namespace built by mutation across RSA, PBE, X509, and finalize. */
export type CertkitPki = {
  oids: Record<string, string>;
  rsa: CertkitRsaNamespace;
  pbe: CertkitPbeNamespace;
  setRsaPublicKey: CertkitRsaNamespace['setPublicKey'];
  setRsaPrivateKey: CertkitRsaNamespace['setPrivateKey'];
  wrapRsaPrivateKey: (key: Asn1Object) => Asn1Object;
  privateKeyFromAsn1: (obj: Asn1Object) => RsaPrivateKey;
  privateKeyToAsn1: (key: RsaPrivateKey) => Asn1Object;
  privateKeyToRSAPrivateKey: (key: RsaPrivateKey) => Asn1Object;
  publicKeyFromAsn1: (obj: Asn1Object) => RsaPublicKey;
  publicKeyToAsn1: (key: RsaPublicKey) => Asn1Object;
  publicKeyToSubjectPublicKeyInfo: (key: RsaPublicKey) => Asn1Object;
  publicKeyToRSAPublicKey: (key: RsaPublicKey) => Asn1Object;
  encryptPrivateKeyInfo: (obj: Asn1Object, password: string, options?: EncryptPrivateKeyInfoOptions) => Asn1Object;
  decryptPrivateKeyInfo: (obj: Asn1Object, password: string) => Asn1Object | null;
  encryptedPrivateKeyToPem: (epki: Asn1Object, maxline?: number) => string;
  encryptedPrivateKeyFromPem: (pem: string) => Asn1Object;
  encryptRsaPrivateKey: (rsaKey: RsaPrivateKey, password: string, options?: EncryptPrivateKeyInfoOptions) => string;
  decryptRsaPrivateKey: (pem: string, password: string) => RsaPrivateKey;
  certificateFromPem: (pem: string, computeHash?: boolean, strict?: boolean) => X509Certificate;
  certificateToPem: (cert: X509Certificate, maxline?: number) => string;
  publicKeyFromPem: (pem: string) => RsaPublicKey;
  publicKeyToPem: (key: RsaPublicKey, maxline?: number) => string;
  publicKeyToRSAPublicKeyPem: (key: RsaPublicKey, maxline?: number) => string;
  getPublicKeyFingerprint: (key: RsaPublicKey, options?: PublicKeyFingerprintOptions) => PublicKeyFingerprint;
  certificationRequestFromPem: (pem: string, computeHash?: boolean, strict?: boolean) => X509CertificationRequest;
  certificationRequestToPem: (csr: X509CertificationRequest, maxline?: number) => string;
  createCertificate: () => X509Certificate;
  certificateFromAsn1: (obj: Asn1Object, computeHash?: boolean) => X509Certificate;
  certificateExtensionsFromAsn1: (exts: Asn1Object) => X509Extension[];
  certificateExtensionFromAsn1: (ext: Asn1Object) => X509Extension;
  getTBSCertificate: (cert: X509Certificate) => Asn1Object;
  distinguishedNameToAsn1: (dn: { attributes: DnAttribute[] }) => Asn1Object;
  certificateToAsn1: (cert: X509Certificate) => Asn1Object;
  certificateExtensionsToAsn1: (exts: X509Extension[]) => Asn1Object;
  certificateExtensionToAsn1: (ext: X509Extension) => Asn1Object;
  certificationRequestToAsn1: (csr: X509CertificationRequest) => Asn1Object;
  certificationRequestFromAsn1: (obj: Asn1Object, computeHash?: boolean) => X509CertificationRequest;
  createCertificationRequest: () => X509CertificationRequest;
  getCertificationRequestInfo: (csr: X509CertificationRequest) => Asn1Object;
  createCaStore: (certs?: Array<X509Certificate | string>) => X509CaStore;
  certificateError: CertificateErrorMap;
  verifyCertificateChain: (
    caStore: X509CaStore,
    chain: X509Certificate[],
    options?: VerifyCallback | VerifyOptions
  ) => boolean;
  RDNAttributesAsArray: (rdn: Asn1Object, md: MessageDigest) => DnAttribute[];
  CRIAttributesAsArray: (attributes: Asn1Object) => DnAttribute[];
  pemToDer: (pem: string) => ByteStringBuffer;
  privateKeyFromPem: (pem: string) => RsaPrivateKey;
  privateKeyToPem: (key: RsaPrivateKey, maxline?: number) => string;
  privateKeyInfoToPem: (keyInfo: Asn1Object, maxline?: number) => string;
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

export type CertkitPkiFinalizeMethods = Pick<
  CertkitPki,
  'pemToDer' | 'privateKeyFromPem' | 'privateKeyToPem' | 'privateKeyInfoToPem'
>;

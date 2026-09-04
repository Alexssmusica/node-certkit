import type { Asn1Object, Asn1Validator, DerError } from '../../asn1/Asn1Types.js';

export type X509Runtime = {
  asn1: Record<string, unknown>;
  oids: Record<string, string>;
  md: Record<string, unknown>;
  util: Record<string, unknown>;
  pem: Record<string, unknown>;
  rsa: Record<string, unknown>;
  pss: Record<string, unknown>;
  mgf: Record<string, unknown>;
  random: Record<string, unknown>;
  pki: Record<string, unknown>;
};

export type X509Deps = X509Runtime;

export type X509Validators = {
  shortNames: Record<string, string>;
  x509CertificateValidator: Asn1Validator;
  certificationRequestValidator: Asn1Validator;
  certificationRequestInfoValidator: Asn1Validator;
  rsassaPssParameterValidator: Asn1Validator;
  rdnValidator: Asn1Validator;
};

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

export type ExtensionFillDeps = {
  asn1: Record<string, any>;
  oids: Record<string, string>;
  util: Record<string, any>;
  dnToAsn1: (obj: { attributes: DnAttribute[] }) => Asn1Object;
};

export type FillMissingExtensionFields = (e: X509Extension, options?: { cert?: X509Certificate }) => X509Extension;

export type CertificateExtensionFromAsn1Options = {
  ctx: X509AttachCtx;
};

export type DnAttribute = {
  type: string;
  value: string;
  valueTagClass: number;
  name?: string;
  shortName?: string;
  valueConstructed?: boolean;
  extensions?: X509Extension[];
};

/** Partial DN attribute accepted by setters; missing fields are filled by fillMissingFields. */
export type DnAttributeInput = {
  type?: string;
  value?: string;
  valueTagClass?: number;
  name?: string;
  shortName?: string;
  valueConstructed?: boolean;
  extensions?: X509Extension[];
};

export type DistinguishedName = {
  getField: (sn: string | { type?: string; name?: string; shortName?: string }) => DnAttribute | null;
  addField: (attr: DnAttributeInput) => void;
  attributes: DnAttribute[];
  hash: string | null;
  uniqueId?: string;
};

export type X509Extension = {
  id?: string;
  name?: string;
  critical?: boolean;
  value?: string;
  digitalSignature?: boolean;
  nonRepudiation?: boolean;
  keyEncipherment?: boolean;
  dataEncipherment?: boolean;
  keyAgreement?: boolean;
  keyCertSign?: boolean;
  cRLSign?: boolean;
  encipherOnly?: boolean;
  decipherOnly?: boolean;
  cA?: boolean;
  pathLenConstraint?: number;
  altNames?: unknown[];
  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: unknown;
  nsComment?: string;
  [key: string]: unknown;
};

export type SignatureParameters = {
  hash?: { algorithm: string; oid?: string };
  mgf?: { algorithm: string; oid?: string };
  saltLength?: number;
};

export type SigInfo = {
  algorithmOid: string | null;
  parameters?: SignatureParameters;
};

export type Validity = {
  notBefore: Date;
  notAfter: Date;
};

export type MessageDigest = {
  algorithm: string;
  update: (bytes: string) => void;
  digest: () => { toHex: () => string; getBytes: () => string };
  start?: () => void;
};

export type PublicKey = {
  n: unknown;
  e: unknown;
  verify: (md: MessageDigest, signature: string, scheme?: unknown) => boolean;
};

export type PrivateKey = {
  sign: (md: MessageDigest) => string;
};

export type X509Certificate = {
  version: number;
  serialNumber: string;
  signatureOid: string | null;
  signature: string | null;
  siginfo: SigInfo;
  validity: Validity;
  issuer: DistinguishedName;
  subject: DistinguishedName;
  extensions: X509Extension[];
  publicKey: PublicKey | null;
  md: MessageDigest | null;
  tbsCertificate?: Asn1Object;
  signatureParameters?: SignatureParameters;
  setSubject: (attrs: DnAttributeInput[], uniqueId?: string) => void;
  setIssuer: (attrs: DnAttributeInput[], uniqueId?: string) => void;
  setExtensions: (exts: X509Extension[]) => void;
  getExtension: (options: string | { id?: string; name?: string }) => X509Extension | null;
  sign: (key: PrivateKey, md?: MessageDigest) => void;
  verify: (child: X509Certificate) => boolean;
  isIssuer: (parent: X509Certificate) => boolean;
  issued: (child: X509Certificate) => boolean;
  generateSubjectKeyIdentifier: () => string;
  verifySubjectKeyIdentifier: () => boolean;
};

export type X509CertificationRequest = {
  version: number;
  signatureOid: string | null;
  signature: string | null;
  siginfo: SigInfo;
  subject: DistinguishedName;
  publicKey: PublicKey | null;
  attributes: DnAttribute[];
  getAttribute: (sn: string | { type?: string; name?: string; shortName?: string }) => DnAttribute | null;
  addAttribute: (attr: DnAttributeInput) => void;
  md: MessageDigest | null;
  certificationRequestInfo?: Asn1Object;
  signatureParameters?: SignatureParameters;
  setSubject: (attrs: DnAttributeInput[]) => void;
  setAttributes: (attrs: DnAttributeInput[]) => void;
  sign: (key: PrivateKey, md?: MessageDigest) => void;
  verify: () => boolean;
};

export type X509CaStore = {
  certs: Record<string, X509Certificate | X509Certificate[]>;
  getIssuer: (cert: X509Certificate) => X509Certificate | X509Certificate[] | null;
  addCertificate: (cert: X509Certificate | string) => void;
  hasCertificate: (cert: X509Certificate | string) => boolean;
  listAllCertificates: () => X509Certificate[];
  removeCertificate: (cert: X509Certificate | string) => X509Certificate | null;
};

export type CertificateErrorCode =
  | 'certkit.pki.BadCertificate'
  | 'certkit.pki.UnsupportedCertificate'
  | 'certkit.pki.CertificateRevoked'
  | 'certkit.pki.CertificateExpired'
  | 'certkit.pki.CertificateUnknown'
  | 'certkit.pki.UnknownCertificateAuthority';

export type CertificateErrorMap = {
  bad_certificate: CertificateErrorCode;
  unsupported_certificate: CertificateErrorCode;
  certificate_revoked: CertificateErrorCode;
  certificate_expired: CertificateErrorCode;
  certificate_unknown: CertificateErrorCode;
  unknown_ca: CertificateErrorCode;
};

export type VerifyCallback = (
  verified: boolean | CertificateErrorCode,
  depth: number,
  certs: X509Certificate[]
) => boolean | { message?: string; error?: CertificateErrorCode | string } | string | 0;

export type VerifyOptions = {
  verify?: VerifyCallback;
  validityCheckDate?: Date | null;
};

export type VerifyErrorObject = {
  message: string;
  error: CertificateErrorCode;
  notBefore?: Date;
  notAfter?: Date;
  now?: Date;
};

export type AttributeLookup = {
  type?: string;
  name?: string;
  shortName?: string;
};

/** Runtime context passed to x509 attach methods (shared, certificate, CSR). */
export type X509AttachCtx = X509Runtime & {
  asn1: Record<string, any>;
  oids: Record<string, string>;
  md: Record<string, { create: () => MessageDigest }>;
  pki: Record<string, any>;
  util?: Record<string, any>;
  pss?: { create: (...args: unknown[]) => unknown };
  mgf?: Record<string, any>;
  pem?: {
    decode: (pem: string) => Array<{ type: string; body: string; procType?: { type: string } }>;
    encode: (msg: { type: string; body: string }, options?: { maxline?: number }) => string;
  };
};

export type X509Helpers = {
  getAttribute: (obj: { attributes: DnAttribute[] }, options: string | AttributeLookup) => DnAttribute | null;
  readSignatureParameters: (oid: string, obj: Asn1Object, fillDefaults: boolean) => SignatureParameters;
  createSignatureDigest: (options: { signatureOid: string; type: string }) => MessageDigest;
  verifySignature: (options: {
    certificate: X509Certificate | X509CertificationRequest;
    subject?: X509Certificate | X509CertificationRequest;
    md: MessageDigest;
    signature: string | null;
  }) => boolean;
  dnToAsn1: (obj: { attributes: DnAttribute[] }) => Asn1Object;
  getAttributesAsJson: (attrs: DnAttribute[]) => Record<string, unknown>;
  fillMissingFields: (attrs: DnAttributeInput[]) => void;
  fillMissingExtensionFields: (e: X509Extension, options?: { cert?: X509Certificate }) => void;
  signatureParametersToAsn1: (oid: string, params: SignatureParameters) => Asn1Object;
  CRIAttributesToAsn1: (csr: X509CertificationRequest) => Asn1Object;
  dateToAsn1: (date: Date) => Asn1Object;
};

export type { Asn1Object, Asn1Validator, DerError };

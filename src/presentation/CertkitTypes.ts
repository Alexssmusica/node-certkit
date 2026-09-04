import type { Asn1NamespaceObject } from '../domain/asn1/Asn1Types.js';
import type { Pkcs7Asn1NamespaceObject } from '../domain/asn1/Pkcs7Asn1.js';
import type { AesNamespaceObject } from '../domain/cipher/AesAlgorithm.js';
import type { CipherNamespaceObject } from '../domain/cipher/CipherNamespace.js';
import type { DesNamespaceObject } from '../domain/cipher/DesAlgorithm.js';
import type { Rc2NamespaceObject } from '../domain/cipher/Rc2Cipher.js';
import type { Md5Digest } from '../domain/digest/Md5.js';
import type { Sha1Digest } from '../domain/digest/Sha1.js';
import type { Sha256Digest } from '../domain/digest/Sha256.js';
import type { Sha512Digest } from '../domain/digest/Sha512.js';
import type { DigestFactory, MdRegistry } from '../domain/digest/MdRegistry.js';
import type { HmacContext } from '../domain/digest/Hmac.js';
import type { Pbkdf2Function } from '../domain/pki/Pbkdf2.js';
import type { MgfNamespaceObject } from '../domain/pki/Mgf.js';
import type { BigInteger } from '../domain/math/BigInteger.js';
import type { UtilNamespaceObject } from '../domain/util/UtilNamespace.js';
import type { FortunaRandomNamespace } from '../infrastructure/random/FortunaRandom.js';
import type { CertkitPkcs12Namespace, CertkitPki, CertkitRsaNamespace } from '../domain/pki/CertkitPkiTypes.js';

export type CertkitOptions = {
  usePureJavaScript: boolean;
};

export type CertkitHmacNamespace = {
  create: () => HmacContext;
};

export type CertkitMgf1Namespace = {
  create: (md: unknown) => unknown;
};

export type CertkitJsbnNamespace = {
  BigInteger: typeof BigInteger;
};

export type CertkitPkcs1Namespace = {
  encode_rsa_oaep: (publicKey: unknown, message: string, options?: unknown) => string;
  decode_rsa_oaep: (privateKey: unknown, encrypted: string, options?: unknown) => string;
};

export type CertkitPemNamespace = {
  encode: (msg: unknown, options?: unknown) => string;
  decode: (str: string) => unknown[];
};

export type CertkitPrngNamespace = {
  create: (options: { md: unknown }) => unknown;
};

export type CertkitPrimeNamespace = {
  generateProbablePrime: (
    bits: number,
    options?: unknown,
    callback?: (err: Error | null, num?: BigInteger) => void
  ) => BigInteger | void;
};

export type CertkitPkcs5Namespace = {
  pbkdf2?: Pbkdf2Function;
};

export type CertkitPkcs7Namespace = {
  asn1?: Pkcs7Asn1NamespaceObject;
};

export type CertkitMgfNamespace = MgfNamespaceObject & {
  mgf1?: CertkitMgf1Namespace;
};

export type CertkitSha512Namespace = DigestFactory<Sha512Digest> & {
  sha384?: DigestFactory<Sha512Digest>;
  sha256?: DigestFactory<Sha512Digest>;
  sha224?: DigestFactory<Sha512Digest>;
};

/** Fully assembled flat certkit namespace after createCertkit() completes. */
export interface AssembledCertkit {
  options: CertkitOptions;
  cipher: CipherNamespaceObject;
  aes: AesNamespaceObject;
  des: DesNamespaceObject;
  rc2: Rc2NamespaceObject;
  asn1: Asn1NamespaceObject;
  md: MdRegistry;
  md5: DigestFactory<Md5Digest>;
  sha1: DigestFactory<Sha1Digest>;
  sha256: DigestFactory<Sha256Digest>;
  sha384: DigestFactory<Sha512Digest>;
  sha512: CertkitSha512Namespace;
  hmac: CertkitHmacNamespace;
  pbkdf2: Pbkdf2Function;
  pkcs5: CertkitPkcs5Namespace;
  pem: Record<string, unknown>;
  util: UtilNamespaceObject;
  prng: Record<string, unknown>;
  random: FortunaRandomNamespace;
  pkcs1: Record<string, unknown>;
  oids: Record<string, string>;
  pkcs7asn1: Pkcs7Asn1NamespaceObject;
  pkcs7: Record<string, unknown>;
  mgf1: Record<string, unknown>;
  mgf: MgfNamespaceObject;
  jsbn: CertkitJsbnNamespace;
  prime: Record<string, unknown>;
  pki: CertkitPki;
  rsa: CertkitRsaNamespace;
  pbe: CertkitPki['pbe'];
  pss: Record<string, unknown>;
  pkcs12: CertkitPkcs12Namespace;
}

export type { CertkitPki, CertkitPkcs12Namespace, CertkitRsaNamespace } from '../domain/pki/CertkitPkiTypes.js';

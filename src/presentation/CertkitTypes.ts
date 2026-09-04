import type { Asn1NamespaceObject, Pkcs7Asn1NamespaceObject } from '../domain/asn1/Asn1Types.js';
import type {
  AesNamespaceObject,
  CipherNamespaceObject,
  DesNamespaceObject,
  Rc2NamespaceObject
} from '../domain/cipher/CipherTypes.js';
import type {
  DigestFactory,
  HmacContext,
  Md5Digest,
  MdRegistry,
  Sha1Digest,
  Sha256Digest,
  Sha512Digest
} from '../domain/digest/DigestTypes.js';
import type { Mgf1 } from '../domain/pki/Mgf1.js';
import type { Pbkdf2Function } from '../domain/pki/Pbkdf2Types.js';
import type { PemCodec } from '../domain/pki/PemCodec.js';
import type { Pkcs1Codec } from '../domain/pki/Pkcs1Codec.js';
import type { PssScheme } from '../domain/pki/PssScheme.js';
import type { MgfNamespaceObject } from '../domain/pki/MgfTypes.js';
import type { BigInteger } from '../domain/math/BigInteger.js';
import type { UtilNamespaceObject } from '../domain/util/UtilTypes.js';
import type { PrimeService } from '../domain/prime/PrimeService.js';
import type { FortunaRandomNamespace } from '../infrastructure/random/RandomTypes.js';
import type { Fortuna } from '../infrastructure/prng/Fortuna.js';
import type { CertkitPkcs12Namespace, CertkitPki, CertkitRsaNamespace } from '../domain/pki/CertkitPkiTypes.js';

export type CertkitOptions = {
  usePureJavaScript: boolean;
};

export type CertkitHmacNamespace = {
  create: () => HmacContext;
};

export type CertkitMgf1Namespace = ReturnType<typeof Mgf1.createCertkitNamespace>;

export type CertkitJsbnNamespace = {
  BigInteger: typeof BigInteger;
};

export type CertkitPkcs1Namespace = ReturnType<typeof Pkcs1Codec.createCertkitNamespace>;

export type CertkitPemNamespace = ReturnType<typeof PemCodec.createCertkitNamespace>;

export type CertkitPrngNamespace = ReturnType<typeof Fortuna.createCertkitNamespace>;

export type CertkitPrimeNamespace = ReturnType<typeof PrimeService.createCertkitNamespace>;

export type CertkitPkcs5Namespace = {
  pbkdf2?: Pbkdf2Function;
};

export type CertkitPkcs7Namespace = {
  asn1?: Pkcs7Asn1NamespaceObject;
};

export type CertkitPssNamespace = ReturnType<typeof PssScheme.createCertkitNamespace>;

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
  pem: CertkitPemNamespace;
  util: UtilNamespaceObject;
  prng: CertkitPrngNamespace;
  random: FortunaRandomNamespace;
  pkcs1: CertkitPkcs1Namespace;
  oids: Record<string, string>;
  pkcs7asn1: Pkcs7Asn1NamespaceObject;
  pkcs7: CertkitPkcs7Namespace;
  mgf1: CertkitMgf1Namespace;
  mgf: CertkitMgfNamespace;
  jsbn: CertkitJsbnNamespace;
  prime: CertkitPrimeNamespace;
  pki: CertkitPki;
  rsa: CertkitRsaNamespace;
  pbe: CertkitPki['pbe'];
  pss: CertkitPssNamespace;
  pkcs12: CertkitPkcs12Namespace;
}

export type { CertkitPki, CertkitPkcs12Namespace, CertkitRsaNamespace } from '../domain/pki/CertkitPkiTypes.js';
export type {
  Pkcs12Bag,
  Pkcs12Bags,
  Pkcs12BagsFilter,
  Pkcs12CreateOptions,
  Pkcs12Pfx
} from '../domain/pki/Pkcs12Types.js';

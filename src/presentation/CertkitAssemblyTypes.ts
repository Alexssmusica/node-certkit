import type {Asn1NamespaceObject} from '../domain/asn1/Asn1Types.js';
import type {RsaService} from '../domain/pki/RsaService.js';

type DigestCreate = {create: () => unknown};
type Sha512Variant = {create: () => unknown};
type Pbkdf2Fn = (...args: never[]) => unknown;
type HmacNamespace = {create: () => unknown};

export interface MutableCertkit {
  options: {usePureJavaScript: boolean};
  cipher?: Record<string, unknown>;
  aes?: Record<string, unknown>;
  des?: Record<string, unknown>;
  rc2?: Record<string, unknown>;
  asn1?: Asn1NamespaceObject;
  md?: Record<string, unknown> & {
    algorithms: Record<string, unknown>;
  };
  md5?: DigestCreate;
  sha1?: DigestCreate;
  sha256?: DigestCreate;
  sha512?: DigestCreate & {
    sha384?: Sha512Variant;
    sha256?: Sha512Variant;
    sha224?: Sha512Variant;
  };
  sha384?: Sha512Variant;
  hmac?: HmacNamespace;
  pbkdf2?: Pbkdf2Fn;
  pkcs5?: {pbkdf2?: Pbkdf2Fn};
  pem?: Record<string, unknown>;
  util?: Record<string, unknown>;
  prng?: Record<string, unknown>;
  random?: Record<string, unknown> & {
    getBytesSync(count: number): string;
    getBytes(count: number): string;
  };
  pkcs1?: Record<string, unknown>;
  oids?: Record<string, string>;
  pkcs7asn1?: Record<string, unknown>;
  pkcs7?: {asn1?: Record<string, unknown>};
  mgf?: Record<string, unknown> & {mgf1?: Record<string, unknown>};
  mgf1?: Record<string, unknown>;
  jsbn?: {BigInteger: unknown};
  prime?: Record<string, unknown>;
  pki?: Record<string, unknown> & {
    oids?: Record<string, string>;
    rsa?: Record<string, unknown>;
    pbe?: Record<string, unknown>;
  };
  rsa?: Record<string, unknown>;
  pbe?: Record<string, unknown>;
  pss?: Record<string, unknown>;
  pkcs12?: Record<string, unknown>;
  [key: string]: unknown;
}

export type {RsaService};

import type { MdRegistry } from '../domain/digest/DigestTypes.js';
import type { CertkitPki } from '../domain/pki/CertkitPkiTypes.js';
import type { RsaService } from '../domain/pki/RsaService.js';
import type {
  AssembledCertkit,
  CertkitMgfNamespace,
  CertkitOptions,
  CertkitPkcs7Namespace,
  CertkitSha512Namespace
} from './CertkitTypes.js';

export type MutableCertkit = Partial<Omit<AssembledCertkit, 'pki' | 'md' | 'mgf' | 'pkcs7' | 'sha512'>> & {
  options: CertkitOptions;
  pki?: Partial<CertkitPki>;
  md?: Partial<MdRegistry>;
  mgf?: Partial<CertkitMgfNamespace>;
  pkcs7?: CertkitPkcs7Namespace;
  sha512?: Partial<CertkitSha512Namespace>;
};

export type { RsaService };

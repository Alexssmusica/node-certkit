import type { Asn1NamespaceObject, Asn1Validator } from '../asn1/Asn1Types.js';
import type { AesNamespaceObject, DesNamespaceObject, Rc2NamespaceObject } from '../cipher/CipherTypes.js';
import type { MdRegistry } from '../digest/DigestTypes.js';
import type { UtilNamespaceObject } from '../util/UtilTypes.js';
import type { FortunaRandomNamespace } from '../../infrastructure/random/RandomTypes.js';
import type { CertkitPkcs5Namespace } from '../../presentation/CertkitTypes.js';
import type { PemCodec } from './PemCodec.js';
import type { CertkitPki, CertkitPkiForPbe } from './CertkitPkiTypes.js';

export type PbeDeps = {
  asn1: Asn1NamespaceObject;
  oids: Record<string, string>;
  md: MdRegistry;
  util: UtilNamespaceObject;
  aes: AesNamespaceObject;
  des: DesNamespaceObject;
  rc2: Rc2NamespaceObject;
  pem: ReturnType<typeof PemCodec.createCertkitNamespace>;
  random: FortunaRandomNamespace;
  pkcs5: CertkitPkcs5Namespace;
  pki: Partial<CertkitPkiForPbe>;
};

export type PbeValidators = {
  encryptedPrivateKeyValidator: Asn1Validator;
  PBES2AlgorithmsValidator: Asn1Validator;
  pkcs12PbeParamsValidator: Asn1Validator;
};

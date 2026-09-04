import type { Asn1Validator } from '../asn1/Asn1Types.js';

export type PbeDeps = {
  asn1: any;
  oids: Record<string, string>;
  md: any;
  util: any;
  aes: any;
  des: any;
  rc2: any;
  pem: any;
  random: any;
  pbkdf2: any;
  pkcs5: any;
  cipher: any;
  pki: any;
};

export type PbeValidators = {
  encryptedPrivateKeyValidator: Asn1Validator;
  PBES2AlgorithmsValidator: Asn1Validator;
  pkcs12PbeParamsValidator: Asn1Validator;
};

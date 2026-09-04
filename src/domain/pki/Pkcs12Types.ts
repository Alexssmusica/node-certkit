import type { Asn1Object, Asn1Validator } from '../asn1/Asn1Types.js';
import type { RsaPrivateKey } from './RsaTypes.js';
import type { X509Certificate } from './x509/X509Types.js';

export type Pkcs12Deps = {
  asn1: any;
  oids: Record<string, string>;
  md: any;
  util: any;
  hmac: any;
  pbe: any;
  random: any;
  pki: any;
  pkcs7: { asn1: any };
};

export type Pkcs12Validators = {
  contentInfoValidator: Asn1Validator;
  pfxValidator: Asn1Validator;
  safeBagValidator: Asn1Validator;
  attributeValidator: Asn1Validator;
  certBagValidator: Asn1Validator;
};

export type Pkcs12Bag = {
  type: string;
  attributes: Record<string, string[] | undefined>;
  key?: RsaPrivateKey | null;
  cert?: X509Certificate | null;
  asn1?: Asn1Object;
};

export type Pkcs12BagsFilter = {
  localKeyId?: string;
  localKeyIdHex?: string;
  friendlyName?: string;
  bagType?: string;
};

export type Pkcs12Bags = Record<string, Pkcs12Bag[] | undefined>;

export type Pkcs12Pfx = {
  version: number;
  safeContents: Array<{ encrypted: boolean; safeBags: Pkcs12Bag[] }>;
  getBags: (filter: Pkcs12BagsFilter) => Pkcs12Bags;
  getBagsByFriendlyName: (friendlyName: string, bagType?: string) => Pkcs12Bag[];
  getBagsByLocalKeyId: (localKeyId: string, bagType?: string) => Pkcs12Bag[];
};

export type Pkcs12CreateOptions = {
  algorithm?: 'aes128' | 'aes192' | 'aes256' | '3des';
  count?: number;
  saltSize?: number;
  useMac?: boolean;
  localKeyId?: string | null;
  friendlyName?: string;
  generateLocalKeyId?: boolean;
  encAlgorithm?: string;
};

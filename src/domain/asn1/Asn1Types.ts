import type {Asn1Codec} from './Asn1Codec.js';

export type Asn1Object = {
  tagClass: number;
  type: number;
  constructed: boolean;
  composed: boolean;
  value: unknown;
  bitStringContents?: string;
  original?: Asn1Object;
};

export type Asn1FromDerOptions = {
  strict?: boolean;
  parseAllBytes?: boolean;
  decodeBitStrings?: boolean;
  maxDepth?: number;
};

export type Asn1Validator = {
  name?: string;
  tagClass?: number;
  type?: number;
  constructed?: boolean;
  value?: Asn1Validator[];
  optional?: boolean;
  capture?: string;
  captureAsn1?: string;
  captureBitStringContents?: string;
  captureBitStringValue?: string;
};

export type Asn1NamespaceObject = Record<string, unknown> & {
  Class: typeof Asn1Codec.Class;
  Type: typeof Asn1Codec.Type;
  maxDepth: number;
  create: typeof Asn1Codec.create;
  copy: typeof Asn1Codec.copy;
  equals: typeof Asn1Codec.equals;
  getBerValueLength: typeof Asn1Codec.getBerValueLength;
  fromDer: typeof Asn1Codec.fromDer;
  toDer: typeof Asn1Codec.toDer;
  oidToDer: typeof Asn1Codec.oidToDer;
  derToOid: typeof Asn1Codec.derToOid;
  utcTimeToDate: typeof Asn1Codec.utcTimeToDate;
  generalizedTimeToDate: typeof Asn1Codec.generalizedTimeToDate;
  dateToUtcTime: typeof Asn1Codec.dateToUtcTime;
  dateToGeneralizedTime: typeof Asn1Codec.dateToGeneralizedTime;
  integerToDer: typeof Asn1Codec.integerToDer;
  derToInteger: typeof Asn1Codec.derToInteger;
  validate: typeof Asn1Codec.validate;
  prettyPrint: typeof Asn1Codec.prettyPrint;
};

export type DerError = Error & Record<string, unknown>;

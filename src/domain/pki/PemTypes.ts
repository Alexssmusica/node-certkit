export type PemProcType = {
  version: string;
  type: string;
};

export type PemDekInfo = {
  algorithm: string;
  parameters: string | null;
};

export type PemHeader = {
  name: string;
  values: string[];
};

export type PemMessage = {
  type: string;
  procType: PemProcType | null;
  contentDomain: string | null;
  dekInfo: PemDekInfo | null;
  headers: PemHeader[];
  body: string;
};

export type PemEncodeOptions = {
  maxline?: number;
};

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

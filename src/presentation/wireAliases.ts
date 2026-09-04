/**
 * Cross-namespace alias wiring for the flat certkit object.
 * Centralizes cross-namespace aliases for the flat certkit object.
 */
export interface CertkitNamespace {
  options: {usePureJavaScript: boolean};
  pkcs5?: {pbkdf2?: unknown};
  pbkdf2?: unknown;
  pkcs7?: {asn1?: unknown};
  pkcs7asn1?: unknown;
  mgf?: {mgf1?: unknown};
  mgf1?: unknown;
  pki?: {oids?: Record<string, string>; rsa?: unknown};
  oids?: Record<string, string>;
  rsa?: unknown;
  sha512?: {
    sha384?: unknown;
    sha256?: unknown;
    sha224?: unknown;
  };
  sha384?: unknown;
  md?: Record<string, unknown> & {
    algorithms?: Record<string, unknown>;
  };
  [key: string]: unknown;
}

export function wireCrossNamespaceAliases(certkit: CertkitNamespace): void {
  // certkit.pkcs5.pbkdf2 ↔ certkit.pbkdf2
  if (certkit.pbkdf2) {
    certkit.pkcs5 = certkit.pkcs5 || {};
    if (!certkit.pkcs5.pbkdf2) {
      certkit.pkcs5.pbkdf2 = certkit.pbkdf2;
    }
    if (!certkit.pbkdf2) {
      certkit.pbkdf2 = certkit.pkcs5.pbkdf2;
    }
  }

  // certkit.pkcs7.asn1 ↔ certkit.pkcs7asn1
  if (certkit.pkcs7asn1) {
    certkit.pkcs7 = certkit.pkcs7 || {};
    if (!certkit.pkcs7.asn1) {
      certkit.pkcs7.asn1 = certkit.pkcs7asn1;
    }
  }

  // certkit.mgf.mgf1 ↔ certkit.mgf1
  if (certkit.mgf1) {
    certkit.mgf = certkit.mgf || {};
    if (!certkit.mgf.mgf1) {
      certkit.mgf.mgf1 = certkit.mgf1;
    }
  }

  // certkit.pki.oids ↔ certkit.oids
  if (certkit.pki?.oids) {
    if (!certkit.oids) {
      certkit.oids = certkit.pki.oids;
    }
  } else if (certkit.oids) {
    certkit.pki = certkit.pki || {};
    if (!certkit.pki.oids) {
      certkit.pki.oids = certkit.oids;
    }
  }

  // certkit.pki.rsa ↔ certkit.rsa
  if (certkit.pki?.rsa) {
    if (!certkit.rsa) {
      certkit.rsa = certkit.pki.rsa;
    }
  } else if (certkit.rsa) {
    certkit.pki = certkit.pki || {};
    if (!certkit.pki.rsa) {
      certkit.pki.rsa = certkit.rsa;
    }
  }

  // sha512 family aliases
  if (certkit.sha512 && certkit.md) {
    const md = certkit.md;
    const algorithms = md.algorithms || (md.algorithms = {});

    md.sha512 = md.sha512 || certkit.sha512;
    algorithms.sha512 = algorithms.sha512 || certkit.sha512;

    const sha384 = certkit.sha384 || certkit.sha512.sha384;
    if (sha384) {
      certkit.sha384 = sha384;
      certkit.sha512.sha384 = sha384;
      md.sha384 = md.sha384 || sha384;
      algorithms.sha384 = algorithms.sha384 || sha384;
    }

    const sha512_256 = certkit.sha512.sha256;
    if (sha512_256) {
      md['sha512/256'] = md['sha512/256'] || sha512_256;
      algorithms['sha512/256'] = algorithms['sha512/256'] || sha512_256;
    }

    const sha512_224 = certkit.sha512.sha224;
    if (sha512_224) {
      md['sha512/224'] = md['sha512/224'] || sha512_224;
      algorithms['sha512/224'] = algorithms['sha512/224'] || sha512_224;
    }
  }
}

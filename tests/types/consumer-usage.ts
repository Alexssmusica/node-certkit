/**
 * Type-level regression test mirroring a real consumer migration from node-forge.
 * Validates src/index.ts public types (namespace merge + PKCS#12 flow).
 */
import certkit, { type Pkcs12Pfx } from '../../src/index.js';

type CertificateData = {
  emissao: Date;
  validade: Date;
  nome: string | undefined;
  cnpj: string | undefined;
};

type CertificateLoadInput = {
  buffer: string;
  password: string;
};

type CertificateLoadOutput = {
  pem: string;
  key: string;
  data: CertificateData;
};

type LoadCertificate = (input: CertificateLoadInput) => CertificateLoadOutput;

function getKey(p12: Pkcs12Pfx): string {
  const shroudedKeyBags =
    p12.getBags({ bagType: certkit.pki.oids.pkcs8ShroudedKeyBag })[certkit.pki.oids.pkcs8ShroudedKeyBag] ?? [];
  const keyBags = p12.getBags({ bagType: certkit.pki.oids.keyBag })[certkit.pki.oids.keyBag] ?? [];
  const keyData = shroudedKeyBags.concat(keyBags);
  if (!keyData[0]?.key) {
    throw new Error('Private key not found in certificate');
  }
  const rsaPrivateKey = certkit.pki.privateKeyToAsn1(keyData[0].key);
  const privateKeyInfo = certkit.pki.wrapRsaPrivateKey(rsaPrivateKey);
  return certkit.pki.privateKeyInfoToPem(privateKeyInfo);
}

function getPem(p12: Pkcs12Pfx): string {
  const certBags = p12.getBags({ bagType: certkit.pki.oids.certBag })[certkit.pki.oids.certBag] ?? [];
  if (!certBags[0]?.cert) {
    throw new Error('Certificate not found in certificate');
  }
  return certkit.pki.certificateToPem(certBags[0].cert);
}

function getData(pem: string): CertificateData {
  const certificate = certkit.pki.certificateFromPem(pem);
  const commonName = certificate.subject.getField({ name: 'commonName' });
  if (!commonName) {
    throw new Error('commonName not found in certificate subject');
  }
  const values = commonName.value.toString().split(':');
  return {
    emissao: certificate.validity.notBefore,
    validade: certificate.validity.notAfter,
    nome: values[0],
    cnpj: values[1]
  };
}

export const setupLoadCertificate = (): LoadCertificate => (input) => {
  const decoded = certkit.util.binary.base64.decode(input.buffer);
  const asn = certkit.asn1.fromDer(new certkit.util.ByteStringBuffer(decoded));
  let p12: Pkcs12Pfx;
  try {
    p12 = certkit.pkcs12.pkcs12FromAsn1(asn, true, input.password);
  } catch {
    throw new Error('CertificatePasswordError');
  }
  const pem = getPem(p12);
  const data = getData(pem);
  return {
    pem,
    key: getKey(p12),
    data
  };
};

// Compile-time assertions for namespace types and README examples.
type _Pkcs12Pfx = import('../../src/index.js').Pkcs12Pfx;
type _Certificate = import('../../src/index.js').X509Certificate;
type _Asn1 = import('../../src/index.js').Asn1Object;
type _ByteBuffer = import('../../src/index.js').ByteStringBuffer;

declare const _pemExample: string;
declare const _cert: import('../../src/index.js').X509Certificate;
declare const _password: string;

const _loaded: Pkcs12Pfx = certkit.pkcs12.pkcs12FromAsn1(certkit.asn1.fromDer(_pemExample), false, _password);
void _loaded;
void certkit.pki.certificateToPem(_cert);
void certkit.pem.decode(_pemExample);
void certkit.pkcs1.encode_rsa_oaep({ n: { bitLength: () => 2048 } }, 'message');

// Namespace type syntax via named import (forge-style).
import { certkit as certkitTypes } from '../../src/index.js';
type _NamespacePkcs12Pfx = certkitTypes.pkcs12.Pkcs12Pfx;
type _NamespaceCertificate = certkitTypes.pki.Certificate;
void (undefined as unknown as _NamespacePkcs12Pfx);
void (undefined as unknown as _NamespaceCertificate);

export {};

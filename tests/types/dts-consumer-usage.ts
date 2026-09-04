/**
 * Validates the published declaration file (lib/index.d.ts) as consumers see it.
 * Run after `npm run build` via `npm run test:dts`.
 */
import certkit, { type Pkcs12Pfx } from '../../lib/index.js';

type CertificateData = {
  emissao: Date;
  validade: Date;
  nome: string | undefined;
  cnpj: string | undefined;
};

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

function loadFromBuffer(bufferB64: string, password: string): { pem: string; key: string; data: CertificateData } {
  const decoded = certkit.util.binary.base64.decode(bufferB64);
  const asn = certkit.asn1.fromDer(new certkit.util.ByteStringBuffer(decoded));
  const p12: Pkcs12Pfx = certkit.pkcs12.pkcs12FromAsn1(asn, true, password);
  const certBags = p12.getBags({ bagType: certkit.pki.oids.certBag })[certkit.pki.oids.certBag] ?? [];
  if (!certBags[0]?.cert) {
    throw new Error('Certificate not found');
  }
  const pem = certkit.pki.certificateToPem(certBags[0].cert);
  const certificate = certkit.pki.certificateFromPem(pem);
  const commonName = certificate.subject.getField({ name: 'commonName' });
  if (!commonName) {
    throw new Error('commonName not found');
  }
  const values = commonName.value.toString().split(':');
  return {
    pem,
    key: getKey(p12),
    data: {
      emissao: certificate.validity.notBefore,
      validade: certificate.validity.notAfter,
      nome: values[0],
      cnpj: values[1]
    }
  };
}

void loadFromBuffer;

export {};

/**
 * Validates the published declaration file (lib/index.d.ts) as consumers see it.
 * Run after `npm run build` via `npm run test:dts`.
 */
import { certkit, type Pkcs12Pfx } from '../../lib/index.js';

type CertificateData = {
  emissao: Date;
  validade: Date;
  nome: string | undefined;
  cnpj: string | undefined;
};

type CertificateNFSeData = {
  p12Buffer: Buffer;
  tempPassword: string;
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

function getPrivateKeyNFSe(
  privateKey: certkit.pki.rsa.PrivateKey,
  certificate: certkit.pki.Certificate,
  caCertificates: certkit.pki.Certificate[]
): CertificateNFSeData {
  const tempPassword = Math.random().toString(36).substring(2);
  const p12Asn1 = certkit.pkcs12.toPkcs12Asn1(
    privateKey,
    [certificate, ...caCertificates],
    tempPassword,
    { algorithm: '3des' }
  );
  const p12Der = certkit.asn1.toDer(p12Asn1).getBytes();
  const p12Buffer = Buffer.from(p12Der, 'binary');
  return { p12Buffer, tempPassword };
}

function loadCertificateNFSe(p12: Pkcs12Pfx): CertificateNFSeData {
  let privateKey: certkit.pki.rsa.PrivateKey | null = null;
  let certificate: certkit.pki.Certificate | null = null;
  const caCertificates: certkit.pki.Certificate[] = [];

  for (const safeContent of p12.safeContents) {
    for (const bag of safeContent.safeBags) {
      if (bag.type === certkit.pki.oids.pkcs8ShroudedKeyBag || bag.type === certkit.pki.oids.keyBag) {
        privateKey = bag.key ?? null;
      }
      if (bag.type === certkit.pki.oids.certBag && bag.cert) {
        const bc = bag.cert.getExtension('basicConstraints');
        if (!bc || bc['cA'] === false) {
          certificate = bag.cert;
        } else {
          caCertificates.push(bag.cert);
        }
      }
    }
  }

  if (!privateKey || !certificate) {
    throw new Error('Could not find private key or certificate in PFX/P12 file.');
  }

  return getPrivateKeyNFSe(privateKey, certificate, caCertificates);
}

void loadFromBuffer;
void loadCertificateNFSe;

export {};

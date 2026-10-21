/**
 * Type-level regression test for NFSe certificate load flow.
 * Validates named import { certkit } for runtime API and named type exports.
 */
import { certkit, type Pkcs12Pfx, type RsaPrivateKey, type X509Certificate } from '../../src/index.js';

type CertificateNFSeData = {
  p12Buffer: Buffer;
  tempPassword: string;
};

function getPrivateKeyNFSe(
  privateKey: RsaPrivateKey,
  certificate: X509Certificate,
  caCertificates: X509Certificate[]
): CertificateNFSeData {
  const tempPassword = Math.random().toString(36).substring(2);
  const p12Asn1 = certkit.pkcs12.toPkcs12Asn1(privateKey, [certificate, ...caCertificates], tempPassword, {
    algorithm: '3des'
  });
  const p12Der = certkit.asn1.toDer(p12Asn1).getBytes();
  const p12Buffer = Buffer.from(p12Der, 'binary');
  return { p12Buffer, tempPassword };
}

export function loadCertificateNFSe(p12: Pkcs12Pfx): CertificateNFSeData {
  let privateKey: RsaPrivateKey | null = null;
  let certificate: X509Certificate | null = null;
  const caCertificates: X509Certificate[] = [];

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

export {};

import { describe, it, expect } from 'vitest';
import certkit, { type Pkcs12Pfx } from '../src/index.js';
import fs from 'node:fs';
import path from 'node:path';

const fixtureDir = path.join(import.meta.dirname, 'fixtures');
const bufferB64 = fs.readFileSync(path.join(fixtureDir, 'certificate.pfx.b64'), 'utf8').trim();
const password = fs.readFileSync(path.join(fixtureDir, 'certificate.password.txt'), 'utf8').trim();
const meta = JSON.parse(fs.readFileSync(path.join(fixtureDir, 'certificate.meta.json'), 'utf8')) as {
  nome: string;
  cnpj: string;
  notBefore: string;
  notAfter: string;
};

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

function loadCertificate(input: CertificateLoadInput) {
  const decoded = certkit.util.binary.base64.decode(input.buffer);
  const asn = certkit.asn1.fromDer(new certkit.util.ByteStringBuffer(decoded));
  const p12 = certkit.pkcs12.pkcs12FromAsn1(asn, true, input.password);
  const pem = getPem(p12);
  const data = getData(pem);
  return {
    pem,
    key: getKey(p12),
    data
  };
}

describe('Certificate load golden test', () => {
  it('loads PKCS#12 and extracts PEM, key and certificate data', () => {
    const result = loadCertificate({ buffer: bufferB64, password });
    expect(result.pem.includes('BEGIN CERTIFICATE')).toBeTruthy();
    expect(result.key.includes('BEGIN RSA PRIVATE KEY') || result.key.includes('BEGIN PRIVATE KEY')).toBeTruthy();
    expect(result.data.nome).toBe(meta.nome);
    expect(result.data.cnpj).toBe(meta.cnpj);
    expect(result.data.emissao.toISOString()).toBe(meta.notBefore);
    expect(result.data.validade.toISOString()).toBe(meta.notAfter);
  });

  it('throws on wrong password', () => {
    expect(() => {
      loadCertificate({ buffer: bufferB64, password: 'wrong' });
    }).toThrow();
  });
});

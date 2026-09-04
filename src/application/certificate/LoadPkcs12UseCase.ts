import type {InfrastructureContext} from '../../infrastructure/index.js';

export interface CertificateField {
  value: string | unknown;
}

export interface DistinguishedName {
  getField(sn: string | {name?: string; type?: string}): CertificateField;
}

export interface Certificate {
  subject: DistinguishedName;
  validity: {
    notBefore: Date;
    notAfter: Date;
  };
}

export interface Bag {
  cert?: Certificate;
  key?: unknown;
}

export interface Pkcs12Pfx {
  getBags(filter: {bagType: string}): Record<string, Bag[] | undefined>;
}

export interface LoadPkcs12CertkitApi {
  util: {
    binary: {
      base64: {
        decode(input: string): Uint8Array;
      };
    };
    ByteStringBuffer: new (input?: Uint8Array | string) => unknown;
  };
  asn1: {
    fromDer(bytes: unknown): unknown;
  };
  pkcs12: {
    pkcs12FromAsn1(asn1: unknown, strict: boolean, password: string): Pkcs12Pfx;
  };
  pki: {
    oids: Record<string, string>;
    privateKeyToAsn1(key: unknown): unknown;
    wrapRsaPrivateKey(key: unknown): unknown;
    privateKeyInfoToPem(keyInfo: unknown): string;
    certificateToPem(cert: Certificate): string;
    certificateFromPem(pem: string): Certificate;
  };
}

export interface LoadPkcs12Input {
  buffer: string;
  password: string;
}

export interface CertificateData {
  emissao: Date;
  validade: Date;
  nome: string;
  cnpj: string;
}

export interface LoadPkcs12Result {
  pem: string;
  key: string;
  data: CertificateData;
}

/**
 * Certificate load flow: base64 → DER → PKCS#12 → bags → PEM/key/data.
 */
export class LoadPkcs12UseCase {
  constructor(
    private readonly ctx: InfrastructureContext,
    private readonly certkit: LoadPkcs12CertkitApi
  ) {}

  execute(input: LoadPkcs12Input): LoadPkcs12Result {
    void this.ctx;

    const buffer = this.certkit.util.binary.base64.decode(input.buffer);
    const asn = this.certkit.asn1.fromDer(new this.certkit.util.ByteStringBuffer(buffer));
    const p12 = this.certkit.pkcs12.pkcs12FromAsn1(asn, true, input.password);
    const pem = this.getPem(p12);

    return {
      pem,
      key: this.getKey(p12),
      data: this.getData(pem)
    };
  }

  private getKey(p12: Pkcs12Pfx): string {
    const oids = this.certkit.pki.oids;
    const shroudedKeyBags = p12.getBags({
      bagType: oids.pkcs8ShroudedKeyBag!
    })[oids.pkcs8ShroudedKeyBag!] ?? [];
    const keyBags = p12.getBags({
      bagType: oids.keyBag!
    })[oids.keyBag!] ?? [];
    const keyData = shroudedKeyBags.concat(keyBags);

    if (!keyData[0]?.key) {
      throw new Error('Private key not found in certificate');
    }

    const rsaPrivateKey = this.certkit.pki.privateKeyToAsn1(keyData[0].key);
    const privateKeyInfo = this.certkit.pki.wrapRsaPrivateKey(rsaPrivateKey);
    return this.certkit.pki.privateKeyInfoToPem(privateKeyInfo);
  }

  private getPem(p12: Pkcs12Pfx): string {
    const certBags = p12.getBags({
      bagType: this.certkit.pki.oids.certBag!
    })[this.certkit.pki.oids.certBag!] ?? [];

    if (!certBags[0]?.cert) {
      throw new Error('Certificate not found in certificate');
    }

    return this.certkit.pki.certificateToPem(certBags[0].cert);
  }

  private getData(pem: string): CertificateData {
    const certificate = this.certkit.pki.certificateFromPem(pem);
    const fieldValue = certificate.subject.getField({name: 'commonName'}).value;
    const values = String(fieldValue).split(':');

    return {
      emissao: certificate.validity.notBefore,
      validade: certificate.validity.notAfter,
      nome: values[0]!,
      cnpj: values[1]!
    };
  }
}

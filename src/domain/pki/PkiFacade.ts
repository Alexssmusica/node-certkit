import type { PemKeyCodec } from '../ports/index.js';
import { PemCodec } from './PemCodec.js';
import { PbeService } from './PbeService.js';
import { Pkcs12Service } from './Pkcs12Service.js';
import { X509Service } from './X509Service.js';

export type PkiFacadeDeps = {
  asn1: Record<string, unknown>;
  oids: Record<string, string>;
  md: Record<string, unknown>;
  util: Record<string, unknown>;
  pem: ReturnType<typeof PemCodec.createCertkitNamespace>;
  aes: Record<string, unknown>;
  des: Record<string, unknown>;
  rc2: Record<string, unknown>;
  random: Record<string, unknown>;
  pbkdf2: Record<string, unknown>;
  pkcs5: Record<string, unknown>;
  cipher: Record<string, unknown>;
  hmac: Record<string, unknown>;
  pss: Record<string, unknown>;
  mgf: Record<string, unknown>;
  pkcs7: { asn1: Record<string, unknown> };
  pki: Record<string, unknown>;
};

export type PkiFinalizeDeps = PkiFacadeDeps & {
  rsaService: { setPemKeyCodec(codec: PemKeyCodec): void };
};

/**
 * Explicit assembler facade for certkit.pki, replacing incremental mutation
 * by oids, rsa, pbe, x509, pkcs12, and pki modules.
 */
export class PkiFacade {
  static attachPbe(deps: PkiFacadeDeps): Record<string, unknown> {
    const { pbe, pkiMethods } = PbeService.createCertkitNamespace({
      asn1: deps.asn1,
      oids: deps.oids,
      md: deps.md,
      util: deps.util,
      aes: deps.aes,
      des: deps.des,
      rc2: deps.rc2,
      pem: deps.pem,
      random: deps.random,
      pbkdf2: deps.pbkdf2,
      pkcs5: deps.pkcs5,
      cipher: deps.cipher,
      pki: deps.pki
    });
    Object.assign(deps.pki, pkiMethods);
    deps.pki.pbe = pbe;
    return pbe;
  }

  static attachX509(deps: PkiFacadeDeps): void {
    const x509Methods = X509Service.createCertkitNamespace({
      asn1: deps.asn1,
      oids: deps.oids,
      md: deps.md,
      util: deps.util,
      pem: deps.pem,
      rsa: deps.pki.rsa as Record<string, unknown>,
      pss: deps.pss,
      mgf: deps.mgf,
      random: deps.random,
      pki: deps.pki
    });
    Object.assign(deps.pki, x509Methods);
  }

  static attachPkcs12(deps: PkiFacadeDeps & { pbe: Record<string, unknown> }): Record<string, unknown> {
    return Pkcs12Service.createCertkitNamespace({
      asn1: deps.asn1,
      oids: deps.oids,
      md: deps.md,
      util: deps.util,
      hmac: deps.hmac,
      pbe: deps.pbe,
      random: deps.random,
      pki: deps.pki,
      pkcs7: deps.pkcs7
    });
  }

  static finalize(deps: PkiFinalizeDeps): void {
    PkiFacade.#attachPemMethods(deps.pki, deps);
    deps.rsaService.setPemKeyCodec({
      privateKeyFromPem(pem: string) {
        return (deps.pki.privateKeyFromPem as (p: string) => unknown)(pem);
      },
      publicKeyFromPem(pem: string) {
        return (deps.pki.publicKeyFromPem as (p: string) => unknown)(pem);
      }
    });
  }

  static #attachPemMethods(pki: Record<string, unknown>, deps: PkiFacadeDeps): void {
    const asn1 = deps.asn1;

    pki.pemToDer = function (pem: string) {
      const msg = deps.pem.decode(pem)[0]!;
      if (msg.procType?.type === 'ENCRYPTED') {
        throw new Error('Could not convert PEM to DER; PEM is encrypted.');
      }
      return (deps.util.createBuffer as (body: string) => unknown)(msg.body);
    };

    pki.privateKeyFromPem = function (pem: string) {
      const msg = deps.pem.decode(pem)[0]!;
      if (msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
        const error = new Error(
          'Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".'
        ) as Error & {
          headerType?: string;
        };
        error.headerType = msg.type;
        throw error;
      }
      if (msg.procType?.type === 'ENCRYPTED') {
        throw new Error('Could not convert private key from PEM; PEM is encrypted.');
      }
      const obj = (asn1 as { fromDer: (body: string) => unknown }).fromDer(msg.body);
      return (pki.privateKeyFromAsn1 as (o: unknown) => unknown)(obj);
    };

    pki.privateKeyToPem = function (key: unknown, maxline?: number) {
      const msg = {
        type: 'RSA PRIVATE KEY',
        body: (asn1 as { toDer: (o: unknown) => { getBytes(): string } })
          .toDer((pki.privateKeyToAsn1 as (k: unknown) => unknown)(key))
          .getBytes()
      };
      return (deps.pem.encode as (msg: { type: string; body: string }, options?: { maxline?: number }) => string)(msg, { maxline });
    };

    pki.privateKeyInfoToPem = function (keyInfo: unknown, maxline?: number) {
      const msg = {
        type: 'PRIVATE KEY',
        body: (asn1 as { toDer: (o: unknown) => { getBytes(): string } }).toDer(keyInfo).getBytes()
      };
      return (deps.pem.encode as (msg: { type: string; body: string }, options?: { maxline?: number }) => string)(msg, { maxline });
    };
  }
}

export default PkiFacade;

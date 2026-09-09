import type { X509Runtime } from './X509Runtime.js';
import type { CertkitPki } from '../CertkitPkiTypes.js';
import type { X509Helpers } from './X509Types.js';
import type { DistinguishedName, X509CaStore, X509Certificate } from './X509Types.js';

export class CaStore {
  static attach(ctx: X509Runtime, helpers: X509Helpers): void {
    const asn1 = ctx.asn1;
    const pki = ctx.pki as CertkitPki;
    const dnToAsn1 = helpers.dnToAsn1;

    pki.createCaStore = function (certs?: Array<X509Certificate | string>): X509CaStore {
      const caStore = {
        certs: {} as Record<string, X509Certificate | X509Certificate[]>
      } as X509CaStore;

      caStore.getIssuer = function (cert: X509Certificate) {
        return CaStore.#getBySubject(caStore, cert.issuer, ctx, pki, dnToAsn1);
      };

      caStore.addCertificate = function (cert: X509Certificate | string) {
        if (typeof cert === 'string') {
          cert = pki.certificateFromPem(cert);
        }

        CaStore.#ensureSubjectHasHash(cert.subject, ctx, pki, dnToAsn1);

        if (!caStore.hasCertificate(cert)) {
          const hash = cert.subject.hash!;
          if (hash in caStore.certs) {
            let existingCerts = caStore.certs[hash];
            if (!ctx.util.isArray(existingCerts)) {
              existingCerts = [existingCerts as X509Certificate];
            }
            (existingCerts as X509Certificate[]).push(cert);
            caStore.certs[hash] = existingCerts;
          } else {
            caStore.certs[hash] = cert;
          }
        }
      };

      caStore.hasCertificate = function (cert: X509Certificate | string): boolean {
        if (typeof cert === 'string') {
          cert = pki.certificateFromPem(cert);
        }

        let match = CaStore.#getBySubject(caStore, cert.subject, ctx, pki, dnToAsn1);
        if (!match) {
          return false;
        }
        if (!ctx.util.isArray(match)) {
          match = [match as X509Certificate];
        }
        const matchArr = match as X509Certificate[];
        const der1 = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
        for (let i = 0; i < matchArr.length; ++i) {
          const der2 = asn1.toDer(pki.certificateToAsn1(matchArr[i]!)).getBytes();
          if (der1 === der2) {
            return true;
          }
        }
        return false;
      };

      caStore.listAllCertificates = function (): X509Certificate[] {
        const certList: X509Certificate[] = [];

        for (const hash in caStore.certs) {
          if (Object.prototype.hasOwnProperty.call(caStore.certs, hash)) {
            const value = caStore.certs[hash]!;
            if (!ctx.util.isArray(value)) {
              certList.push(value as X509Certificate);
            } else {
              for (let i = 0; i < (value as X509Certificate[]).length; ++i) {
                certList.push((value as X509Certificate[])[i]!);
              }
            }
          }
        }

        return certList;
      };

      caStore.removeCertificate = function (cert: X509Certificate | string): X509Certificate | null {
        let result: X509Certificate | null = null;

        if (typeof cert === 'string') {
          cert = pki.certificateFromPem(cert);
        }
        CaStore.#ensureSubjectHasHash(cert.subject, ctx, pki, dnToAsn1);
        if (!caStore.hasCertificate(cert)) {
          return null;
        }

        const match = CaStore.#getBySubject(caStore, cert.subject, ctx, pki, dnToAsn1);

        if (!ctx.util.isArray(match)) {
          result = caStore.certs[cert.subject.hash!] as X509Certificate;
          delete caStore.certs[cert.subject.hash!];
          return result;
        }

        const der1 = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
        const matchArr = match as X509Certificate[];
        for (let i = 0; i < matchArr.length; ++i) {
          const der2 = asn1.toDer(pki.certificateToAsn1(matchArr[i]!)).getBytes();
          if (der1 === der2) {
            result = matchArr[i]!;
            matchArr.splice(i, 1);
          }
        }
        if (matchArr.length === 0) {
          delete caStore.certs[cert.subject.hash!];
        }

        return result;
      };

      if (certs) {
        for (let i = 0; i < certs.length; ++i) {
          caStore.addCertificate(certs[i]!);
        }
      }

      return caStore;
    };
  }

  static #getBySubject(
    caStore: X509CaStore,
    subject: DistinguishedName,
    ctx: X509Runtime,
    pki: CertkitPki,
    dnToAsn1: X509Helpers['dnToAsn1']
  ): X509Certificate | X509Certificate[] | null {
    CaStore.#ensureSubjectHasHash(subject, ctx, pki, dnToAsn1);
    return caStore.certs[subject.hash!] || null;
  }

  static #ensureSubjectHasHash(
    subject: DistinguishedName,
    ctx: X509Runtime,
    pki: CertkitPki,
    dnToAsn1: X509Helpers['dnToAsn1']
  ): void {
    if (!subject.hash) {
      const md = ctx.md.sha1.create();
      subject.attributes = pki.RDNAttributesAsArray(dnToAsn1(subject), md);
      subject.hash = md.digest().toHex();
    }
  }
}

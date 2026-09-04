import type { Asn1NamespaceObject, Asn1Object } from '../asn1/Asn1Types.js';
import type { PemKeyCodec } from '../ports/index.js';
import type { RsaPrivateKey } from './RsaTypes.js';
import type { PemMessage } from './PemTypes.js';
import { PemCodec } from './PemCodec.js';
import { PbeService } from './PbeService.js';
import { Pkcs12Service } from './Pkcs12Service.js';
import { X509Service } from './X509Service.js';
import type {
  CertkitPbeNamespace,
  CertkitPki,
  CertkitPkcs12Namespace,
  PkiFacadeDeps,
  PkiFinalizeDeps
} from './CertkitPkiTypes.js';

export type { PkiFacadeDeps, PkiFinalizeDeps } from './CertkitPkiTypes.js';

/**
 * Explicit assembler facade for certkit.pki, replacing incremental mutation
 * by oids, rsa, pbe, x509, pkcs12, and pki modules.
 */
export class PkiFacade {
  static attachPbe(deps: PkiFacadeDeps): CertkitPbeNamespace {
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
      rsa: deps.pki.rsa!,
      pss: deps.pss,
      mgf: deps.mgf,
      random: deps.random,
      pki: deps.pki
    });
    Object.assign(deps.pki, x509Methods);
  }

  static attachPkcs12(deps: PkiFacadeDeps & { pbe: CertkitPbeNamespace }): CertkitPkcs12Namespace {
    return Pkcs12Service.createCertkitNamespace({
      asn1: deps.asn1,
      oids: deps.oids,
      md: deps.md,
      util: deps.util,
      hmac: deps.hmac,
      pbe: deps.pbe,
      random: deps.random,
      pki: deps.pki,
      pkcs7: { asn1: deps.pkcs7.asn1! }
    });
  }

  static finalize(deps: PkiFinalizeDeps): void {
    PkiFacade.#attachPemMethods(deps.pki, deps);
    deps.rsaService.setPemKeyCodec({
      privateKeyFromPem(pem: string) {
        return deps.pki.privateKeyFromPem!(pem);
      },
      publicKeyFromPem(pem: string) {
        return deps.pki.publicKeyFromPem!(pem);
      }
    });
  }

  static #attachPemMethods(pki: Partial<CertkitPki>, deps: PkiFacadeDeps): void {
    const asn1 = deps.asn1;

    pki.pemToDer = function (pem: string) {
      const msg = deps.pem.decode(pem)[0]!;
      if (msg.procType?.type === 'ENCRYPTED') {
        throw new Error('Could not convert PEM to DER; PEM is encrypted.');
      }
      return deps.util.createBuffer(msg.body);
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
      const obj = asn1.fromDer(msg.body);
      return pki.privateKeyFromAsn1!(obj);
    };

    pki.privateKeyToPem = function (key: RsaPrivateKey, maxline?: number) {
      const msg: PemMessage = {
        type: 'RSA PRIVATE KEY',
        procType: null,
        contentDomain: null,
        dekInfo: null,
        headers: [],
        body: asn1.toDer(pki.privateKeyToAsn1!(key)).getBytes()
      };
      return deps.pem.encode(msg, { maxline });
    };

    pki.privateKeyInfoToPem = function (keyInfo: Asn1Object, maxline?: number) {
      const msg: PemMessage = {
        type: 'PRIVATE KEY',
        procType: null,
        contentDomain: null,
        dekInfo: null,
        headers: [],
        body: asn1.toDer(keyInfo).getBytes()
      };
      return deps.pem.encode(msg, { maxline });
    };
  }
}

export default PkiFacade;

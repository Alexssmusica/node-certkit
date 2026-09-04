import { Pkcs7Asn1 } from '../domain/asn1/Pkcs7Asn1.js';
import { Mgf } from '../domain/pki/Mgf.js';
import { Mgf1 } from '../domain/pki/Mgf1.js';
import { OidRegistry } from '../domain/pki/OidRegistry.js';
import { Pkcs1Codec } from '../domain/pki/Pkcs1Codec.js';
import { PkiFacade, type PkiFacadeDeps } from '../domain/pki/PkiFacade.js';
import { PssScheme } from '../domain/pki/PssScheme.js';
import { RsaService } from '../domain/pki/RsaService.js';
import { NodeCryptoProvider } from '../infrastructure/crypto/NodeCryptoProvider.js';
import { NodePrimeGenerator } from '../infrastructure/prime/NodePrimeGenerator.js';
import type { CertkitPbeNamespace } from '../domain/pki/CertkitPkiTypes.js';
import type { CertkitMgfNamespace } from './CertkitTypes.js';
import type { MdRegistry } from '../domain/digest/DigestTypes.js';
import type { RsaServiceDeps } from '../domain/pki/RsaTypes.js';
import type { MutableCertkit, RsaService as RsaServiceType } from './CertkitAssemblyTypes.js';

function createPkiDeps(certkit: MutableCertkit, includePbe = false): PkiFacadeDeps {
  certkit.pki = certkit.pki || {};
  const deps: PkiFacadeDeps = {
    asn1: certkit.asn1!,
    oids: certkit.pki.oids || certkit.oids!,
    md: certkit.md! as MdRegistry,
    util: certkit.util!,
    pem: certkit.pem!,
    aes: certkit.aes!,
    des: certkit.des!,
    rc2: certkit.rc2!,
    random: certkit.random!,
    pbkdf2: certkit.pbkdf2!,
    pkcs5: certkit.pkcs5!,
    cipher: certkit.cipher!,
    hmac: certkit.hmac!,
    pss: certkit.pss!,
    mgf: certkit.mgf! as CertkitMgfNamespace,
    pkcs7: { asn1: certkit.pkcs7!.asn1! },
    pki: certkit.pki
  };
  if (includePbe) {
    return {
      ...deps,
      pbe: (certkit.pki.pbe || certkit.pbe!) as CertkitPbeNamespace
    } as PkiFacadeDeps & { pbe: CertkitPbeNamespace };
  }
  return deps;
}

export function assembleOids(certkit: MutableCertkit): void {
  certkit.pki = certkit.pki || {};
  const oids = OidRegistry.createCertkitNamespace();
  certkit.pki.oids = oids;
  certkit.oids = oids;
}

export function assemblePkcs7Asn1(certkit: MutableCertkit): void {
  const p7v = Pkcs7Asn1.createCertkitNamespace();
  certkit.pkcs7asn1 = certkit.pkcs7asn1 || p7v;
  Object.assign(certkit.pkcs7asn1, p7v);
  certkit.pkcs7 = certkit.pkcs7 || {};
  certkit.pkcs7.asn1 = certkit.pkcs7asn1;
}

export function assembleMgf1(certkit: MutableCertkit): void {
  certkit.mgf = certkit.mgf || {};
  const mgf1 = Mgf1.createCertkitNamespace();
  certkit.mgf.mgf1 = mgf1;
  certkit.mgf1 = certkit.mgf1 || mgf1;
  Object.assign(certkit.mgf1, mgf1);
}

export function assembleMgf(certkit: MutableCertkit): void {
  const mgf1 = certkit.mgf1 || Mgf1.createCertkitNamespace();
  const mgf = Mgf.createCertkitNamespace(mgf1);
  certkit.mgf = certkit.mgf || mgf;
  Object.assign(certkit.mgf, mgf);
  certkit.mgf.mgf1 = mgf1;
}

export function assemblePss(certkit: MutableCertkit): void {
  const getRandomBytes = (count: number) => certkit.random!.getBytesSync(count);
  const pss = PssScheme.createCertkitNamespace(getRandomBytes);
  certkit.pss = certkit.pss || pss;
  Object.assign(certkit.pss, pss);
}

export function assemblePkcs1(certkit: MutableCertkit): void {
  const getRandomBytes = (count: number) => certkit.random!.getBytesSync(count);
  const pkcs1 = Pkcs1Codec.createCertkitNamespace(getRandomBytes);
  certkit.pkcs1 = certkit.pkcs1 || pkcs1;
  Object.assign(certkit.pkcs1, pkcs1);
}

export function assembleRsa(certkit: MutableCertkit): RsaServiceType {
  certkit.pki = certkit.pki || {};

  const nativeCrypto = new NodeCryptoProvider();
  const rsaService = new RsaService({
    oids: certkit.pki.oids || {},
    asn1: certkit.asn1!,
    random: certkit.random! as RsaServiceDeps['random'],
    primeGenerator: new NodePrimeGenerator(certkit.random),
    nativeCrypto,
    usePureJavaScript: certkit.options?.usePureJavaScript ?? false
  });

  rsaService.attachToPki(certkit.pki);
  certkit.rsa = certkit.pki.rsa!;
  return rsaService;
}

export function assemblePbe(certkit: MutableCertkit): void {
  const deps = createPkiDeps(certkit, false);
  const pbe = PkiFacade.attachPbe(deps);
  certkit.pbe = certkit.pbe || pbe;
  Object.assign(certkit.pbe, pbe);
}

export function assembleX509(certkit: MutableCertkit): void {
  const deps = createPkiDeps(certkit, false);
  PkiFacade.attachX509(deps);
}

export function assemblePkcs12(certkit: MutableCertkit): void {
  const deps = createPkiDeps(certkit, true) as PkiFacadeDeps & { pbe: CertkitPbeNamespace };
  const p12 = PkiFacade.attachPkcs12(deps);
  certkit.pkcs12 = certkit.pkcs12 || p12;
  Object.assign(certkit.pkcs12, p12);
}

export function assemblePkiFinalize(certkit: MutableCertkit, rsaService: RsaServiceType): void {
  const deps = createPkiDeps(certkit, false);
  PkiFacade.finalize({ ...deps, rsaService });
}

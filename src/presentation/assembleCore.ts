import { Asn1Codec } from '../domain/asn1/Asn1Codec.js';
import { createBaseNNamespace } from '../domain/encoding/BaseNCodec.js';
import { BigInteger } from '../domain/math/BigInteger.js';
import { PemCodec } from '../domain/pki/PemCodec.js';
import { PrimeService } from '../domain/prime/PrimeService.js';
import { createUtilNamespace } from '../domain/util/UtilNamespace.js';
import { Fortuna } from '../infrastructure/prng/Fortuna.js';
import { FortunaRandom } from '../infrastructure/random/FortunaRandom.js';
import type { FortunaRandomDependencies } from '../infrastructure/random/RandomTypes.js';
import type { MutableCertkit } from './CertkitAssemblyTypes.js';

export function assembleUtil(certkit: MutableCertkit): void {
  const baseN = createBaseNNamespace();
  const namespace = createUtilNamespace(baseN);
  const util = (certkit.util = certkit.util || namespace);
  Object.assign(util, namespace);
}

export function assembleAsn1(certkit: MutableCertkit): void {
  const oids = certkit.pki?.oids;
  const asn1 = Asn1Codec.createCertkitNamespace(oids);
  certkit.asn1 = certkit.asn1 || asn1;
  Object.assign(certkit.asn1, asn1);
}

export function assemblePem(certkit: MutableCertkit): void {
  const pem = PemCodec.createCertkitNamespace();
  certkit.pem = certkit.pem || pem;
  Object.assign(certkit.pem, pem);
}

export function assembleJsbn(certkit: MutableCertkit): void {
  certkit.jsbn = certkit.jsbn || ({} as NonNullable<MutableCertkit['jsbn']>);
  certkit.jsbn.BigInteger = BigInteger;
}

export function assemblePrng(certkit: MutableCertkit): void {
  const prng = Fortuna.createCertkitNamespace();
  certkit.prng = certkit.prng || prng;
  Object.assign(certkit.prng, prng);
}

export function assembleRandom(certkit: MutableCertkit): void {
  const deps = {
    aes: certkit.aes!,
    sha256: certkit.md!.sha256!
  } as FortunaRandomDependencies;
  certkit.random = FortunaRandom.mergeInto(
    certkit.random as Parameters<typeof FortunaRandom.mergeInto>[0],
    deps
  ) as MutableCertkit['random'];
}

export function assemblePrime(certkit: MutableCertkit): void {
  if (!certkit.prime) {
    const getRandomBytes = (count: number) => certkit.random!.getBytesSync(count);
    certkit.prime = PrimeService.createCertkitNamespace(getRandomBytes);
  }
}

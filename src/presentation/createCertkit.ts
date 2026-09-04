/**
 * Composition root: assembles the flat certkit namespace from domain modules,
 * then wires cross-namespace aliases.
 */
import certkit from './certkitRoot.js';
import {
  assembleAes,
  assembleCipher,
  assembleCipherModes,
  assembleDes,
  assembleRc2
} from './assembleCipher.js';
import {
  assembleAsn1,
  assembleJsbn,
  assemblePem,
  assemblePrime,
  assemblePrng,
  assembleRandom,
  assembleUtil
} from './assembleCore.js';
import {
  assembleHmac,
  assembleMd,
  assembleMd5,
  assemblePbkdf2,
  assembleSha1,
  assembleSha256,
  assembleSha512
} from './assembleDigest.js';
import {
  assembleMgf,
  assembleMgf1,
  assembleOids,
  assemblePbe,
  assemblePkcs1,
  assemblePkcs12,
  assemblePkcs7Asn1,
  assemblePkiFinalize,
  assemblePss,
  assembleRsa,
  assembleX509
} from './assemblePki.js';
import type {AssembledCertkit} from './CertkitTypes.js';
import type {MutableCertkit} from './CertkitAssemblyTypes.js';
import {wireCrossNamespaceAliases, type CertkitNamespace} from './wireAliases.js';

export type Certkit = AssembledCertkit;

export function createCertkit(): Certkit {
  const f = certkit as MutableCertkit;

  assembleCipher(f);
  assembleCipherModes(f);
  assembleAes(f);
  assembleAsn1(f);
  assembleDes(f);
  assembleMd(f);
  assembleHmac(f);
  assembleMd5(f);
  assembleSha1(f);
  assembleSha256(f);
  assembleSha512(f);
  assembleMgf1(f);
  assembleMgf(f);
  assemblePbkdf2(f);
  assemblePem(f);
  assembleUtil(f);
  assemblePrng(f);
  assembleRandom(f);
  assemblePkcs1(f);
  assembleOids(f);
  assemblePkcs7Asn1(f);
  assembleRc2(f);
  assembleJsbn(f);
  assemblePrime(f);
  const rsaService = assembleRsa(f);
  assemblePbe(f);
  assemblePss(f);
  assembleX509(f);
  assemblePkcs12(f);
  assemblePkiFinalize(f, rsaService);

  wireCrossNamespaceAliases(f as unknown as CertkitNamespace);
  return certkit as AssembledCertkit;
}

export default createCertkit;

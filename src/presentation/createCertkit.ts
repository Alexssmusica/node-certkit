/**
 * Composition root: assembles the flat certkit namespace from domain modules,
 * then wires cross-namespace aliases.
 */
import certkit from './certkitRoot.js';
import { assembleAes, assembleCipher, assembleCipherModes, assembleDes, assembleRc2 } from './assembleCipher.js';
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
import type { AssembledCertkit } from './CertkitTypes.js';
import type { MutableCertkit } from './CertkitAssemblyTypes.js';
import { wireCrossNamespaceAliases } from './wireAliases.js';

export type Certkit = AssembledCertkit;

export function createCertkit(): Certkit {
  const mutableCertkit = certkit as MutableCertkit;

  assembleCipher(mutableCertkit);
  assembleCipherModes(mutableCertkit);
  assembleAes(mutableCertkit);
  assembleAsn1(mutableCertkit);
  assembleDes(mutableCertkit);
  assembleMd(mutableCertkit);
  assembleHmac(mutableCertkit);
  assembleMd5(mutableCertkit);
  assembleSha1(mutableCertkit);
  assembleSha256(mutableCertkit);
  assembleSha512(mutableCertkit);
  assembleMgf1(mutableCertkit);
  assembleMgf(mutableCertkit);
  assemblePbkdf2(mutableCertkit);
  assemblePem(mutableCertkit);
  assembleUtil(mutableCertkit);
  assemblePrng(mutableCertkit);
  assembleRandom(mutableCertkit);
  assemblePkcs1(mutableCertkit);
  assembleOids(mutableCertkit);
  assemblePkcs7Asn1(mutableCertkit);
  assembleRc2(mutableCertkit);
  assembleJsbn(mutableCertkit);
  assemblePrime(mutableCertkit);
  const rsaService = assembleRsa(mutableCertkit);
  assemblePbe(mutableCertkit);
  assemblePss(mutableCertkit);
  assembleX509(mutableCertkit);
  assemblePkcs12(mutableCertkit);
  assemblePkiFinalize(mutableCertkit, rsaService);

  wireCrossNamespaceAliases(mutableCertkit);
  return certkit as AssembledCertkit;
}

export default createCertkit;

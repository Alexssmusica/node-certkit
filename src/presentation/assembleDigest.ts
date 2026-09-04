import { DigestRegistry } from '../domain/digest/DigestRegistry.js';
import { Hmac, type DigestAlgorithmRegistry } from '../domain/digest/Hmac.js';
import { Md5 } from '../domain/digest/Md5.js';
import { Sha1 } from '../domain/digest/Sha1.js';
import { Sha256 } from '../domain/digest/Sha256.js';
import { Sha512 } from '../domain/digest/Sha512.js';
import { Pbkdf2 } from '../domain/pki/Pbkdf2.js';
import { NodeCryptoProvider } from '../infrastructure/crypto/NodeCryptoProvider.js';
import type { MutableCertkit } from './CertkitAssemblyTypes.js';

export function assembleMd(certkit: MutableCertkit): void {
  const md = DigestRegistry.createCertkitNamespace();
  certkit.md = certkit.md || md;
  if (!certkit.md.algorithms) {
    certkit.md.algorithms = md.algorithms;
  }
}

export function assembleMd5(certkit: MutableCertkit): void {
  const md5 = { create: Md5.create.bind(Md5) };
  certkit.md5 = certkit.md5 || md5;
  certkit.md!.md5 = certkit.md!.algorithms.md5 = md5;
}

export function assembleSha1(certkit: MutableCertkit): void {
  const sha1 = { create: Sha1.create.bind(Sha1) };
  certkit.sha1 = certkit.sha1 || sha1;
  certkit.md!.sha1 = certkit.md!.algorithms.sha1 = sha1;
}

export function assembleSha256(certkit: MutableCertkit): void {
  const sha256 = { create: Sha256.create.bind(Sha256) };
  certkit.sha256 = certkit.sha256 || sha256;
  certkit.md!.sha256 = certkit.md!.algorithms.sha256 = sha256;
}

export function assembleSha512(certkit: MutableCertkit): void {
  const sha512 = { create: Sha512.create.bind(Sha512) };
  certkit.sha512 = certkit.sha512 || sha512;
  certkit.md!.sha512 = certkit.md!.algorithms.sha512 = sha512;

  const sha384 =
    (certkit.sha384 =
    certkit.sha512.sha384 =
      certkit.sha512.sha384 || {
        create: () => Sha512.create('SHA-384')
      });
  certkit.md!.sha384 = certkit.md!.algorithms.sha384 = sha384;

  const sha512_256 = (certkit.sha512.sha256 = certkit.sha512.sha256 || {
    create: () => Sha512.create('SHA-512/256')
  });
  certkit.md!['sha512/256'] = certkit.md!.algorithms['sha512/256'] = sha512_256;

  const sha512_224 = (certkit.sha512.sha224 = certkit.sha512.sha224 || {
    create: () => Sha512.create('SHA-512/224')
  });
  certkit.md!['sha512/224'] = certkit.md!.algorithms['sha512/224'] = sha512_224;
}

export function assembleHmac(certkit: MutableCertkit): void {
  const hmac = {
    create: () => Hmac.create(certkit.md!.algorithms as DigestAlgorithmRegistry)
  };
  certkit.hmac = certkit.hmac || hmac;
}

export function assemblePbkdf2(certkit: MutableCertkit): void {
  const nativeCrypto = new NodeCryptoProvider();
  const pbkdf2 = Pbkdf2.createCertkitFunction({
    usePureJavaScript: certkit.options.usePureJavaScript,
    nativeCrypto,
    mdAlgorithms: certkit.md!.algorithms as DigestAlgorithmRegistry,
    hmacCreate: () => certkit.hmac!.create() as ReturnType<typeof Hmac.create>
  });

  certkit.pkcs5 = certkit.pkcs5 || {};
  certkit.pkcs5.pbkdf2 = pbkdf2;
  certkit.pbkdf2 = certkit.pbkdf2 || pbkdf2;
}

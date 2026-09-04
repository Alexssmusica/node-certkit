import { AesAlgorithm } from '../domain/cipher/AesAlgorithm.js';
import { CipherNamespace } from '../domain/cipher/CipherNamespace.js';
import { CipherModes } from '../domain/cipher/CipherModes.js';
import { DesAlgorithm } from '../domain/cipher/DesAlgorithm.js';
import { Rc2Cipher } from '../domain/cipher/Rc2Cipher.js';
import type { MutableCertkit } from './CertkitAssemblyTypes.js';

export function assembleCipher(certkit: MutableCertkit): void {
  const cipher = CipherNamespace.createCertkitNamespace();
  certkit.cipher = certkit.cipher || cipher;

  if (!certkit.cipher.algorithms) {
    certkit.cipher.algorithms = cipher.algorithms;
  }
  if (!certkit.cipher.modes) {
    certkit.cipher.modes = cipher.modes;
  }
  if (!certkit.cipher.BlockCipher) {
    certkit.cipher.BlockCipher = cipher.BlockCipher;
  }

  Object.assign(certkit.cipher, {
    createCipher: cipher.createCipher,
    createDecipher: cipher.createDecipher,
    registerAlgorithm: cipher.registerAlgorithm,
    getAlgorithm: cipher.getAlgorithm,
    BlockCipher: cipher.BlockCipher,
    algorithms: cipher.algorithms,
    modes: cipher.modes
  });
}

export function assembleCipherModes(certkit: MutableCertkit): void {
  certkit.cipher = certkit.cipher || {};
  const modes = CipherModes.createCertkitModes();
  certkit.cipher.modes = certkit.cipher.modes || modes;
  Object.assign(certkit.cipher.modes as object, modes);
}

export function assembleAes(certkit: MutableCertkit): void {
  const aes = AesAlgorithm.createCertkitNamespace();
  certkit.aes = certkit.aes || aes;
  Object.assign(certkit.aes, aes);
  if (certkit.cipher) {
    AesAlgorithm.registerAlgorithms(certkit.cipher as Parameters<typeof AesAlgorithm.registerAlgorithms>[0]);
  }
}

export function assembleDes(certkit: MutableCertkit): void {
  const des = DesAlgorithm.createCertkitNamespace();
  certkit.des = certkit.des || des;
  Object.assign(certkit.des, des);
  if (certkit.cipher) {
    DesAlgorithm.registerAlgorithms(certkit.cipher as Parameters<typeof DesAlgorithm.registerAlgorithms>[0]);
  }
}

export function assembleRc2(certkit: MutableCertkit): void {
  const rc2 = Rc2Cipher.createCertkitNamespace();
  certkit.rc2 = certkit.rc2 || rc2;
  Object.assign(certkit.rc2, rc2);
}

import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { MessageDigest, Mgf1Object } from './MgfTypes.js';

export class Mgf1 {
  static create(messageDigest: MessageDigest): Mgf1Object {
    return {
      generate(seed: string, maskLen: number): string {
        const maskBuffer = new ByteStringBuffer();
        const len = Math.ceil(maskLen / messageDigest.digestLength);
        for (let index = 0; index < len; index++) {
          const counterBuffer = new ByteStringBuffer();
          counterBuffer.putInt32(index);
          messageDigest.start();
          messageDigest.update(seed + counterBuffer.getBytes());
          maskBuffer.putBuffer(messageDigest.digest());
        }
        maskBuffer.truncate(maskBuffer.length() - maskLen);
        return maskBuffer.getBytes();
      }
    };
  }

  static createCertkitNamespace(): { create: typeof Mgf1.create } {
    return {
      create: Mgf1.create.bind(Mgf1)
    };
  }
}

export default Mgf1;

import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import type { MessageDigest, Mgf1Object } from './MgfTypes.js';

export class Mgf1 {
  static create(md: MessageDigest): Mgf1Object {
    return {
      generate(seed: string, maskLen: number): string {
        const t = new ByteStringBuffer();
        const len = Math.ceil(maskLen / md.digestLength);
        for (let i = 0; i < len; i++) {
          const c = new ByteStringBuffer();
          c.putInt32(i);
          md.start();
          md.update(seed + c.getBytes());
          t.putBuffer(md.digest());
        }
        t.truncate(t.length() - maskLen);
        return t.getBytes();
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

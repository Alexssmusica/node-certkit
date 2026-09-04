import type { NativeCryptoProvider } from '../ports/index.js';
import type { DigestAlgorithmRegistry, HmacContext } from '../digest/DigestTypes.js';
import type { Pbkdf2Callback, Pbkdf2Dependencies, Pbkdf2Function } from './Pbkdf2Types.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import { EnvInfo } from '../../infrastructure/env/EnvInfo.js';

type MessageDigest = {
  digestLength: number;
  start: () => void;
  update: (bytes: string) => void;
  digest: () => { getBytes: () => string };
};

export class Pbkdf2 {
  static createCertkitFunction(deps: Pbkdf2Dependencies): Pbkdf2Function {
    const nativeCrypto = deps.nativeCrypto;

    function pbkdf2(
      p: string,
      s: string,
      c: number,
      dkLen: number,
      md?: string | MessageDigest | null | Pbkdf2Callback,
      callback?: Pbkdf2Callback
    ): string | void {
      if (typeof md === 'function') {
        callback = md;
        md = null;
      }

      if (
        EnvInfo.isNodejs &&
        !deps.usePureJavaScript &&
        nativeCrypto.available &&
        nativeCrypto.pbkdf2Available &&
        (md === null || typeof md !== 'object') &&
        (nativeCrypto.pbkdf2SyncSupportsDigest || !md || md === 'sha256')
      ) {
        if (typeof md !== 'string') {
          md = 'sha256';
        }
        const digest = md as string;
        const pBuf = Buffer.from(p, 'binary');
        const sBuf = Buffer.from(s, 'binary');
        if (!callback) {
          if (!nativeCrypto.pbkdf2SyncSupportsDigest) {
            return nativeCrypto
              .pbkdf2Sync(pBuf.toString('binary'), sBuf.toString('binary'), c, dkLen)
              .toString('binary');
          }
          return nativeCrypto
            .pbkdf2Sync(pBuf.toString('binary'), sBuf.toString('binary'), c, dkLen, digest)
            .toString('binary');
        }
        const done: Pbkdf2Callback = callback;
        if (!nativeCrypto.pbkdf2SyncSupportsDigest) {
          nativeCrypto.pbkdf2!(pBuf.toString('binary'), sBuf.toString('binary'), c, dkLen, digest, function (err, key) {
            if (err) {
              return done(err);
            }
            done(null, key.toString('binary'));
          });
          return;
        }
        nativeCrypto.pbkdf2!(pBuf.toString('binary'), sBuf.toString('binary'), c, dkLen, digest, function (err, key) {
          if (err) {
            return done(err);
          }
          done(null, key.toString('binary'));
        });
        return;
      }

      if (typeof md === 'undefined' || md === null) {
        md = 'sha256';
      }
      if (typeof md === 'string') {
        if (!(md in deps.mdAlgorithms)) {
          throw new Error('Unknown hash algorithm: ' + md);
        }
        md = deps.mdAlgorithms[md]!.create() as unknown as MessageDigest;
      }

      const mdObj = md as MessageDigest;
      const hLen = mdObj.digestLength;

      if (!Number.isInteger(c) || c < 1) {
        const err = new Error('Invalid PBKDF2 iteration count.');
        if (callback) {
          return callback(err);
        }
        throw err;
      }

      if (!Number.isInteger(dkLen) || dkLen < 1) {
        const err = new Error('Invalid PBKDF2 derived key length.');
        if (callback) {
          return callback(err);
        }
        throw err;
      }

      if (dkLen > 0xffffffff * hLen) {
        const err = new Error('Derived key is too long.');
        if (callback) {
          return callback(err);
        }
        throw err;
      }

      const len = Math.ceil(dkLen / hLen);
      const r = dkLen - (len - 1) * hLen;

      const prf = deps.hmacCreate();
      prf.start(mdObj as unknown as Parameters<HmacContext['start']>[0], p);
      let dk = '';
      let xor: string;
      let u_c: string;
      let u_c1: string;

      if (!callback) {
        for (let i = 1; i <= len; ++i) {
          prf.start(null, null);
          prf.update(s);
          prf.update(UtilNamespace.int32ToBytes(i));
          xor = u_c1 = prf.digest().getBytes();

          for (let j = 2; j <= c; ++j) {
            prf.start(null, null);
            prf.update(u_c1);
            u_c = prf.digest().getBytes();
            xor = UtilNamespace.xorBytes(xor, u_c, hLen);
            u_c1 = u_c;
          }

          dk += i < len ? xor : xor.substr(0, r);
        }
        return dk;
      }

      let i = 1;
      let j: number;

      function outer(): void {
        if (i > len) {
          return callback!(null, dk);
        }

        prf.start(null, null);
        prf.update(s);
        prf.update(UtilNamespace.int32ToBytes(i));
        xor = u_c1 = prf.digest().getBytes();

        j = 2;
        inner();
      }

      function inner(): void {
        if (j <= c) {
          prf.start(null, null);
          prf.update(u_c1);
          u_c = prf.digest().getBytes();
          xor = UtilNamespace.xorBytes(xor, u_c, hLen);
          u_c1 = u_c;
          ++j;
          EnvInfo.setImmediate(inner);
          return;
        }

        dk += i < len ? xor : xor.substr(0, r);

        ++i;
        outer();
      }

      outer();
    }

    return pbkdf2 as Pbkdf2Function;
  }
}

export default Pbkdf2;

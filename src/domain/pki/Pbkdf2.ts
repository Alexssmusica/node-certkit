import type { HmacContext } from '../digest/DigestTypes.js';
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

    /** PBKDF2 key derivation (RFC 2898 section 5.2): `p` password, `s` salt, `c` iterations, `dk` derived key. */
    function pbkdf2(
      password: string,
      salt: string,
      iterationCount: number,
      dkLen: number,
      messageDigest?: string | MessageDigest | null | Pbkdf2Callback,
      callback?: Pbkdf2Callback
    ): string | void {
      if (typeof messageDigest === 'function') {
        callback = messageDigest;
        messageDigest = null;
      }

      if (
        EnvInfo.isNodejs &&
        !deps.usePureJavaScript &&
        nativeCrypto.available &&
        nativeCrypto.pbkdf2Available &&
        (messageDigest === null || typeof messageDigest !== 'object') &&
        (nativeCrypto.pbkdf2SyncSupportsDigest || !messageDigest || messageDigest === 'sha256')
      ) {
        if (typeof messageDigest !== 'string') {
          messageDigest = 'sha256';
        }
        const digest = messageDigest;
        const pBuf = Buffer.from(password, 'binary');
        const sBuf = Buffer.from(salt, 'binary');
        if (!callback) {
          if (!nativeCrypto.pbkdf2SyncSupportsDigest) {
            return nativeCrypto
              .pbkdf2Sync(pBuf.toString('binary'), sBuf.toString('binary'), iterationCount, dkLen)
              .toString('binary');
          }
          return nativeCrypto
            .pbkdf2Sync(pBuf.toString('binary'), sBuf.toString('binary'), iterationCount, dkLen, digest)
            .toString('binary');
        }
        const done: Pbkdf2Callback = callback;
        if (!nativeCrypto.pbkdf2SyncSupportsDigest) {
          nativeCrypto.pbkdf2!(
            pBuf.toString('binary'),
            sBuf.toString('binary'),
            iterationCount,
            dkLen,
            digest,
            function (err, key) {
              if (err) {
                return done(err);
              }
              done(null, key.toString('binary'));
            }
          );
          return;
        }
        nativeCrypto.pbkdf2!(
          pBuf.toString('binary'),
          sBuf.toString('binary'),
          iterationCount,
          dkLen,
          digest,
          function (err, key) {
            if (err) {
              return done(err);
            }
            done(null, key.toString('binary'));
          }
        );
        return;
      }

      if (typeof messageDigest === 'undefined' || messageDigest === null) {
        messageDigest = 'sha256';
      }
      if (typeof messageDigest === 'string') {
        if (!(messageDigest in deps.mdAlgorithms)) {
          throw new Error('Unknown hash algorithm: ' + messageDigest);
        }
        messageDigest = deps.mdAlgorithms[messageDigest].create() as unknown as MessageDigest;
      }

      const mdObj = messageDigest;
      const hLen = mdObj.digestLength;

      if (!Number.isInteger(iterationCount) || iterationCount < 1) {
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

      const blockCount = Math.ceil(dkLen / hLen);
      const finalBlockLength = dkLen - (blockCount - 1) * hLen;

      const prf = deps.hmacCreate();
      prf.start(mdObj as unknown as Parameters<HmacContext['start']>[0], password);
      let derivedKeyBytes = '';
      let xor: string;
      let currentU: string;
      let previousU: string;

      if (!callback) {
        for (let index = 1; index <= blockCount; ++index) {
          prf.start(null, null);
          prf.update(salt);
          prf.update(UtilNamespace.int32ToBytes(index));
          xor = previousU = prf.digest().getBytes();

          for (let innerIndex = 2; innerIndex <= iterationCount; ++innerIndex) {
            prf.start(null, null);
            prf.update(previousU);
            currentU = prf.digest().getBytes();
            xor = UtilNamespace.xorBytes(xor, currentU, hLen);
            previousU = currentU;
          }

          derivedKeyBytes += index < blockCount ? xor : xor.substr(0, finalBlockLength);
        }
        return derivedKeyBytes;
      }

      let index = 1;
      let innerIndex: number;

      function outer(): void {
        if (index > blockCount) {
          return callback!(null, derivedKeyBytes);
        }

        prf.start(null, null);
        prf.update(salt);
        prf.update(UtilNamespace.int32ToBytes(index));
        xor = previousU = prf.digest().getBytes();

        innerIndex = 2;
        inner();
      }

      function inner(): void {
        if (innerIndex <= iterationCount) {
          prf.start(null, null);
          prf.update(previousU);
          currentU = prf.digest().getBytes();
          xor = UtilNamespace.xorBytes(xor, currentU, hLen);
          previousU = currentU;
          ++innerIndex;
          EnvInfo.setImmediate(inner);
          return;
        }

        derivedKeyBytes += index < blockCount ? xor : xor.substr(0, finalBlockLength);

        ++index;
        outer();
      }

      outer();
    }

    return pbkdf2 as Pbkdf2Function;
  }
}

export default Pbkdf2;

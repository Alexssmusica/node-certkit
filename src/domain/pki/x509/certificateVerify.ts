import type {X509Runtime} from './X509Runtime.js';
import type {
  CertificateErrorMap,
  VerifyCallback,
  VerifyErrorObject,
  VerifyOptions,
  X509CaStore,
  X509Certificate
} from './X509Types.js';

type VerifyCtx = X509Runtime & {
  util: {isArray: (v: unknown) => boolean};
  pki: {
    certificateError: CertificateErrorMap;
    verifyCertificateChain: (
      caStore: X509CaStore,
      chain: X509Certificate[],
      options?: VerifyOptions | VerifyCallback
    ) => boolean;
  };
};

export class CertificateVerify {
  static attach(ctx: X509Runtime): void {
    const c = ctx as VerifyCtx;
    const pki = c.pki;

    pki.certificateError = {
      bad_certificate: 'certkit.pki.BadCertificate',
      unsupported_certificate: 'certkit.pki.UnsupportedCertificate',
      certificate_revoked: 'certkit.pki.CertificateRevoked',
      certificate_expired: 'certkit.pki.CertificateExpired',
      certificate_unknown: 'certkit.pki.CertificateUnknown',
      unknown_ca: 'certkit.pki.UnknownCertificateAuthority'
    };

    pki.verifyCertificateChain = function(
      caStore: X509CaStore,
      chain: X509Certificate[],
      options?: VerifyOptions | VerifyCallback
    ): boolean {
      if (typeof options === 'function') {
        options = {verify: options};
      }
      options = options || {};

      chain = chain.slice(0);
      const certs = chain.slice(0);

      let validityCheckDate: Date | null | undefined = options.validityCheckDate;
      if (typeof validityCheckDate === 'undefined') {
        validityCheckDate = new Date();
      }

      let first = true;
      let error: VerifyErrorObject | null = null;
      let depth = 0;
      do {
        const cert = chain.shift()!;
        let parent: X509Certificate | X509Certificate[] | null = null;
        let selfSigned = false;

        if (validityCheckDate) {
          if (validityCheckDate < cert.validity.notBefore ||
             validityCheckDate > cert.validity.notAfter) {
            error = {
              message: 'Certificate is not valid yet or has expired.',
              error: pki.certificateError.certificate_expired,
              notBefore: cert.validity.notBefore,
              notAfter: cert.validity.notAfter,
              now: validityCheckDate
            };
          }
        }

        if (error === null) {
          parent = chain[0] || caStore.getIssuer(cert);
          if (parent === null) {
            if (cert.isIssuer(cert)) {
              selfSigned = true;
              parent = cert;
            }
          }

          if (parent) {
            let parents: X509Certificate | X509Certificate[] = parent;
            if (!c.util.isArray(parents)) {
              parents = [parents];
            }

            let verified = false;
            const parentList = parents as X509Certificate[];
            while (!verified && parentList.length > 0) {
              parent = parentList.shift()!;
              try {
                verified = parent.verify(cert);
              } catch {
                // failure to verify, try next one
              }
            }

            if (!verified) {
              error = {
                message: 'Certificate signature is invalid.',
                error: pki.certificateError.bad_certificate
              };
            }
          }

          if (error === null && (!parent || selfSigned) &&
            !caStore.hasCertificate(cert)) {
            error = {
              message: 'Certificate is not trusted.',
              error: pki.certificateError.unknown_ca
            };
          }
        }

        if (error === null && parent && !cert.isIssuer(parent as X509Certificate)) {
          error = {
            message: 'Certificate issuer is invalid.',
            error: pki.certificateError.bad_certificate
          };
        }

        if (error === null) {
          const se: Record<string, boolean> = {
            keyUsage: true,
            basicConstraints: true
          };
          for (let i = 0; error === null && i < cert.extensions.length; ++i) {
            const ext = cert.extensions[i]!;
            if (ext.critical && !(ext.name! in se)) {
              error = {
                message:
                  'Certificate has an unsupported critical extension.',
                error: pki.certificateError.unsupported_certificate
              };
            }
          }
        }

        if (error === null &&
          (!first || (chain.length === 0 && (!parent || selfSigned)))) {
          const bcExt = cert.getExtension('basicConstraints');
          const keyUsageExt = cert.getExtension('keyUsage');
          if (keyUsageExt !== null) {
            if (!keyUsageExt.keyCertSign || bcExt === null) {
              error = {
                message:
                  'Certificate keyUsage or basicConstraints conflict ' +
                  'or indicate that the certificate is not a CA. ' +
                  'If the certificate is the only one in the chain or ' +
                  'isn\'t the first then the certificate must be a ' +
                  'valid CA.',
                error: pki.certificateError.bad_certificate
              };
            }
          }
          if (error === null && bcExt === null) {
            error = {
              message:
                'Certificate is missing basicConstraints extension and cannot ' +
                'be used as a CA.',
              error: pki.certificateError.bad_certificate
            };
          }
          if (error === null && bcExt !== null && !bcExt.cA) {
            error = {
              message:
                'Certificate basicConstraints indicates the certificate ' +
                'is not a CA.',
              error: pki.certificateError.bad_certificate
            };
          }
          if (error === null && keyUsageExt !== null &&
            bcExt !== null && 'pathLenConstraint' in bcExt) {
            const pathLen = depth - 1;
            if (pathLen > (bcExt.pathLenConstraint as number)) {
              error = {
                message:
                  'Certificate basicConstraints pathLenConstraint violated.',
                error: pki.certificateError.bad_certificate
              };
            }
          }
        }

        const vfd = (error === null) ? true : error.error;
        const ret = options.verify ? options.verify(vfd, depth, certs) : vfd;
        if (ret === true) {
          error = null;
        } else {
          if (vfd === true) {
            error = {
              message: 'The application rejected the certificate.',
              error: pki.certificateError.bad_certificate
            };
          }

          if (ret || ret === 0) {
            if (typeof ret === 'object' && !c.util.isArray(ret)) {
              if (ret.message) {
                error!.message = ret.message;
              }
              if (ret.error) {
                error!.error = ret.error as VerifyErrorObject['error'];
              }
            } else if (typeof ret === 'string') {
              error!.error = ret as VerifyErrorObject['error'];
            }
          }

          throw error;
        }

        first = false;
        ++depth;
      } while (chain.length > 0);

      return true;
    };
  }
}

export default CertificateVerify;

import type { X509Deps } from './X509Types.js';
import { X509Asn1 } from './X509Asn1.js';
import { X509Shared } from './x509Shared.js';
import { Certificate } from './Certificate.js';
import { CertificationRequest } from './CertificationRequest.js';
import { CaStore } from './CaStore.js';
import { CertificateVerify } from './certificateVerify.js';
import type { CertkitPki } from '../CertkitPkiTypes.js';

export type { X509Deps } from './X509Types.js';
export { Certificate } from './Certificate.js';
export { CertificationRequest } from './CertificationRequest.js';
export { CaStore } from './CaStore.js';

export class X509Service {
  static createCertkitNamespace(deps: X509Deps): CertkitPki {
    const ctx = deps;
    ctx.pki.oids = deps.oids;
    const validators = X509Asn1.create(ctx);
    const helpers = X509Shared.attach(ctx, validators);
    Certificate.attach(ctx, validators, helpers);
    CertificationRequest.attach(ctx, validators, helpers);
    CaStore.attach(ctx, helpers);
    CertificateVerify.attach(ctx);
    return ctx.pki as CertkitPki;
  }
}

export default X509Service;

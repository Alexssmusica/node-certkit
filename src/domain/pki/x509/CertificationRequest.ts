import type { Asn1Object } from '../../asn1/Asn1Types.js';
import type { X509Validators } from './X509Asn1.js';
import type { X509Runtime } from './X509Runtime.js';
import type {
  DerError,
  DnAttribute,
  DnAttributeInput,
  MessageDigest,
  PrivateKey,
  X509AttachCtx,
  X509CertificationRequest,
  X509Helpers
} from './X509Types.js';

export class CertificationRequest {
  static attach(ctx: X509Runtime, validators: X509Validators, h: X509Helpers): void {
    const c = ctx as X509AttachCtx;
    const asn1 = c.asn1;
    const oids = c.oids;
    const pki = c.pki;
    const {
      getAttribute,
      readSignatureParameters,
      createSignatureDigest,
      verifySignature,
      dnToAsn1,
      fillMissingFields,
      CRIAttributesToAsn1
    } = h;

    pki.certificationRequestFromAsn1 = function (obj: Asn1Object, computeHash?: boolean) {
      const capture: Record<string, unknown> = {};
      const errors: string[] = [];
      if (!asn1.validate(obj, validators.certificationRequestValidator, capture, errors)) {
        const error = new Error(
          'Cannot read PKCS#10 certificate request. ' + 'ASN.1 object is not a PKCS#10 CertificationRequest.'
        ) as DerError;
        error.errors = errors;
        throw error;
      }

      const oid = asn1.derToOid(capture.publicKeyOid as string);
      if (oid !== oids.rsaEncryption) {
        throw new Error('Cannot read public key. OID is not RSA.');
      }

      const csr = pki.createCertificationRequest();
      csr.version = capture.csrVersion ? (capture.csrVersion as string).charCodeAt(0) : 0;
      csr.signatureOid = asn1.derToOid(capture.csrSignatureOid as string);
      csr.signatureParameters = readSignatureParameters(
        csr.signatureOid,
        capture.csrSignatureParams as Asn1Object,
        true
      );
      csr.siginfo.algorithmOid = asn1.derToOid(capture.csrSignatureOid as string);
      csr.siginfo.parameters = readSignatureParameters(
        csr.siginfo.algorithmOid,
        capture.csrSignatureParams as Asn1Object,
        false
      );
      csr.signature = capture.csrSignature as string;

      csr.certificationRequestInfo = capture.certificationRequestInfo as Asn1Object;

      if (computeHash) {
        csr.md = createSignatureDigest({
          signatureOid: csr.signatureOid!,
          type: 'certification request'
        });

        const bytes = asn1.toDer(csr.certificationRequestInfo);
        csr.md.update(bytes.getBytes());
      }

      const smd = c.md.sha1.create();
      csr.subject.getField = function (sn: any) {
        return getAttribute(csr.subject, sn);
      };
      csr.subject.addField = function (attr: any) {
        fillMissingFields([attr]);
        csr.subject.attributes.push(attr);
      };
      csr.subject.attributes = pki.RDNAttributesAsArray(capture.certificationRequestInfoSubject, smd);
      csr.subject.hash = smd.digest().toHex();

      csr.publicKey = pki.publicKeyFromAsn1(capture.subjectPublicKeyInfo);

      csr.getAttribute = function (sn: any) {
        return getAttribute(csr, sn);
      };
      csr.addAttribute = function (attr: any) {
        fillMissingFields([attr]);
        csr.attributes.push(attr);
      };
      csr.attributes = pki.CRIAttributesAsArray(capture.certificationRequestInfoAttributes || []);

      return csr;
    };

    pki.createCertificationRequest = function (): X509CertificationRequest {
      const csr = {} as X509CertificationRequest;
      csr.version = 0x00;
      csr.signatureOid = null;
      csr.signature = null;
      csr.siginfo = { algorithmOid: null };

      csr.subject = {} as X509CertificationRequest['subject'];
      csr.subject.getField = function (sn: any) {
        return getAttribute(csr.subject, sn);
      };
      csr.subject.addField = function (attr: any) {
        fillMissingFields([attr]);
        csr.subject.attributes.push(attr);
      };
      csr.subject.attributes = [];
      csr.subject.hash = null;

      csr.publicKey = null;
      csr.attributes = [];
      csr.getAttribute = function (sn: any) {
        return getAttribute(csr, sn);
      };
      csr.addAttribute = function (attr: any) {
        fillMissingFields([attr]);
        csr.attributes.push(attr);
      };
      csr.md = null;

      csr.setSubject = function (attrs: DnAttributeInput[]) {
        fillMissingFields(attrs);
        csr.subject.attributes = attrs as DnAttribute[];
        csr.subject.hash = null;
      };

      csr.setAttributes = function (attrs: DnAttributeInput[]) {
        fillMissingFields(attrs);
        csr.attributes = attrs as DnAttribute[];
      };

      csr.sign = function (key: PrivateKey, md?: MessageDigest) {
        csr.md = md || c.md.sha1.create();
        const algorithmOid = oids[csr.md.algorithm + 'WithRSAEncryption'];
        if (!algorithmOid) {
          const error = new Error(
            'Could not compute certification request digest. ' + 'Unknown message digest algorithm OID.'
          ) as DerError;
          error.algorithm = csr.md.algorithm;
          throw error;
        }
        csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid;

        csr.certificationRequestInfo = pki.getCertificationRequestInfo(csr);
        const bytes = asn1.toDer(csr.certificationRequestInfo);

        csr.md.update(bytes.getBytes());
        csr.signature = key.sign(csr.md);
      };

      csr.verify = function () {
        let rval = false;

        let md = csr.md;
        if (md === null) {
          md = createSignatureDigest({
            signatureOid: csr.signatureOid!,
            type: 'certification request'
          });

          const cri = csr.certificationRequestInfo || pki.getCertificationRequestInfo(csr);
          const bytes = asn1.toDer(cri);
          md.update(bytes.getBytes());
        }

        if (md !== null) {
          rval = verifySignature({
            certificate: csr,
            md: md,
            signature: csr.signature
          });
        }

        return rval;
      };

      return csr;
    };

    pki.getCertificationRequestInfo = function (csr: X509CertificationRequest): Asn1Object {
      const cri = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(csr.version).getBytes()),
        dnToAsn1(csr.subject),
        pki.publicKeyToAsn1(csr.publicKey),
        CRIAttributesToAsn1(csr)
      ]);

      return cri;
    };
  }
}

export default CertificationRequest;

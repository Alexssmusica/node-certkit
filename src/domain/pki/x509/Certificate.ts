import type { X509Validators } from './X509Types.js';
import type { X509Runtime } from './X509Runtime.js';
import { certificateExtensionFromAsn1, certificateExtensionsFromAsn1 } from './CertificateExtensions.js';
import type { DerError, X509AttachCtx, X509Helpers } from './X509Types.js';

export class Certificate {
  static attach(runtime: X509Runtime, validators: X509Validators, h: X509Helpers): void {
    const c = runtime as X509AttachCtx;
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
      fillMissingExtensionFields,
      signatureParametersToAsn1,
      dateToAsn1
    } = h;

    pki.certificateFromPem = function (pem: any, computeHash: any, strict: any) {
      const msg = c.pem.decode(pem)[0]!;

      if (msg.type !== 'CERTIFICATE' && msg.type !== 'X509 CERTIFICATE' && msg.type !== 'TRUSTED CERTIFICATE') {
        const error = new Error(
          'Could not convert certificate from PEM; PEM header type ' +
            'is not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".'
        ) as DerError;
        error.headerType = msg.type;
        throw error;
      }
      if (msg.procType && msg.procType.type === 'ENCRYPTED') {
        throw new Error('Could not convert certificate from PEM; PEM is encrypted.');
      }

      const obj = asn1.fromDer(msg.body, strict);

      return pki.certificateFromAsn1(obj, computeHash);
    };

    /**
     * Converts an X.509 certificate to PEM format.
     *
     * @param cert the certificate.
     * @param maxline the maximum characters per line, defaults to 64.
     *
     * @return the PEM-formatted certificate.
     */
    pki.certificateToPem = function (cert: any, maxline: any) {
      const msg = {
        type: 'CERTIFICATE',
        body: asn1.toDer(pki.certificateToAsn1(cert)).getBytes()
      };
      return c.pem.encode(msg, { maxline: maxline });
    };

    /**
     * Converts an RSA public key from PEM format.
     *
     * @param pem the PEM-formatted public key.
     *
     * @return the public key.
     */
    pki.publicKeyFromPem = function (pem: any) {
      const msg = c.pem.decode(pem)[0];

      if (msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
        const error = new Error(
          'Could not convert public key from PEM; PEM header ' + 'type is not "PUBLIC KEY" or "RSA PUBLIC KEY".'
        ) as DerError;
        error.headerType = msg.type;
        throw error;
      }
      if (msg.procType && msg.procType.type === 'ENCRYPTED') {
        throw new Error('Could not convert public key from PEM; PEM is encrypted.');
      }

      const obj = asn1.fromDer(msg.body);

      return pki.publicKeyFromAsn1(obj);
    };

    /**
     * Converts an RSA public key to PEM format (using a SubjectPublicKeyInfo).
     *
     * @param key the public key.
     * @param maxline the maximum characters per line, defaults to 64.
     *
     * @return the PEM-formatted public key.
     */
    pki.publicKeyToPem = function (key: any, maxline: any) {
      const msg = {
        type: 'PUBLIC KEY',
        body: asn1.toDer(pki.publicKeyToAsn1(key)).getBytes()
      };
      return c.pem.encode(msg, { maxline: maxline });
    };

    /**
     * Converts an RSA public key to PEM format (using an RSAPublicKey).
     *
     * @param key the public key.
     * @param maxline the maximum characters per line, defaults to 64.
     *
     * @return the PEM-formatted public key.
     */
    pki.publicKeyToRSAPublicKeyPem = function (key: any, maxline: any) {
      const msg = {
        type: 'RSA PUBLIC KEY',
        body: asn1.toDer(pki.publicKeyToRSAPublicKey(key)).getBytes()
      };
      return c.pem.encode(msg, { maxline: maxline });
    };

    /**
     * Gets a fingerprint for the given public key.
     *
     * @param options the options to use.
     *          [md] the message digest object to use (defaults to c.md.sha1).
     *          [type] the type of fingerprint, such as 'RSAPublicKey',
     *            'SubjectPublicKeyInfo' (defaults to 'RSAPublicKey').
     *          [encoding] an alternative output encoding, such as 'hex'
     *            (defaults to none, outputs a byte buffer).
     *          [delimiter] the delimiter to use between bytes for 'hex' encoded
     *            output, eg: ':' (defaults to none).
     *
     * @return the fingerprint as a byte buffer or other encoding based on options.
     */
    pki.getPublicKeyFingerprint = function (key: any, options: any) {
      options = options || {};
      const md = options.md || c.md.sha1.create();
      const type = options.type || 'RSAPublicKey';

      let bytes;
      switch (type) {
        case 'RSAPublicKey':
          bytes = asn1.toDer(pki.publicKeyToRSAPublicKey(key)).getBytes();
          break;
        case 'SubjectPublicKeyInfo':
          bytes = asn1.toDer(pki.publicKeyToAsn1(key)).getBytes();
          break;
        default:
          throw new Error('Unknown fingerprint type "' + options.type + '".');
      }

      // hash public key bytes
      md.start();
      md.update(bytes);
      const digest = md.digest();
      if (options.encoding === 'hex') {
        const hex = digest.toHex();
        if (options.delimiter) {
          return hex.match(/.{2}/g).join(options.delimiter);
        }
        return hex;
      } else if (options.encoding === 'binary') {
        return digest.getBytes();
      } else if (options.encoding) {
        throw new Error('Unknown encoding "' + options.encoding + '".');
      }
      return digest;
    };

    /**
     * Converts a PKCS#10 certification request (CSR) from PEM format.
     *
     * Note: If the certification request is to be verified then compute hash
     * should be set to true. This will scan the CertificationRequestInfo part of
     * the ASN.1 object while it is converted so it doesn't need to be converted
     * back to ASN.1-DER-encoding later.
     *
     * @param pem the PEM-formatted certificate.
     * @param computeHash true to compute the hash for verification.
     * @param strict true to be strict when checking ASN.1 value lengths, false to
     *          allow truncated values (default: true).
     *
     * @return the certification request (CSR).
     */
    pki.certificationRequestFromPem = function (pem: any, computeHash: any, strict: any) {
      const msg = c.pem.decode(pem)[0];

      if (msg.type !== 'CERTIFICATE REQUEST') {
        const error = new Error(
          'Could not convert certification request from PEM; ' + 'PEM header type is not "CERTIFICATE REQUEST".'
        ) as DerError;
        error.headerType = msg.type;
        throw error;
      }
      if (msg.procType && msg.procType.type === 'ENCRYPTED') {
        throw new Error('Could not convert certification request from PEM; ' + 'PEM is encrypted.');
      }

      const obj = asn1.fromDer(msg.body, strict);

      return pki.certificationRequestFromAsn1(obj, computeHash);
    };

    /**
     * Converts a PKCS#10 certification request (CSR) to PEM format.
     *
     * @param csr the certification request.
     * @param maxline the maximum characters per line, defaults to 64.
     *
     * @return the PEM-formatted certification request.
     */
    pki.certificationRequestToPem = function (csr: any, maxline: any) {
      const msg = {
        type: 'CERTIFICATE REQUEST',
        body: asn1.toDer(pki.certificationRequestToAsn1(csr)).getBytes()
      };
      return c.pem.encode(msg, { maxline: maxline });
    };

    /**
     * Creates an empty X.509v3 RSA certificate.
     *
     * @return the certificate.
     */

    pki.createCertificate = function () {
      const cert: any = {} as any;
      cert.version = 0x02;
      cert.serialNumber = '00';
      cert.signatureOid = null;
      cert.signature = null;
      cert.siginfo = {} as any;
      cert.siginfo.algorithmOid = null;
      cert.validity = {} as any;
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();

      cert.issuer = {} as any;
      cert.issuer.getField = function (sn: any) {
        return getAttribute(cert.issuer, sn);
      };
      cert.issuer.addField = function (attr: any) {
        fillMissingFields([attr]);
        cert.issuer.attributes.push(attr);
      };
      cert.issuer.attributes = [];
      cert.issuer.hash = null;

      cert.subject = {} as any;
      cert.subject.getField = function (sn: any) {
        return getAttribute(cert.subject, sn);
      };
      cert.subject.addField = function (attr: any) {
        fillMissingFields([attr]);
        cert.subject.attributes.push(attr);
      };
      cert.subject.attributes = [];
      cert.subject.hash = null;

      cert.extensions = [];
      cert.publicKey = null;
      cert.md = null;

      /**
       * Sets the subject of this certificate.
       *
       * @param attrs the array of subject attributes to use.
       * @param uniqueId an optional a unique ID to use.
       */
      cert.setSubject = function (attrs: any, uniqueId: any) {
        // set new attributes, clear hash
        fillMissingFields(attrs);
        cert.subject.attributes = attrs;
        delete cert.subject.uniqueId;
        if (uniqueId) {
          // TODO: support arbitrary bit length ids
          cert.subject.uniqueId = uniqueId;
        }
        cert.subject.hash = null;
      };

      /**
       * Sets the issuer of this certificate.
       *
       * @param attrs the array of issuer attributes to use.
       * @param uniqueId an optional a unique ID to use.
       */
      cert.setIssuer = function (attrs: any, uniqueId: any) {
        // set new attributes, clear hash
        fillMissingFields(attrs);
        cert.issuer.attributes = attrs;
        delete cert.issuer.uniqueId;
        if (uniqueId) {
          // TODO: support arbitrary bit length ids
          cert.issuer.uniqueId = uniqueId;
        }
        cert.issuer.hash = null;
      };

      /**
       * Sets the extensions of this certificate.
       *
       * @param exts the array of extensions to use.
       */
      cert.setExtensions = function (exts: any) {
        for (let i = 0; i < exts.length; ++i) {
          fillMissingExtensionFields(exts[i], { cert: cert });
        }
        // set new extensions
        cert.extensions = exts;
      };

      /**
       * Gets an extension by its name or id.
       *
       * @param options the name to use or an object with:
       *          name the name to use.
       *          id the id to use.
       *
       * @return the extension or null if not found.
       */
      cert.getExtension = function (options: any) {
        if (typeof options === 'string') {
          options = { name: options };
        }

        let rval = null;
        let ext;
        for (let i = 0; rval === null && i < cert.extensions.length; ++i) {
          ext = cert.extensions[i];
          if (options.id && ext.id === options.id) {
            rval = ext;
          } else if (options.name && ext.name === options.name) {
            rval = ext;
          }
        }
        return rval;
      };

      /**
       * Signs this certificate using the given private key.
       *
       * @param key the private key to sign with.
       * @param md the message digest object to use (defaults to c.md.sha1).
       */
      cert.sign = function (key: any, md: any) {
        // TODO: get signature OID from private key
        cert.md = md || c.md.sha1.create();
        const algorithmOid = oids[cert.md.algorithm + 'WithRSAEncryption'];
        if (!algorithmOid) {
          const error = new Error(
            'Could not compute certificate digest. ' + 'Unknown message digest algorithm OID.'
          ) as DerError;
          error.algorithm = cert.md.algorithm;
          throw error;
        }
        cert.signatureOid = cert.siginfo.algorithmOid = algorithmOid;

        // get TBSCertificate, convert to DER
        cert.tbsCertificate = pki.getTBSCertificate(cert);
        const bytes = asn1.toDer(cert.tbsCertificate);

        // digest and sign
        cert.md.update(bytes.getBytes());
        cert.signature = key.sign(cert.md);
      };

      /**
       * Attempts verify the signature on the passed certificate using this
       * certificate's public key.
       *
       * @param child the certificate to verify.
       *
       * @return true if verified, false if not.
       */
      cert.verify = function (child: any) {
        let rval = false;

        if (!cert.issued(child)) {
          const issuer = child.issuer;
          const subject = cert.subject;
          const error = new Error(
            'The parent certificate did not issue the given child ' +
              "certificate; the child certificate's issuer does not match the " +
              "parent's subject."
          ) as DerError;
          error.expectedIssuer = subject.attributes;
          error.actualIssuer = issuer.attributes;
          throw error;
        }

        let md = child.md;
        if (md === null) {
          // create digest for OID signature types
          md = createSignatureDigest({
            signatureOid: child.signatureOid,
            type: 'certificate'
          });

          // produce DER formatted TBSCertificate and digest it
          const tbsCertificate = child.tbsCertificate || pki.getTBSCertificate(child);
          const bytes = asn1.toDer(tbsCertificate);
          md.update(bytes.getBytes());
        }

        if (md !== null) {
          rval = verifySignature({
            certificate: cert,
            subject: child,
            md: md,
            signature: child.signature
          });
        }

        return rval;
      };

      /**
       * Returns true if this certificate's issuer matches the passed
       * certificate's subject. Note that no signature check is performed.
       *
       * @param parent the certificate to check.
       *
       * @return true if this certificate's issuer matches the passed certificate's
       *         subject.
       */
      cert.isIssuer = function (parent: any) {
        let rval = false;

        const i = cert.issuer;
        const s = parent.subject;

        // compare hashes if present
        if (i.hash && s.hash) {
          rval = i.hash === s.hash;
        } else if (i.attributes.length === s.attributes.length) {
          // all attributes are the same so issuer matches subject
          rval = true;
          let iattr, sattr;
          for (let n = 0; rval && n < i.attributes.length; ++n) {
            iattr = i.attributes[n];
            sattr = s.attributes[n];
            if (iattr.type !== sattr.type || iattr.value !== sattr.value) {
              // attribute mismatch
              rval = false;
            }
          }
        }

        return rval;
      };

      /**
       * Returns true if this certificate's subject matches the issuer of the
       * given certificate). Note that not signature check is performed.
       *
       * @param child the certificate to check.
       *
       * @return true if this certificate's subject matches the passed
       *         certificate's issuer.
       */
      cert.issued = function (child: any) {
        return child.isIssuer(cert);
      };

      /**
       * Generates the subjectKeyIdentifier for this certificate as byte buffer.
       *
       * @return the subjectKeyIdentifier for this certificate as byte buffer.
       */
      cert.generateSubjectKeyIdentifier = function () {
        /* See: 4.2.1.2 section of the the RFC3280, keyIdentifier is either:
    
          (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
            value of the BIT STRING subjectPublicKey (excluding the tag,
            length, and number of unused bits).
    
          (2) The keyIdentifier is composed of a four bit type field with
            the value 0100 followed by the least significant 60 bits of the
            SHA-1 hash of the value of the BIT STRING subjectPublicKey
            (excluding the tag, length, and number of unused bit string bits).
        */

        // skipping the tag, length, and number of unused bits is the same
        // as just using the RSAPublicKey (for RSA keys, which are the
        // only ones supported)
        return pki.getPublicKeyFingerprint(cert.publicKey, { type: 'RSAPublicKey' });
      };

      /**
       * Verifies the subjectKeyIdentifier extension value for this certificate
       * against its public key. If no extension is found, false will be
       * returned.
       *
       * @return true if verified, false if not.
       */
      cert.verifySubjectKeyIdentifier = function () {
        const oid = oids['subjectKeyIdentifier'];
        for (let i = 0; i < cert.extensions.length; ++i) {
          const ext = cert.extensions[i];
          if (ext.id === oid) {
            const ski = cert.generateSubjectKeyIdentifier().getBytes();
            return c.util.hexToBytes(ext.subjectKeyIdentifier) === ski;
          }
        }
        return false;
      };

      return cert;
    };

    /**
     * Converts an X.509v3 RSA certificate from an ASN.1 object.
     *
     * Note: If the certificate is to be verified then compute hash should
     * be set to true. There is currently no implementation for converting
     * a certificate back to ASN.1 so the TBSCertificate part of the ASN.1
     * object needs to be scanned before the cert object is created.
     *
     * @param obj the asn1 representation of an X.509v3 RSA certificate.
     * @param computeHash true to compute the hash for verification.
     *
     * @return the certificate.
     */

    pki.certificateFromAsn1 = function (obj: any, computeHash: any) {
      // validate certificate and capture data
      const capture: any = {} as any;
      const errors: string[] = [];
      if (!asn1.validate(obj, validators.x509CertificateValidator, capture, errors)) {
        const error = new Error(
          'Cannot read X.509 certificate. ' + 'ASN.1 object is not an X509v3 Certificate.'
        ) as DerError;
        error.errors = errors;
        throw error;
      }

      // get oid
      const oid = asn1.derToOid(capture.publicKeyOid);
      if (oid !== oids.rsaEncryption) {
        throw new Error('Cannot read public key. OID is not RSA.');
      }

      // create certificate
      const cert = pki.createCertificate();
      cert.version = capture.certVersion ? capture.certVersion.charCodeAt(0) : 0;
      const serial = c.util.createBuffer(capture.certSerialNumber);
      cert.serialNumber = serial.toHex();
      cert.signatureOid = asn1.derToOid(capture.certSignatureOid);
      cert.signatureParameters = readSignatureParameters(cert.signatureOid, capture.certSignatureParams, true);
      cert.siginfo.algorithmOid = asn1.derToOid(capture.certinfoSignatureOid);
      cert.siginfo.parameters = readSignatureParameters(
        cert.siginfo.algorithmOid,
        capture.certinfoSignatureParams,
        false
      );
      if (cert.signatureOid !== cert.siginfo.algorithmOid) {
        throw new Error('Certificate signature algorithm mismatch between TBSCertificate and outer signature.');
      }
      cert.signature = capture.certSignature;

      const validity = [];
      if (capture.certValidity1UTCTime !== undefined) {
        validity.push(asn1.utcTimeToDate(capture.certValidity1UTCTime));
      }
      if (capture.certValidity2GeneralizedTime !== undefined) {
        validity.push(asn1.generalizedTimeToDate(capture.certValidity2GeneralizedTime));
      }
      if (capture.certValidity3UTCTime !== undefined) {
        validity.push(asn1.utcTimeToDate(capture.certValidity3UTCTime));
      }
      if (capture.certValidity4GeneralizedTime !== undefined) {
        validity.push(asn1.generalizedTimeToDate(capture.certValidity4GeneralizedTime));
      }
      if (validity.length > 2) {
        throw new Error(
          'Cannot read notBefore/notAfter validity times; more ' + 'than two times were provided in the certificate.'
        );
      }
      if (validity.length < 2) {
        throw new Error(
          'Cannot read notBefore/notAfter validity times; they ' +
            'were not provided as either UTCTime or GeneralizedTime.'
        );
      }
      cert.validity.notBefore = validity[0];
      cert.validity.notAfter = validity[1];

      // keep TBSCertificate to preserve signature when exporting
      cert.tbsCertificate = capture.tbsCertificate;

      if (computeHash) {
        // create digest for OID signature type
        cert.md = createSignatureDigest({
          signatureOid: cert.signatureOid,
          type: 'certificate'
        });

        // produce DER formatted TBSCertificate and digest it
        const bytes = asn1.toDer(cert.tbsCertificate);
        cert.md.update(bytes.getBytes());
      }

      // handle issuer, build issuer message digest
      const imd = c.md.sha1.create();
      const ibytes = asn1.toDer(capture.certIssuer);
      imd.update(ibytes.getBytes());
      cert.issuer.getField = function (sn: any) {
        return getAttribute(cert.issuer, sn);
      };
      cert.issuer.addField = function (attr: any) {
        fillMissingFields([attr]);
        cert.issuer.attributes.push(attr);
      };
      cert.issuer.attributes = pki.RDNAttributesAsArray(capture.certIssuer);
      if (capture.certIssuerUniqueId) {
        cert.issuer.uniqueId = capture.certIssuerUniqueId;
      }
      cert.issuer.hash = imd.digest().toHex();

      // handle subject, build subject message digest
      const smd = c.md.sha1.create();
      const sbytes = asn1.toDer(capture.certSubject);
      smd.update(sbytes.getBytes());
      cert.subject.getField = function (sn: any) {
        return getAttribute(cert.subject, sn);
      };
      cert.subject.addField = function (attr: any) {
        fillMissingFields([attr]);
        cert.subject.attributes.push(attr);
      };
      cert.subject.attributes = pki.RDNAttributesAsArray(capture.certSubject);
      if (capture.certSubjectUniqueId) {
        cert.subject.uniqueId = capture.certSubjectUniqueId;
      }
      cert.subject.hash = smd.digest().toHex();

      // handle extensions
      if (capture.certExtensions) {
        cert.extensions = pki.certificateExtensionsFromAsn1(capture.certExtensions);
      } else {
        cert.extensions = [];
      }

      // convert RSA public key from ASN.1
      cert.publicKey = pki.publicKeyFromAsn1(capture.subjectPublicKeyInfo);

      return cert;
    };

    const extensionOptions = { ctx: c };

    pki.certificateExtensionsFromAsn1 = function (exts: any) {
      return certificateExtensionsFromAsn1(exts, extensionOptions);
    };

    pki.certificateExtensionFromAsn1 = function (ext: any) {
      return certificateExtensionFromAsn1(ext, extensionOptions);
    };

    /**
     * Converts a PKCS#10 certification request (CSR) from an ASN.1 object.
     *
     * Note: If the certification request is to be verified then compute hash
     * should be set to true. There is currently no implementation for converting
     * a certificate back to ASN.1 so the CertificationRequestInfo part of the
     * ASN.1 object needs to be scanned before the csr object is created.
     *
     * @param obj the asn1 representation of a PKCS#10 certification request (CSR).
     * @param computeHash true to compute the hash for verification.
     *
     * @return the certification request (CSR).
     */

    pki.getTBSCertificate = function (cert: any) {
      // TBSCertificate
      const notBefore = dateToAsn1(cert.validity.notBefore);
      const notAfter = dateToAsn1(cert.validity.notAfter);
      const tbs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // version
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          // integer
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(cert.version).getBytes())
        ]),
        // serialNumber
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, c.util.hexToBytes(cert.serialNumber)),
        // signature
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          // algorithm
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(cert.siginfo.algorithmOid).getBytes()),
          // parameters
          signatureParametersToAsn1(cert.siginfo.algorithmOid, cert.siginfo.parameters)
        ]),
        // issuer
        dnToAsn1(cert.issuer),
        // validity
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [notBefore, notAfter]),
        // subject
        dnToAsn1(cert.subject),
        // SubjectPublicKeyInfo
        pki.publicKeyToAsn1(cert.publicKey)
      ]);

      if (cert.issuer.uniqueId) {
        // issuerUniqueID (optional)
        tbs.value.push(
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
            asn1.create(
              asn1.Class.UNIVERSAL,
              asn1.Type.BITSTRING,
              false,
              // TODO: support arbitrary bit length ids
              String.fromCharCode(0x00) + cert.issuer.uniqueId
            )
          ])
        );
      }
      if (cert.subject.uniqueId) {
        // subjectUniqueID (optional)
        tbs.value.push(
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
            asn1.create(
              asn1.Class.UNIVERSAL,
              asn1.Type.BITSTRING,
              false,
              // TODO: support arbitrary bit length ids
              String.fromCharCode(0x00) + cert.subject.uniqueId
            )
          ])
        );
      }

      if (cert.extensions.length > 0) {
        // extensions (optional)
        tbs.value.push(pki.certificateExtensionsToAsn1(cert.extensions));
      }

      return tbs;
    };

    /**
     * Converts a DistinguishedName (subject or issuer) to an ASN.1 object.
     *
     * @param dn the DistinguishedName.
     *
     * @return the asn1 representation of a DistinguishedName.
     */
    pki.distinguishedNameToAsn1 = function (dn: any) {
      return dnToAsn1(dn);
    };

    /**
     * Converts an X.509v3 RSA certificate to an ASN.1 object.
     *
     * @param cert the certificate.
     *
     * @return the asn1 representation of an X.509v3 RSA certificate.
     */
    pki.certificateToAsn1 = function (cert: any) {
      // prefer cached TBSCertificate over generating one
      const tbsCertificate = cert.tbsCertificate || pki.getTBSCertificate(cert);

      // Certificate
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // TBSCertificate
        tbsCertificate,
        // AlgorithmIdentifier (signature algorithm)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          // algorithm
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(cert.signatureOid).getBytes()),
          // parameters
          signatureParametersToAsn1(cert.signatureOid, cert.signatureParameters)
        ]),
        // SignatureValue
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, String.fromCharCode(0x00) + cert.signature)
      ]);
    };

    /**
     * Converts X.509v3 certificate extensions to ASN.1.
     *
     * @param exts the extensions to convert.
     *
     * @return the extensions in ASN.1 format.
     */
    pki.certificateExtensionsToAsn1 = function (exts: any) {
      // create top-level extension container
      const rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 3, true, []);

      // create extension sequence (stores a sequence for each extension)
      const seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
      rval.value.push(seq);

      for (let i = 0; i < exts.length; ++i) {
        seq.value.push(pki.certificateExtensionToAsn1(exts[i]));
      }

      return rval;
    };

    /**
     * Converts a single certificate extension to ASN.1.
     *
     * @param ext the extension to convert.
     *
     * @return the extension in ASN.1 format.
     */
    pki.certificateExtensionToAsn1 = function (ext: any) {
      // create a sequence for each extension
      const extseq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

      // extnID (OID)
      extseq.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(ext.id).getBytes()));

      // critical defaults to false
      if (ext.critical) {
        // critical BOOLEAN DEFAULT FALSE
        extseq.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)));
      }

      let value = ext.value;
      if (typeof ext.value !== 'string') {
        // value is asn.1
        value = asn1.toDer(value).getBytes();
      }

      // extnValue (OCTET STRING)
      extseq.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, value));

      return extseq;
    };

    /**
     * Converts a PKCS#10 certification request to an ASN.1 object.
     *
     * @param csr the certification request.
     *
     * @return the asn1 representation of a certification request.
     */
    pki.certificationRequestToAsn1 = function (csr: any) {
      // prefer cached CertificationRequestInfo over generating one
      const cri = csr.certificationRequestInfo || pki.getCertificationRequestInfo(csr);

      // Certificate
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // CertificationRequestInfo
        cri,
        // AlgorithmIdentifier (signature algorithm)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          // algorithm
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(csr.signatureOid).getBytes()),
          // parameters
          signatureParametersToAsn1(csr.signatureOid, csr.signatureParameters)
        ]),
        // signature
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, String.fromCharCode(0x00) + csr.signature)
      ]);
    };

    /**
     * Creates a CA store.
     *
     * @param certs an optional array of certificate objects or PEM-formatted
     *          certificate strings to add to the CA store.
     *
     * @return the CA store.
     */
  }
}

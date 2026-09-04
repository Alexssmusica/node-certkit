/* Migrated from lib/pkcs12.js */
import {createPkcs12Validators} from './Pkcs12Asn1.js';
import type {Pkcs12Deps} from './Pkcs12Types.js';
import type {CertkitPkcs12Namespace} from './CertkitPkiTypes.js';

export type {Pkcs12Deps} from './Pkcs12Types.js';

export class Pkcs12Service {
  static createCertkitNamespace(deps: Pkcs12Deps): CertkitPkcs12Namespace {
    const asn1 = deps.asn1;
    const p12: any = {};
    const {
      contentInfoValidator,
      pfxValidator,
      safeBagValidator,
      attributeValidator,
      certBagValidator
    } = createPkcs12Validators(asn1);

    // OID for the content type is 'data'
    function createDataContentInfo(contentBytes: any) {
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // contentType
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.data).getBytes()),
        // content
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
            contentBytes)
        ])
      ]);
    }

/**
 * Search SafeContents structure for bags with matching attributes.
 *
 * The search can optionally be narrowed by a certain bag type.
 *
 * @param safeContents the SafeContents structure to search in.
 * @param attrName the name of the attribute to compare against.
 * @param attrValue the attribute value to search for.
 * @param [bagType] bag type to narrow search by.
 *
 * @return an array of matching bags.
 */
function _getBagsByAttribute(safeContents: any, attrName: any, attrValue: any, bagType: any) {
  const result = [];

  for(let i = 0; i < safeContents.length; i++) {
    for(let j = 0; j < safeContents[i].safeBags.length; j++) {
      const bag = safeContents[i].safeBags[j];
      if(bagType !== undefined && bag.type !== bagType) {
        continue;
      }
      // only filter by bag type, no attribute specified
      if(attrName === null) {
        result.push(bag);
        continue;
      }
      if(bag.attributes[attrName] !== undefined &&
        bag.attributes[attrName].indexOf(attrValue) >= 0) {
        result.push(bag);
      }
    }
  }

  return result;
}

/**
 * Converts a PKCS#12 PFX in ASN.1 notation into a PFX object.
 *
 * @param obj The PKCS#12 PFX in ASN.1 notation.
 * @param strict true to use strict DER decoding, false not to (default: true).
 * @param {String} password Password to decrypt with (optional).
 *
 * @return PKCS#12 PFX object.
 */
p12.pkcs12FromAsn1 = function(obj: any, strict: any, password: any) {
  // handle args
  if(typeof strict === 'string') {
    password = strict;
    strict = true;
  } else if(strict === undefined) {
    strict = true;
  }

  // validate PFX and capture data
  const capture: any = {};
  const errors: any[] = [];
  if(!asn1.validate(obj, pfxValidator, capture, errors)) {
    const error: any = new Error('Cannot read PKCS#12 PFX. ' +
      'ASN.1 object is not an PKCS#12 PFX.');
    error.errors = error;
    throw error;
  }

  const pfx = {
    version: capture.version.charCodeAt(0),
    safeContents: [],

    /**
     * Gets bags with matching attributes.
     *
     * @param filter the attributes to filter by:
     *          [localKeyId] the localKeyId to search for.
     *          [localKeyIdHex] the localKeyId in hex to search for.
     *          [friendlyName] the friendly name to search for.
     *          [bagType] bag type to narrow each attribute search by.
     *
     * @return a map of attribute type to an array of matching bags or, if no
     *           attribute was given but a bag type, the map key will be the
     *           bag type.
     */
    getBags: function(filter: any) {
      const rval: any = {};

      let localKeyId;
      if('localKeyId' in filter) {
        localKeyId = filter.localKeyId;
      } else if('localKeyIdHex' in filter) {
        localKeyId = deps.util.hexToBytes(filter.localKeyIdHex);
      }

      // filter on bagType only
      if(localKeyId === undefined && !('friendlyName' in filter) &&
        'bagType' in filter) {
        rval[filter.bagType] = _getBagsByAttribute(
          pfx.safeContents, null, null, filter.bagType);
      }

      if(localKeyId !== undefined) {
        rval.localKeyId = _getBagsByAttribute(
          pfx.safeContents, 'localKeyId',
          localKeyId, filter.bagType);
      }
      if('friendlyName' in filter) {
        rval.friendlyName = _getBagsByAttribute(
          pfx.safeContents, 'friendlyName',
          filter.friendlyName, filter.bagType);
      }

      return rval;
    },

    /**
     * DEPRECATED: use getBags() instead.
     *
     * Get bags with matching friendlyName attribute.
     *
     * @param friendlyName the friendly name to search for.
     * @param [bagType] bag type to narrow search by.
     *
     * @return an array of bags with matching friendlyName attribute.
     */
    getBagsByFriendlyName: function(friendlyName: any, bagType: any) {
      return _getBagsByAttribute(
        pfx.safeContents, 'friendlyName', friendlyName, bagType);
    },

    /**
     * DEPRECATED: use getBags() instead.
     *
     * Get bags with matching localKeyId attribute.
     *
     * @param localKeyId the localKeyId to search for.
     * @param [bagType] bag type to narrow search by.
     *
     * @return an array of bags with matching localKeyId attribute.
     */
    getBagsByLocalKeyId: function(localKeyId: any, bagType: any) {
      return _getBagsByAttribute(
        pfx.safeContents, 'localKeyId', localKeyId, bagType);
    }
  };

  if(capture.version.charCodeAt(0) !== 3) {
    const error: any = new Error('PKCS#12 PFX of version other than 3 not supported.');
    error.version = capture.version.charCodeAt(0);
    throw error;
  }

  if(asn1.derToOid(capture.contentType) !== deps.pki.oids.data) {
    const error: any = new Error('Only PKCS#12 PFX in password integrity mode supported.');
    error.oid = asn1.derToOid(capture.contentType);
    throw error;
  }

  let data = capture.content.value[0];
  if(data.tagClass !== asn1.Class.UNIVERSAL ||
     data.type !== asn1.Type.OCTETSTRING) {
    throw new Error('PKCS#12 authSafe content data is not an OCTET STRING.');
  }
  data = _decodePkcs7Data(data);

  // check for MAC
  if(capture.mac) {
    let md = null;
    let macKeyBytes = 0;
    const macAlgorithm = asn1.derToOid(capture.macAlgorithm);
    switch(macAlgorithm) {
    case deps.pki.oids.sha1:
      md = deps.md.sha1.create();
      macKeyBytes = 20;
      break;
    case deps.pki.oids.sha256:
      md = deps.md.sha256.create();
      macKeyBytes = 32;
      break;
    case deps.pki.oids.sha384:
      md = deps.md.sha384.create();
      macKeyBytes = 48;
      break;
    case deps.pki.oids.sha512:
      md = deps.md.sha512.create();
      macKeyBytes = 64;
      break;
    case deps.pki.oids.md5:
      md = deps.md.md5.create();
      macKeyBytes = 16;
      break;
    }
    if(md === null) {
      throw new Error('PKCS#12 uses unsupported MAC algorithm: ' + macAlgorithm);
    }

    // verify MAC (iterations default to 1)
    const macSalt = new deps.util.ByteBuffer(capture.macSalt);
    const macIterations = (('macIterations' in capture) ?
      parseInt(deps.util.bytesToHex(capture.macIterations), 16) : 1);
    const macKey = p12.generateKey(
      password, macSalt, 3, macIterations, macKeyBytes, md);
    const mac = deps.hmac.create();
    mac.start(md, macKey);
    mac.update(data.value);
    const macValue = mac.getMac();
    if(macValue.getBytes() !== capture.macDigest) {
      throw new Error('PKCS#12 MAC could not be verified. Invalid password?');
    }
  } else if(Array.isArray(obj.value) && obj.value.length > 2) {
    /* This is pfx data that should have mac and verify macDigest */
    throw new Error('Invalid PKCS#12. macData field present but MAC was not validated.');
  }

  _decodeAuthenticatedSafe(pfx, data.value, strict, password);
  return pfx;
};

/**
 * Decodes PKCS#7 Data. PKCS#7 (RFC 2315) defines "Data" as an OCTET STRING,
 * but it is sometimes an OCTET STRING that is composed/constructed of chunks,
 * each its own OCTET STRING. This is BER-encoding vs. DER-encoding. This
 * function transforms this corner-case into the usual simple,
 * non-composed/constructed OCTET STRING.
 *
 * This function may be moved to ASN.1 at some point to better deal with
 * more BER-encoding issues, should they arise.
 *
 * @param data the ASN.1 Data object to transform.
 */
function _decodePkcs7Data(data: any) {
  // handle special case of "chunked" data content: an octet string composed
  // of other octet strings
  if(data.composed || data.constructed) {
    const value = deps.util.createBuffer();
    for(let i = 0; i < data.value.length; ++i) {
      value.putBytes(data.value[i].value);
    }
    data.composed = data.constructed = false;
    data.value = value.getBytes();
  }
  return data;
}

/**
 * Decode PKCS#12 AuthenticatedSafe (BER encoded) into PFX object.
 *
 * The AuthenticatedSafe is a BER-encoded SEQUENCE OF ContentInfo.
 *
 * @param pfx The PKCS#12 PFX object to fill.
 * @param {String} authSafe BER-encoded AuthenticatedSafe.
 * @param strict true to use strict DER decoding, false not to.
 * @param {String} password Password to decrypt with (optional).
 */
function _decodeAuthenticatedSafe(pfx: any, authSafe: any, strict: any, password: any) {
  authSafe = asn1.fromDer(authSafe, strict);  /* actually it's BER encoded */

  if(authSafe.tagClass !== asn1.Class.UNIVERSAL ||
     authSafe.type !== asn1.Type.SEQUENCE ||
     authSafe.constructed !== true) {
    throw new Error('PKCS#12 AuthenticatedSafe expected to be a ' +
      'SEQUENCE OF ContentInfo');
  }

  for(let i = 0; i < authSafe.value.length; i++) {
    const contentInfo = authSafe.value[i];

    // validate contentInfo and capture data
    const capture: any = {};
    const errors: any[] = [];
    if(!asn1.validate(contentInfo, contentInfoValidator, capture, errors)) {
      const error: any = new Error('Cannot read ContentInfo.');
      error.errors = errors;
      throw error;
    }

    const obj: any = {
      encrypted: false
    };
    let safeContents = null;
    const data = capture.content.value[0];
    switch(asn1.derToOid(capture.contentType)) {
    case deps.pki.oids.data:
      if(data.tagClass !== asn1.Class.UNIVERSAL ||
         data.type !== asn1.Type.OCTETSTRING) {
        throw new Error('PKCS#12 SafeContents Data is not an OCTET STRING.');
      }
      safeContents = _decodePkcs7Data(data).value;
      break;
    case deps.pki.oids.encryptedData:
      safeContents = _decryptSafeContents(data, password);
      obj.encrypted = true;
      break;
    default:
      const error: any = new Error('Unsupported PKCS#12 contentType.');
      error.contentType = asn1.derToOid(capture.contentType);
      throw error;
    }

    obj.safeBags = _decodeSafeContents(safeContents, strict, password);
    pfx.safeContents.push(obj);
  }
}

/**
 * Decrypt PKCS#7 EncryptedData structure.
 *
 * @param data ASN.1 encoded EncryptedContentInfo object.
 * @param password The user-provided password.
 *
 * @return The decrypted SafeContents (ASN.1 object).
 */
function _decryptSafeContents(data: any, password: any) {
  const capture: any = {};
  const errors: any[] = [];
  if(!asn1.validate(
    data, deps.pkcs7.asn1.encryptedDataValidator, capture, errors)) {
    const error: any = new Error('Cannot read EncryptedContentInfo.');
    error.errors = errors;
    throw error;
  }

  let oid = asn1.derToOid(capture.contentType);
  if(oid !== deps.pki.oids.data) {
    const error: any = new Error(
      'PKCS#12 EncryptedContentInfo ContentType is not Data.');
    error.oid = oid;
    throw error;
  }

  // get cipher
  oid = asn1.derToOid(capture.encAlgorithm);
  const cipher = deps.pki.pbe.getCipher(oid, capture.encParameter, password);

  // get encrypted data
  const encryptedContentAsn1 = _decodePkcs7Data(capture.encryptedContentAsn1);
  const encrypted = deps.util.createBuffer(encryptedContentAsn1.value);

  cipher.update(encrypted);
  if(!cipher.finish()) {
    throw new Error('Failed to decrypt PKCS#12 SafeContents.');
  }

  return cipher.output.getBytes();
}

/**
 * Decode PKCS#12 SafeContents (BER-encoded) into array of Bag objects.
 *
 * The safeContents is a BER-encoded SEQUENCE OF SafeBag.
 *
 * @param {String} safeContents BER-encoded safeContents.
 * @param strict true to use strict DER decoding, false not to.
 * @param {String} password Password to decrypt with (optional).
 *
 * @return {Array} Array of Bag objects.
 */
function _decodeSafeContents(safeContents: any, strict: any, password: any) {
  // if strict and no safe contents, return empty safes
  if(!strict && safeContents.length === 0) {
    return [];
  }

  // actually it's BER-encoded
  safeContents = asn1.fromDer(safeContents, strict);

  if(safeContents.tagClass !== asn1.Class.UNIVERSAL ||
    safeContents.type !== asn1.Type.SEQUENCE ||
    safeContents.constructed !== true) {
    throw new Error(
      'PKCS#12 SafeContents expected to be a SEQUENCE OF SafeBag.');
  }

  const res = [];
  for(let i = 0; i < safeContents.value.length; i++) {
    const safeBag = safeContents.value[i];

    // validate SafeBag and capture data
    const capture: any = {};
    const errors: any[] = [];
    if(!asn1.validate(safeBag, safeBagValidator, capture, errors)) {
      const error: any = new Error('Cannot read SafeBag.');
      error.errors = errors;
      throw error;
    }

    /* Create bag object and push to result array. */
    const bag: any = {
      type: asn1.derToOid(capture.bagId),
      attributes: _decodeBagAttributes(capture.bagAttributes)
    };
    res.push(bag);

    let validator, decoder;
    let bagAsn1 = capture.bagValue.value[0];
    switch(bag.type) {
      case deps.pki.oids.pkcs8ShroudedKeyBag:
        /* bagAsn1 has a EncryptedPrivateKeyInfo, which we need to decrypt.
           Afterwards we can handle it like a keyBag,
           which is a PrivateKeyInfo. */
        bagAsn1 = deps.pki.decryptPrivateKeyInfo(bagAsn1, password);
        if(bagAsn1 === null) {
          throw new Error(
            'Unable to decrypt PKCS#8 ShroudedKeyBag, wrong password?');
        }

        /* fall through */
      case deps.pki.oids.keyBag:
        /* A PKCS#12 keyBag is a simple PrivateKeyInfo as understood by our
           PKI module, hence we don't have to do validation/capturing here,
           just pass what we already got. */
        try {
          bag.key = deps.pki.privateKeyFromAsn1(bagAsn1);
        } catch {
          // ignore unknown key type, pass asn1 value
          bag.key = null;
          bag.asn1 = bagAsn1;
        }
        continue;  /* Nothing more to do. */

      case deps.pki.oids.certBag:
        /* A PKCS#12 certBag can wrap both X.509 and sdsi certificates.
           Therefore put the SafeBag content through another validator to
           capture the fields.  Afterwards check & store the results. */
        validator = certBagValidator;
        decoder = function() {
          if(asn1.derToOid(capture.certId) !== deps.pki.oids.x509Certificate) {
            const error: any = new Error(
              'Unsupported certificate type, only X.509 supported.');
            error.oid = asn1.derToOid(capture.certId);
            throw error;
          }

          // true=produce cert hash
          const certAsn1 = asn1.fromDer(capture.cert, strict);
          try {
            bag.cert = deps.pki.certificateFromAsn1(certAsn1, true);
          } catch {
            // ignore unknown cert type, pass asn1 value
            bag.cert = null;
            bag.asn1 = certAsn1;
          }
        };
        break;

      default:
        const error: any = new Error('Unsupported PKCS#12 SafeBag type.');
        error.oid = bag.type;
        throw error;
    }

    /* Validate SafeBag value (i.e. CertBag, etc.) and capture data if needed. */
    if(validator !== undefined &&
       !asn1.validate(bagAsn1, validator, capture, errors)) {
      const error: any = new Error('Cannot read PKCS#12 ' + validator.name);
      error.errors = errors;
      throw error;
    }

    /* Call decoder function from above to store the results. */
    decoder();
  }

  return res;
}

/**
 * Decode PKCS#12 SET OF PKCS12Attribute into JavaScript object.
 *
 * @param attributes SET OF PKCS12Attribute (ASN.1 object).
 *
 * @return the decoded attributes.
 */
function _decodeBagAttributes(attributes: any) {
  const decodedAttrs: any = {};

  if(attributes !== undefined) {
    for(let i = 0; i < attributes.length; ++i) {
      const capture: any = {};
      const errors: any[] = [];
      if(!asn1.validate(attributes[i], attributeValidator, capture, errors)) {
        const error: any = new Error('Cannot read PKCS#12 BagAttribute.');
        error.errors = errors;
        throw error;
      }

      const oid = asn1.derToOid(capture.oid);
      if(deps.pki.oids[oid] === undefined) {
        // unsupported attribute type, ignore.
        continue;
      }

      decodedAttrs[deps.pki.oids[oid]] = [];
      for(let j = 0; j < capture.values.length; ++j) {
        decodedAttrs[deps.pki.oids[oid]].push(capture.values[j].value);
      }
    }
  }

  return decodedAttrs;
}

/**
 * Wraps a private key and certificate in a PKCS#12 PFX wrapper. If a
 * password is provided then the private key will be encrypted.
 *
 * An entire certificate chain may also be included. To do this, pass
 * an array for the "cert" parameter where the first certificate is
 * the one that is paired with the private key and each subsequent one
 * verifies the previous one. The certificates may be in PEM format or
 * have been already parsed by certkit.
 *
 * @todo implement password-based-encryption for the whole package
 *
 * @param key the private key.
 * @param cert the certificate (may be an array of certificates in order
 *          to specify a certificate chain).
 * @param password the password to use, null for none.
 * @param options:
 *          algorithm the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des'), defaults to 'aes128'.
 *          count the iteration count to use.
 *          saltSize the salt size to use.
 *          useMac true to include a MAC, false not to, defaults to true.
 *          localKeyId the local key ID to use, in hex.
 *          friendlyName the friendly name to use.
 *          generateLocalKeyId true to generate a random local key ID,
 *            false not to, defaults to true.
 *
 * @return the PKCS#12 PFX ASN.1 object.
 */
p12.toPkcs12Asn1 = function(key: any, cert: any, password: any, options: any) {
  // set default options
  options = options || {};
  options.saltSize = options.saltSize || 8;
  options.count = options.count || 2048;
  options.algorithm = options.algorithm || options.encAlgorithm || 'aes128';
  if(!('useMac' in options)) {
    options.useMac = true;
  }
  if(!('localKeyId' in options)) {
    options.localKeyId = null;
  }
  if(!('generateLocalKeyId' in options)) {
    options.generateLocalKeyId = true;
  }

  let localKeyId = options.localKeyId;
  let bagAttrs;
  if(localKeyId !== null) {
    localKeyId = deps.util.hexToBytes(localKeyId);
  } else if(options.generateLocalKeyId) {
    // use SHA-1 of paired cert, if available
    if(cert) {
      let pairedCert = deps.util.isArray(cert) ? cert[0] : cert;
      if(typeof pairedCert === 'string') {
        pairedCert = deps.pki.certificateFromPem(pairedCert);
      }
      const sha1 = deps.md.sha1.create();
      sha1.update(asn1.toDer(deps.pki.certificateToAsn1(pairedCert)).getBytes());
      localKeyId = sha1.digest().getBytes();
    } else {
      // FIXME: consider using SHA-1 of public key (which can be generated
      // from private key components), see: cert.generateSubjectKeyIdentifier
      // generate random bytes
      localKeyId = deps.random.getBytes(20);
    }
  }

  const attrs = [];
  if(localKeyId !== null) {
    attrs.push(
      // localKeyID
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // attrId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.localKeyId).getBytes()),
        // attrValues
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
            localKeyId)
        ])
      ]));
  }
  if('friendlyName' in options) {
    attrs.push(
      // friendlyName
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // attrId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.friendlyName).getBytes()),
        // attrValues
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BMPSTRING, false,
            options.friendlyName)
        ])
      ]));
  }

  if(attrs.length > 0) {
    bagAttrs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, attrs);
  }

  // collect contents for AuthenticatedSafe
  const contents = [];

  // create safe bag(s) for certificate chain
  let chain = [];
  if(cert !== null) {
    if(deps.util.isArray(cert)) {
      chain = cert;
    } else {
      chain = [cert];
    }
  }

  const certSafeBags = [];
  for(let i = 0; i < chain.length; ++i) {
    // convert cert from PEM as necessary
    cert = chain[i];
    if(typeof cert === 'string') {
      cert = deps.pki.certificateFromPem(cert);
    }

    // SafeBag
    const certBagAttrs = (i === 0) ? bagAttrs : undefined;
    const certAsn1 = deps.pki.certificateToAsn1(cert);
    const certSafeBag =
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.certBag).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          // CertBag
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // certId
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
              asn1.oidToDer(deps.pki.oids.x509Certificate).getBytes()),
            // certValue (x509Certificate)
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
              asn1.create(
                asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                asn1.toDer(certAsn1).getBytes())
            ])])]),
        // bagAttributes (OPTIONAL)
        certBagAttrs
      ]);
    certSafeBags.push(certSafeBag);
  }

  if(certSafeBags.length > 0) {
    // SafeContents
    const certSafeContents = asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, certSafeBags);

    // ContentInfo
    const certCI = createDataContentInfo(
      asn1.toDer(certSafeContents).getBytes());
    contents.push(certCI);
  }

  // create safe contents for private key
  let keyBag = null;
  if(key !== null) {
    // SafeBag
    const pkAsn1 = deps.pki.wrapRsaPrivateKey(deps.pki.privateKeyToAsn1(key));
    if(password === null) {
      // no encryption
      keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.keyBag).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          // PrivateKeyInfo
          pkAsn1
        ]),
        // bagAttributes (OPTIONAL)
        bagAttrs
      ]);
    } else {
      // encrypted PrivateKeyInfo
      keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(deps.pki.oids.pkcs8ShroudedKeyBag).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          // EncryptedPrivateKeyInfo
          deps.pki.encryptPrivateKeyInfo(pkAsn1, password, options)
        ]),
        // bagAttributes (OPTIONAL)
        bagAttrs
      ]);
    }

    // SafeContents
    const keySafeContents =
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [keyBag]);

    // ContentInfo
    const keyCI = createDataContentInfo(
      asn1.toDer(keySafeContents).getBytes());
    contents.push(keyCI);
  }

  // create AuthenticatedSafe by stringing together the contents
  const safe = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, contents);

  let macData;
  if(options.useMac) {
    // MacData
    const sha1 = deps.md.sha1.create();
    const macSalt = new deps.util.ByteBuffer(
      deps.random.getBytes(options.saltSize));
    const count = options.count;
    // 160-bit key
    const key = p12.generateKey(password, macSalt, 3, count, 20);
    const mac = deps.hmac.create();
    mac.start(sha1, key);
    mac.update(asn1.toDer(safe).getBytes());
    const macValue = mac.getMac();
    macData = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // mac DigestInfo
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // digestAlgorithm
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          // algorithm = SHA-1
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(deps.pki.oids.sha1).getBytes()),
          // parameters = Null
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
        ]),
        // digest
        asn1.create(
          asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING,
          false, macValue.getBytes())
      ]),
      // macSalt OCTET STRING
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, macSalt.getBytes()),
      // iterations INTEGER (XXX: Only support count < 65536)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
        asn1.integerToDer(count).getBytes()
      )
    ]);
  }

  // PFX
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (3)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      asn1.integerToDer(3).getBytes()),
    // PKCS#7 ContentInfo
    createDataContentInfo(asn1.toDer(safe).getBytes()),
    macData
  ]);
};

/**
 * Derives a PKCS#12 key.
 *
 * @param password the password to derive the key material from, null or
 *          undefined for none.
 * @param salt the salt, as a ByteBuffer, to use.
 * @param id the PKCS#12 ID byte (1 = key material, 2 = IV, 3 = MAC).
 * @param iter the iteration count.
 * @param n the number of bytes to derive from the password.
 * @param md the message digest to use, defaults to SHA-1.
 *
 * @return a ByteBuffer with the bytes derived from the password.
 */
p12.generateKey = deps.pbe.generatePkcs12Key;

    return p12 as CertkitPkcs12Namespace;
  }
}

export default Pkcs12Service;

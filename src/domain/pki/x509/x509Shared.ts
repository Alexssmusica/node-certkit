import type { X509Validators } from './X509Asn1.js';
import type { X509Runtime } from './X509Runtime.js';
import { createFillMissingExtensionFields } from './X509ExtensionFill.js';
import { createX509SignatureHelpers } from './X509Signature.js';
import type { DerError, X509AttachCtx, X509Helpers } from './X509Types.js';

export type { X509Helpers } from './X509Types.js';

export class X509Shared {
  static attach(ctx: X509Runtime, validators: X509Validators): X509Helpers {
    const c = ctx as X509AttachCtx;
    const asn1 = c.asn1;
    const oids = c.oids;
    const pki = c.pki;

    pki.RDNAttributesAsArray = function (rdn: any, md: any) {
      const rval = [];

      let set, attr, obj;
      for (let si = 0; si < rdn.value.length; ++si) {
        set = rdn.value[si];

        for (let i = 0; i < set.value.length; ++i) {
          obj = {} as any;
          attr = set.value[i];
          obj.type = asn1.derToOid(attr.value[0].value);
          obj.value = attr.value[1].value;
          obj.valueTagClass = attr.value[1].type;
          if (obj.type in oids) {
            obj.name = oids[obj.type];
            if (obj.name in validators.shortNames) {
              obj.shortName = validators.shortNames[obj.name];
            }
          }
          if (md) {
            md.update(obj.type);
            md.update(obj.value);
          }
          rval.push(obj);
        }
      }

      return rval;
    };

    /**
     * Converts ASN.1 CRIAttributes into an array with objects that have type and
     * value properties.
     *
     * @param attributes the CRIAttributes to convert.
     */
    pki.CRIAttributesAsArray = function (attributes: any) {
      const rval = [];

      for (let si = 0; si < attributes.length; ++si) {
        const seq = attributes[si];

        const type = asn1.derToOid(seq.value[0].value);
        const values = seq.value[1].value;
        for (let vi = 0; vi < values.length; ++vi) {
          const obj: any = {} as any;
          obj.type = type;
          obj.value = values[vi].value;
          obj.valueTagClass = values[vi].type;
          if (obj.type in oids) {
            obj.name = oids[obj.type];
            if (obj.name in validators.shortNames) {
              obj.shortName = validators.shortNames[obj.name];
            }
          }
          if (obj.type === oids.extensionRequest) {
            obj.extensions = [];
            for (let ei = 0; ei < obj.value.length; ++ei) {
              obj.extensions.push(pki.certificateExtensionFromAsn1(obj.value[ei]));
            }
          }
          rval.push(obj);
        }
      }

      return rval;
    };

    /**
     * Gets an issuer or subject attribute from its name, type, or short name.
     *
     * @param obj the issuer or subject object.
     * @param options a short name string or an object with:
     *          shortName the short name for the attribute.
     *          name the name for the attribute.
     *          type the type for the attribute.
     *
     * @return the attribute.
     */
    function getAttribute(obj: any, options?: any) {
      if (typeof options === 'string') {
        options = { shortName: options };
      }

      let rval = null;
      let attr;
      for (let i = 0; rval === null && i < obj.attributes.length; ++i) {
        attr = obj.attributes[i];
        if (options.type && options.type === attr.type) {
          rval = attr;
        } else if (options.name && options.name === attr.name) {
          rval = attr;
        } else if (options.shortName && options.shortName === attr.shortName) {
          rval = attr;
        }
      }
      return rval;
    }

    function dnToAsn1(obj: any) {
      const rval = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

      let attr, set;
      const attrs = obj.attributes;
      for (let i = 0; i < attrs.length; ++i) {
        attr = attrs[i];
        let value = attr.value;

        let valueTagClass = asn1.Type.PRINTABLESTRING;
        if ('valueTagClass' in attr) {
          valueTagClass = attr.valueTagClass;

          if (valueTagClass === asn1.Type.UTF8) {
            value = c.util!.encodeUtf8(value);
          }
        }

        set = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(attr.type).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, valueTagClass, false, value)
          ])
        ]);
        rval.value.push(set);
      }

      return rval;
    }

    /**
     * Gets all printable attributes (typically of an issuer or subject) in a
     * simplified JSON format for display.
     *
     * @param attrs the attributes.
     *
     * @return the JSON for display.
     */
    function getAttributesAsJson(attrs: any) {
      const rval: any = {} as any;
      for (let i = 0; i < attrs.length; ++i) {
        const attr = attrs[i];
        if (
          attr.shortName &&
          (attr.valueTagClass === asn1.Type.UTF8 ||
            attr.valueTagClass === asn1.Type.PRINTABLESTRING ||
            attr.valueTagClass === asn1.Type.IA5STRING)
        ) {
          let value = attr.value;
          if (attr.valueTagClass === asn1.Type.UTF8) {
            value = c.util!.encodeUtf8(attr.value);
          }
          if (!(attr.shortName in rval)) {
            rval[attr.shortName] = value;
          } else if (c.util!.isArray(rval[attr.shortName])) {
            rval[attr.shortName].push(value);
          } else {
            rval[attr.shortName] = [rval[attr.shortName], value];
          }
        }
      }
      return rval;
    }

    const fillMissingExtensionFields = createFillMissingExtensionFields({
      asn1,
      oids,
      util: c.util!,
      dnToAsn1
    });

    /**
     * Fills in missing fields in attributes.
     *
     * @param attrs the attributes to fill missing fields in.
     */
    function fillMissingFields(attrs: any) {
      let attr;
      for (let i = 0; i < attrs.length; ++i) {
        attr = attrs[i];

        if (typeof attr.name === 'undefined') {
          if (attr.type && attr.type in oids) {
            attr.name = oids[attr.type];
          } else if (attr.shortName && attr.shortName in validators.shortNames) {
            attr.name = oids[validators.shortNames[attr.shortName]];
          }
        }

        if (typeof attr.type === 'undefined') {
          if (attr.name && attr.name in oids) {
            attr.type = oids[attr.name];
          } else {
            const error = new Error('Attribute type not specified.') as DerError;
            error.attribute = attr;
            throw error;
          }
        }

        if (typeof attr.shortName === 'undefined') {
          if (attr.name && attr.name in validators.shortNames) {
            attr.shortName = validators.shortNames[attr.name];
          }
        }

        if (attr.type === oids.extensionRequest) {
          attr.valueConstructed = true;
          attr.valueTagClass = asn1.Type.SEQUENCE;
          if (!attr.value && attr.extensions) {
            attr.value = [];
            for (let ei = 0; ei < attr.extensions.length; ++ei) {
              attr.value.push(pki.certificateExtensionToAsn1(fillMissingExtensionFields(attr.extensions[ei])));
            }
          }
        }

        if (typeof attr.value === 'undefined') {
          const error = new Error('Attribute value not specified.') as DerError;
          error.attribute = attr;
          throw error;
        }
      }
    }

    const { readSignatureParameters, createSignatureDigest, verifySignature, signatureParametersToAsn1 } =
      createX509SignatureHelpers(
        {
          asn1,
          oids,
          md: c.md,
          pss: c.pss!,
          mgf: c.mgf!
        },
        validators
      );

    /**
     * Converts a certification request's attributes to an ASN.1 set of
     * CRIAttributes.
     *
     * @param csr certification request.
     *
     * @return the ASN.1 set of CRIAttributes.
     */
    function CRIAttributesToAsn1(csr: any) {
      const rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, []);

      if (csr.attributes.length === 0) {
        return rval;
      }

      const attrs = csr.attributes;
      for (let i = 0; i < attrs.length; ++i) {
        const attr = attrs[i];
        let value = attr.value;

        let valueTagClass = asn1.Type.UTF8;
        if ('valueTagClass' in attr) {
          valueTagClass = attr.valueTagClass;
        }
        if (valueTagClass === asn1.Type.UTF8) {
          value = c.util!.encodeUtf8(value);
        }
        let valueConstructed = false;
        if ('valueConstructed' in attr) {
          valueConstructed = attr.valueConstructed;
        }

        const seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(attr.type).getBytes()),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
            asn1.create(asn1.Class.UNIVERSAL, valueTagClass, valueConstructed, value)
          ])
        ]);
        rval.value.push(seq);
      }

      return rval;
    }

    const jan_1_1950 = new Date('1950-01-01T00:00:00Z');
    const jan_1_2050 = new Date('2050-01-01T00:00:00Z');

    /**
     * Converts a Date object to ASN.1
     * Handles the different format before and after 1st January 2050
     *
     * @param date date object.
     *
     * @return the ASN.1 object representing the date.
     */
    function dateToAsn1(date: any) {
      if (date >= jan_1_1950 && date < jan_1_2050) {
        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false, asn1.dateToUtcTime(date));
      } else {
        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.GENERALIZEDTIME, false, asn1.dateToGeneralizedTime(date));
      }
    }

    return {
      getAttribute,
      readSignatureParameters,
      createSignatureDigest,
      verifySignature,
      dnToAsn1,
      getAttributesAsJson,
      fillMissingFields,
      fillMissingExtensionFields,
      signatureParametersToAsn1,
      CRIAttributesToAsn1,
      dateToAsn1
    };
  }
}

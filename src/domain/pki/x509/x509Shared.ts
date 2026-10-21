import type { Asn1Object } from '../../asn1/Asn1Types.js';
import type { CertkitPki } from '../CertkitPkiTypes.js';
import type { X509Runtime } from './X509Runtime.js';
import { createFillMissingExtensionFields } from './X509ExtensionFill.js';
import { createX509SignatureHelpers } from './X509Signature.js';
import type {
  AttributeLookup,
  DerError,
  DnAttribute,
  DnAttributeInput,
  MessageDigest,
  X509CertificationRequest,
  X509Helpers,
  X509Validators
} from './X509Types.js';

export type { X509Helpers } from './X509Types.js';

export class X509Shared {
  static attach(ctx: X509Runtime, validators: X509Validators): X509Helpers {
    const asn1 = ctx.asn1;
    const oids = ctx.oids;
    const pki = ctx.pki as CertkitPki;

    pki.RDNAttributesAsArray = function (rdn: Asn1Object, messageDigest?: MessageDigest) {
      const attributes: DnAttribute[] = [];

      let rdnSet;
      let attributeAsn1;
      let dnAttribute: DnAttribute;
      for (let setIndex = 0; setIndex < (rdn.value as Asn1Object[]).length; ++setIndex) {
        rdnSet = (rdn.value as Asn1Object[])[setIndex]!;

        for (let index = 0; index < (rdnSet.value as Asn1Object[]).length; ++index) {
          dnAttribute = {} as DnAttribute;
          attributeAsn1 = (rdnSet.value as Asn1Object[])[index]!;
          dnAttribute.type = asn1.derToOid((attributeAsn1.value as Asn1Object[])[0].value as string);
          dnAttribute.value = (attributeAsn1.value as Asn1Object[])[1].value as string;
          dnAttribute.valueTagClass = (attributeAsn1.value as Asn1Object[])[1].type;
          if (dnAttribute.type in oids) {
            dnAttribute.name = oids[dnAttribute.type];
            if (dnAttribute.name in validators.shortNames) {
              dnAttribute.shortName = validators.shortNames[dnAttribute.name];
            }
          }
          if (messageDigest) {
            messageDigest.update(dnAttribute.type);
            messageDigest.update(dnAttribute.value);
          }
          attributes.push(dnAttribute);
        }
      }

      return attributes;
    };

    /**
     * Converts ASN.1 CRIAttributes into an array with objects that have type and
     * value properties.
     *
     * @param attributes the CRIAttributes to convert.
     */
    pki.CRIAttributesAsArray = function (attributes: Asn1Object[]) {
      const criAttributes: DnAttribute[] = [];

      for (let setIndex = 0; setIndex < attributes.length; ++setIndex) {
        const seq = attributes[setIndex];

        const type = asn1.derToOid((seq.value as Asn1Object[])[0].value as string);
        const values = (seq.value as Asn1Object[])[1].value as Asn1Object[];
        for (let valueIndex = 0; valueIndex < values.length; ++valueIndex) {
          const dnAttribute = {} as DnAttribute;
          dnAttribute.type = type;
          dnAttribute.value = values[valueIndex].value as string | Asn1Object[];
          dnAttribute.valueTagClass = values[valueIndex].type;
          if (dnAttribute.type in oids) {
            dnAttribute.name = oids[dnAttribute.type];
            if (dnAttribute.name in validators.shortNames) {
              dnAttribute.shortName = validators.shortNames[dnAttribute.name];
            }
          }
          if (dnAttribute.type === oids.extensionRequest) {
            dnAttribute.extensions = [];
            const extValues = dnAttribute.value as Asn1Object[];
            for (let extensionIndex = 0; extensionIndex < extValues.length; ++extensionIndex) {
              dnAttribute.extensions.push(pki.certificateExtensionFromAsn1(extValues[extensionIndex]));
            }
          }
          criAttributes.push(dnAttribute);
        }
      }

      return criAttributes;
    };

    /**
     * Gets an issuer or subject attribute from its name, type, or short name.
     *
     * @param dnEntity the issuer or subject object.
     * @param options a short name string or an object with:
     *          shortName the short name for the attribute.
     *          name the name for the attribute.
     *          type the type for the attribute.
     *
     * @return the attribute.
     */
    function getAttribute(dnEntity: { attributes: DnAttribute[] }, options?: string | AttributeLookup) {
      if (typeof options === 'string') {
        options = { shortName: options };
      }

      let foundAttribute: DnAttribute | null = null;
      let attr: DnAttribute;
      for (let index = 0; foundAttribute === null && index < dnEntity.attributes.length; ++index) {
        attr = dnEntity.attributes[index]!;
        if (options!.type && options!.type === attr.type) {
          foundAttribute = attr;
        } else if (options!.name && options!.name === attr.name) {
          foundAttribute = attr;
        } else if (options!.shortName && options!.shortName === attr.shortName) {
          foundAttribute = attr;
        }
      }
      return foundAttribute;
    }

    function dnToAsn1(dnEntity: { attributes: DnAttribute[] }) {
      const rdnSequence = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

      let dnAttributeEntry;
      let attributeSet;
      const attrs = dnEntity.attributes;
      for (let index = 0; index < attrs.length; ++index) {
        dnAttributeEntry = attrs[index];
        let value = dnAttributeEntry.value;

        let valueTagClass = asn1.Type.PRINTABLESTRING;
        if ('valueTagClass' in dnAttributeEntry) {
          valueTagClass = dnAttributeEntry.valueTagClass;

          if (valueTagClass === asn1.Type.UTF8) {
            value = ctx.util.encodeUtf8(value as string);
          }
        }

        attributeSet = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(dnAttributeEntry.type).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, valueTagClass, false, value)
          ])
        ]);
        (rdnSequence.value as Asn1Object[]).push(attributeSet);
      }

      return rdnSequence;
    }

    /**
     * Gets all printable attributes (typically of an issuer or subject) in a
     * simplified JSON format for display.
     *
     * @param attrs the attributes.
     *
     * @return the JSON for display.
     */
    function getAttributesAsJson(attrs: DnAttribute[]) {
      const attributeMap: Record<string, unknown> = {};
      for (let index = 0; index < attrs.length; ++index) {
        const attr = attrs[index];
        if (
          attr.shortName &&
          (attr.valueTagClass === asn1.Type.UTF8 ||
            attr.valueTagClass === asn1.Type.PRINTABLESTRING ||
            attr.valueTagClass === asn1.Type.IA5STRING)
        ) {
          let value = attr.value;
          if (attr.valueTagClass === asn1.Type.UTF8) {
            value = ctx.util.encodeUtf8(attr.value as string);
          }
          if (!(attr.shortName in attributeMap)) {
            attributeMap[attr.shortName] = value;
          } else if (ctx.util.isArray(attributeMap[attr.shortName])) {
            (attributeMap[attr.shortName] as unknown[]).push(value);
          } else {
            attributeMap[attr.shortName] = [attributeMap[attr.shortName], value];
          }
        }
      }
      return attributeMap;
    }

    const fillMissingExtensionFields = createFillMissingExtensionFields({
      asn1,
      oids,
      util: ctx.util,
      dnToAsn1
    });

    /**
     * Fills in missing fields in attributes.
     *
     * @param attrs the attributes to fill missing fields in.
     */
    function fillMissingFields(attrs: DnAttributeInput[]) {
      let attr;
      for (let index = 0; index < attrs.length; ++index) {
        attr = attrs[index];

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
            for (let extensionIndex = 0; extensionIndex < attr.extensions.length; ++extensionIndex) {
              attr.value.push(
                pki.certificateExtensionToAsn1(fillMissingExtensionFields(attr.extensions[extensionIndex]))
              );
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
          digestRegistry: ctx.digestRegistry,
          pss: ctx.pss,
          mgf: ctx.mgf
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
    function CRIAttributesToAsn1(csr: X509CertificationRequest) {
      const criAttributesSet = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, []);

      if (csr.attributes.length === 0) {
        return criAttributesSet;
      }

      const attrs = csr.attributes;
      for (let index = 0; index < attrs.length; ++index) {
        const attr = attrs[index];
        let value = attr.value;

        let valueTagClass = asn1.Type.UTF8;
        if ('valueTagClass' in attr) {
          valueTagClass = attr.valueTagClass;
        }
        if (valueTagClass === asn1.Type.UTF8) {
          value = ctx.util.encodeUtf8(value as string);
        }
        let valueConstructed = false;
        if ('valueConstructed' in attr) {
          valueConstructed = attr.valueConstructed ?? false;
        }

        const seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(attr.type).getBytes()),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
            asn1.create(asn1.Class.UNIVERSAL, valueTagClass, valueConstructed, value)
          ])
        ]);
        (criAttributesSet.value as Asn1Object[]).push(seq);
      }

      return criAttributesSet;
    }

    const jan1Cutoff1950 = new Date('1950-01-01T00:00:00Z');
    const jan1Cutoff2050 = new Date('2050-01-01T00:00:00Z');

    /**
     * Converts a Date object to ASN.1
     * Handles the different format before and after 1st January 2050
     *
     * @param date date object.
     *
     * @return the ASN.1 object representing the date.
     */
    function dateToAsn1(date: Date) {
      if (date >= jan1Cutoff1950 && date < jan1Cutoff2050) {
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

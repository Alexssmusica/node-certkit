import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { Asn1Codec } from './Asn1Codec.js';
import type { Asn1FromDerOptions, Asn1Object, DerError } from './Asn1Types.js';

export function checkBufferLength(bytes: ByteStringBuffer, remaining: number, n: number): void {
  if (n > remaining) {
    const error = new Error('Too few bytes to parse DER.') as DerError;
    error.available = bytes.length();
    error.remaining = remaining;
    error.requested = n;
    throw error;
  }
}

export function getValueLength(bytes: ByteStringBuffer, remaining: number): number | undefined {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  // fromDer already checked that this byte exists
  const b2 = bytes.getByte();
  remaining--;
  if (b2 === 0x80) {
    return undefined;
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  let length;
  const longForm = b2 & 0x80;
  if (!longForm) {
    // length is just the first byte
    length = b2;
  } else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    const longFormBytes = b2 & 0x7f;
    checkBufferLength(bytes, remaining, longFormBytes);
    length = bytes.getInt(longFormBytes << 3);
  }
  // FIXME: this will only happen for 32 bit getInt with high bit set
  if (length < 0) {
    throw new Error('Negative length: ' + length);
  }
  return length;
}

/**
 * Internal function to parse an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the number of bytes remaining for this chunk.
 * @param depth the current parsing depth.
 * @param options object with same options as fromDer().
 *
 * @return the parsed asn1 object.
 */
export function fromDerInternal(
  bytes: ByteStringBuffer,
  remaining: number,
  depth: number,
  options: Asn1FromDerOptions & {
    maxDepth: number;
    strict: boolean;
    parseAllBytes: boolean;
    decodeBitStrings: boolean;
  }
): Asn1Object {
  // check depth limit
  if (depth >= options.maxDepth) {
    throw new Error('ASN.1 parsing error: Max depth exceeded.');
  }

  // temporary storage for consumption calculations
  let start;

  // minimum length for ASN.1 DER structure is 2
  checkBufferLength(bytes, remaining, 2);

  // get the first byte
  const b1 = bytes.getByte();
  // consumed one byte
  remaining--;

  // get the tag class
  const tagClass = b1 & 0xc0;

  // get the type (bits 1-5)
  const type = b1 & 0x1f;

  // get the variable value length and adjust remaining bytes
  start = bytes.length();
  let length = getValueLength(bytes, remaining);
  remaining -= start - bytes.length();

  // ensure there are enough bytes to get the value
  if (length !== undefined && length > remaining) {
    if (options.strict) {
      const error = new Error('Too few bytes to read ASN.1 value.') as DerError;
      error.available = bytes.length();
      error.remaining = remaining;
      error.requested = length;
      throw error;
    }
    // Note: be lenient with truncated values and use remaining state bytes
    length = remaining;
  }

  // value storage
  let value;
  // possible BIT STRING contents storage
  let bitStringContents;

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  const constructed = (b1 & 0x20) === 0x20;
  if (constructed) {
    // parse child asn1 objects from the value
    value = [];
    if (length === undefined) {
      // asn1 object of indefinite length, read until end tag
      for (;;) {
        checkBufferLength(bytes, remaining, 2);
        if (bytes.bytes(2) === String.fromCharCode(0, 0)) {
          bytes.getBytes(2);
          remaining -= 2;
          break;
        }
        start = bytes.length();
        value.push(fromDerInternal(bytes, remaining, depth + 1, options));
        remaining -= start - bytes.length();
      }
    } else {
      // parsing asn1 object of definite length
      while (length > 0) {
        start = bytes.length();
        value.push(fromDerInternal(bytes, length, depth + 1, options));
        remaining -= start - bytes.length();
        length -= start - bytes.length();
      }
    }
  }

  // if a BIT STRING, save the contents including padding
  if (value === undefined && tagClass === Asn1Codec.Class.UNIVERSAL && type === Asn1Codec.Type.BITSTRING) {
    bitStringContents = bytes.bytes(length);
  }

  // determine if a non-constructed value should be decoded as a composed
  // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
  // can be used this way.
  if (
    value === undefined &&
    options.decodeBitStrings &&
    tagClass === Asn1Codec.Class.UNIVERSAL &&
    // FIXME: OCTET STRINGs not yet supported here
    // .. other parts of certkit expect to decode OCTET STRINGs manually
    type === Asn1Codec.Type.BITSTRING /*|| type === Asn1Codec.Type.OCTETSTRING*/ &&
    length !== undefined &&
    length > 1
  ) {
    // save read position
    const savedRead = bytes.read;
    const savedRemaining = remaining;
    let unused = 0;
    if (type === Asn1Codec.Type.BITSTRING) {
      /* The first octet gives the number of bits by which the length of the
        bit string is less than the next multiple of eight (this is called
        the "number of unused bits").

        The second and following octets give the value of the bit string
        converted to an octet string. */
      checkBufferLength(bytes, remaining, 1);
      unused = bytes.getByte();
      remaining--;
    }
    // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
    if (unused === 0) {
      try {
        // attempt to parse child asn1 object from the value
        // (stored in array to signal composed value)
        start = bytes.length();
        const subOptions = {
          // enforce strict mode to avoid parsing ASN.1 from plain data
          strict: true,
          decodeBitStrings: true
        };
        const composed = fromDerInternal(bytes, remaining, depth + 1, subOptions as any);
        let used = start - bytes.length();
        remaining -= used;
        if (type == Asn1Codec.Type.BITSTRING) {
          used++;
        }

        // if the data all decoded and the class indicates UNIVERSAL or
        // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
        const tc = composed.tagClass;
        if (used === length && (tc === Asn1Codec.Class.UNIVERSAL || tc === Asn1Codec.Class.CONTEXT_SPECIFIC)) {
          value = [composed];
        }
      } catch {}
    }
    if (value === undefined) {
      // restore read position
      bytes.read = savedRead;
      remaining = savedRemaining;
    }
  }

  if (value === undefined) {
    // asn1 not constructed or composed, get raw value
    // TODO: do DER to OID conversion and vice-versa in .toDer?

    if (length === undefined) {
      if (options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.');
      }
      // be lenient and use remaining state bytes
      length = remaining;
    }

    if (type === Asn1Codec.Type.BMPSTRING) {
      value = '';
      for (; length > 0; length -= 2) {
        checkBufferLength(bytes, remaining, 2);
        value += String.fromCharCode(bytes.getInt16());
        remaining -= 2;
      }
    } else {
      value = bytes.getBytes(length);
      remaining -= length;
    }
  }

  // add BIT STRING contents if available
  const asn1Options =
    bitStringContents === undefined
      ? null
      : {
          bitStringContents: bitStringContents
        };

  // create and return asn1 object
  return Asn1Codec.create(tagClass, type, constructed, value, asn1Options);
}

/* eslint-disable @typescript-eslint/no-this-alias -- legacy node-forge RSA key POJO pattern */
import type { Asn1Object, Asn1Validator, Asn1Value } from '../asn1/Asn1Types.js';
import { ByteStringBuffer } from '../buffer/ByteStringBuffer.js';
import { BigInteger } from '../math/BigInteger.js';
import type { BigIntegerRandomSource } from '../math/BigInteger.js';
import type { NativeCryptoProvider, PemKeyCodec, PrimeGenerator } from '../ports/index.js';
import { UtilNamespace } from '../util/UtilNamespace.js';
import { constantTimeEquals } from '../util/constantTimeEquals.js';
import { createRsaValidators } from './RsaAsn1.js';
import type {
  KeyPairGenerationState,
  RsaKeyMaterial,
  RsaKeyPair,
  RsaPrivateKey,
  RsaPublicKey,
  RsaServiceDeps
} from './RsaTypes.js';
import { Pkcs1Codec } from './Pkcs1Codec.js';
import { PemCodec } from './PemCodec.js';
import type { CertkitPki, CertkitRsaNamespace } from './CertkitPkiTypes.js';

/** @internal Options that weaken RSA verification; not part of the public API. */
type RsaVerifyInternalOptions = {
  _parseAllDigestBytes?: boolean;
  _skipPaddingChecks?: boolean;
};

const GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];

function getMillerRabinTests(bits: number): number {
  if (bits <= 100) return 27;
  if (bits <= 150) return 18;
  if (bits <= 200) return 15;
  if (bits <= 250) return 12;
  if (bits <= 300) return 9;
  if (bits <= 350) return 8;
  if (bits <= 400) return 7;
  if (bits <= 500) return 6;
  if (bits <= 600) return 5;
  if (bits <= 800) return 4;
  if (bits <= 1250) return 3;
  return 2;
}

function bnToBytes(bigInteger: BigInteger): string {
  let hex = bigInteger.toString(16);
  if (hex[0] >= '8') {
    hex = '00' + hex;
  }
  const bytes = UtilNamespace.hexToBytes(hex);
  if (
    bytes.length > 1 &&
    ((bytes.charCodeAt(0) === 0 && (bytes.charCodeAt(1) & 0x80) === 0) ||
      (bytes.charCodeAt(0) === 0xff && (bytes.charCodeAt(1) & 0x80) === 0x80))
  ) {
    return bytes.substr(1);
  }
  return bytes;
}

export class RsaService {
  readonly #oids: Record<string, string>;
  readonly #asn1: RsaServiceDeps['asn1'];
  readonly #random: RsaServiceDeps['random'];
  readonly #primeGenerator: PrimeGenerator;
  readonly #nativeCrypto: NativeCryptoProvider | null;
  #pemKeyCodec: PemKeyCodec | null;
  readonly #usePureJavaScript: boolean;

  readonly privateKeyValidator: Asn1Validator;
  readonly rsaPrivateKeyValidator: Asn1Validator;
  readonly rsaPublicKeyValidator: Asn1Validator;
  readonly publicKeyValidator: Asn1Validator;
  readonly digestInfoValidator: Asn1Validator;

  constructor(deps: RsaServiceDeps) {
    this.#oids = deps.oids;
    this.#asn1 = deps.asn1;
    this.#random = deps.random;
    this.#primeGenerator = deps.primeGenerator;
    this.#nativeCrypto = deps.nativeCrypto ?? null;
    this.#pemKeyCodec = deps.pemKeyCodec ?? null;
    this.#usePureJavaScript = deps.usePureJavaScript ?? false;

    const validators = createRsaValidators(deps.asn1);
    this.privateKeyValidator = validators.privateKeyValidator;
    this.rsaPrivateKeyValidator = validators.rsaPrivateKeyValidator;
    this.rsaPublicKeyValidator = validators.rsaPublicKeyValidator;
    this.publicKeyValidator = validators.publicKeyValidator;
    this.digestInfoValidator = validators.digestInfoValidator;
  }

  setPemKeyCodec(codec: PemKeyCodec): void {
    this.#pemKeyCodec = codec;
  }

  #createAsn1(tagClass: number, type: number, constructed: boolean, value: Asn1Value): Asn1Object {
    return this.#asn1.create(tagClass, type, constructed, value, null);
  }

  createDefaultPemKeyCodec(): PemKeyCodec {
    const self = this;
    return {
      privateKeyFromPem(pem: string) {
        const pemMessage = PemCodec.decode(pem)[0];
        if (pemMessage.type !== 'PRIVATE KEY' && pemMessage.type !== 'RSA PRIVATE KEY') {
          const error = new Error(
            'Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".'
          ) as Error & {
            headerType?: string;
          };
          error.headerType = pemMessage.type;
          throw error;
        }
        if (pemMessage.procType?.type === 'ENCRYPTED') {
          throw new Error('Could not convert private key from PEM; PEM is encrypted.');
        }
        const asn1Object = self.#asn1.fromDer(pemMessage.body, {});
        return self.privateKeyFromAsn1(asn1Object);
      },
      publicKeyFromPem(pem: string) {
        const pemMessage = PemCodec.decode(pem)[0];
        if (pemMessage.type !== 'PUBLIC KEY' && pemMessage.type !== 'RSA PUBLIC KEY') {
          const error = new Error(
            'Could not convert public key from PEM; PEM header type is not "PUBLIC KEY" or "RSA PUBLIC KEY".'
          ) as Error & {
            headerType?: string;
          };
          error.headerType = pemMessage.type;
          throw error;
        }
        if (pemMessage.procType?.type === 'ENCRYPTED') {
          throw new Error('Could not convert public key from PEM; PEM is encrypted.');
        }
        const asn1Object = self.#asn1.fromDer(pemMessage.body, {});
        return self.publicKeyFromAsn1(asn1Object);
      }
    };
  }

  #getPemKeyCodec(): PemKeyCodec {
    if (!this.#pemKeyCodec) {
      this.#pemKeyCodec = this.createDefaultPemKeyCodec();
    }
    return this.#pemKeyCodec;
  }

  #encodeDigestInfo(oid: string, withNullParameters: boolean, digestBytes: string): string {
    const asn1 = this.#asn1;
    const oidBytes = asn1.oidToDer(oid).getBytes();
    const digestInfo = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
    const digestAlgorithm = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
    (digestAlgorithm.value as Asn1Object[]).push(
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OID, false, oidBytes)
    );
    if (withNullParameters) {
      (digestAlgorithm.value as Asn1Object[]).push(this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''));
    }
    const digest = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, digestBytes);
    (digestInfo.value as Asn1Object[]).push(digestAlgorithm);
    (digestInfo.value as Asn1Object[]).push(digest);
    return asn1.toDer(digestInfo).getBytes();
  }

  #emsaPkcs1v15encode(messageDigest: { algorithm: string; digest(): ByteStringBuffer }): string {
    let oid: string;
    if (messageDigest.algorithm in this.#oids) {
      oid = this.#oids[messageDigest.algorithm]!;
    } else {
      const error = new Error('Unknown message digest algorithm.') as Error & { algorithm?: string };
      error.algorithm = messageDigest.algorithm;
      throw error;
    }
    return this.#encodeDigestInfo(oid, true, messageDigest.digest().getBytes());
  }

  #modPow(baseValue: BigInteger, key: RsaKeyMaterial, usePublicKey: boolean): BigInteger {
    if (usePublicKey) {
      return baseValue.modPow(key.e, key.n);
    }

    if (!key.p || !key.q) {
      return baseValue.modPow(key.d!, key.n);
    }

    if (!key.dP) {
      key.dP = key.d!.mod(key.p.subtract(BigInteger.ONE));
    }
    if (!key.dQ) {
      key.dQ = key.d!.mod(key.q.subtract(BigInteger.ONE));
    }
    if (!key.qInv) {
      key.qInv = key.q.modInverse(key.p);
    }

    let blindingFactor: BigInteger;
    do {
      blindingFactor = new BigInteger(UtilNamespace.bytesToHex(this.#random.getBytesSync(key.n.bitLength() / 8)), 16);
    } while (blindingFactor.compareTo(key.n) >= 0 || !blindingFactor.gcd(key.n).equals(BigInteger.ONE));
    baseValue = baseValue.multiply(blindingFactor.modPow(key.e, key.n)).mod(key.n);

    let modPResult = baseValue.mod(key.p).modPow(key.dP, key.p);
    const modQResult = baseValue.mod(key.q).modPow(key.dQ, key.q);

    while (modPResult.compareTo(modQResult) < 0) {
      modPResult = modPResult.add(key.p);
    }

    let result = modPResult.subtract(modQResult).multiply(key.qInv).mod(key.p).multiply(key.q).add(modQResult);
    result = result.multiply(blindingFactor.modInverse(key.n)).mod(key.n);
    return result;
  }

  #encodePkcs1v15(message: string, key: RsaKeyMaterial, blockType: number): ByteStringBuffer {
    const encodingBlock = new ByteStringBuffer();
    const keyOctetLength = Math.ceil(key.n.bitLength() / 8);

    if (message.length > keyOctetLength - 11) {
      const error = new Error('Message is too long for PKCS#1 v1.5 padding.') as Error & {
        length?: number;
        max?: number;
      };
      error.length = message.length;
      error.max = keyOctetLength - 11;
      throw error;
    }

    encodingBlock.putByte(0x00);
    encodingBlock.putByte(blockType);

    let padNum = keyOctetLength - 3 - message.length;
    if (blockType === 0x00 || blockType === 0x01) {
      const padByte = blockType === 0x00 ? 0x00 : 0xff;
      for (let index = 0; index < padNum; ++index) {
        encodingBlock.putByte(padByte);
      }
    } else {
      while (padNum > 0) {
        let numZeros = 0;
        const padBytes = this.#random.getBytes(padNum);
        for (let index = 0; index < padNum; ++index) {
          const padByte = padBytes.charCodeAt(index);
          if (padByte === 0) {
            ++numZeros;
          } else {
            encodingBlock.putByte(padByte);
          }
        }
        padNum = numZeros;
      }
    }

    encodingBlock.putByte(0x00);
    encodingBlock.putBytes(message);
    return encodingBlock;
  }

  #decodePkcs1v15(
    encodedMessage: string,
    key: RsaKeyMaterial,
    usePublicKey: boolean,
    messageLength?: number | false,
    options?: { _skipPaddingChecks?: boolean }
  ): string {
    const keyOctetLength = Math.ceil(key.n.bitLength() / 8);
    const encodingBlock = new ByteStringBuffer(encodedMessage);
    const first = encodingBlock.getByte();
    const blockType = encodingBlock.getByte();
    if (
      first !== 0x00 ||
      (usePublicKey && blockType !== 0x00 && blockType !== 0x01) ||
      (!usePublicKey && blockType !== 0x02) ||
      (usePublicKey && blockType === 0x00 && typeof messageLength === 'undefined')
    ) {
      throw new Error('Encryption block is invalid.');
    }

    let padNum = 0;
    if (blockType === 0x00) {
      padNum = keyOctetLength - 3 - (messageLength as number);
      for (let index = 0; index < padNum; ++index) {
        if (encodingBlock.getByte() !== 0x00) {
          throw new Error('Encryption block is invalid.');
        }
      }
    } else if (blockType === 0x01) {
      padNum = 0;
      while (encodingBlock.length() > 1) {
        if (encodingBlock.getByte() !== 0xff) {
          --encodingBlock.read;
          break;
        }
        ++padNum;
      }
      if (padNum < 8 && !options?._skipPaddingChecks) {
        throw new Error('Encryption block is invalid.');
      }
    } else if (blockType === 0x02) {
      padNum = 0;
      while (encodingBlock.length() > 1) {
        if (encodingBlock.getByte() === 0x00) {
          --encodingBlock.read;
          break;
        }
        ++padNum;
      }
      if (padNum < 8 && !options?._skipPaddingChecks) {
        throw new Error('Encryption block is invalid.');
      }
    }

    const zero = encodingBlock.getByte();
    if (zero !== 0x00 || padNum !== keyOctetLength - 3 - encodingBlock.length()) {
      throw new Error('Encryption block is invalid.');
    }

    return encodingBlock.getBytes();
  }

  encrypt(message: string, key: RsaKeyMaterial, blockType: boolean | number): string {
    let usePublicKey: boolean;
    let encodingBlock: ByteStringBuffer;

    const keyOctetLength = Math.ceil(key.n.bitLength() / 8);

    if (blockType !== false && blockType !== true) {
      usePublicKey = blockType === 0x02;
      encodingBlock = this.#encodePkcs1v15(message, key, blockType);
    } else {
      usePublicKey = blockType;
      encodingBlock = new ByteStringBuffer();
      encodingBlock.putBytes(message);
    }

    const messageInteger = new BigInteger(encodingBlock.toHex(), 16);
    const ciphertextInteger = this.#modPow(messageInteger, key, usePublicKey);
    const ciphertextHex = ciphertextInteger.toString(16);
    const encryptedData = new ByteStringBuffer();
    let zeros = keyOctetLength - Math.ceil(ciphertextHex.length / 2);
    while (zeros > 0) {
      encryptedData.putByte(0x00);
      --zeros;
    }
    encryptedData.putBytes(UtilNamespace.hexToBytes(ciphertextHex));
    return encryptedData.getBytes();
  }

  decrypt(encryptedData: string, key: RsaKeyMaterial, usePublicKey: boolean, decodePadding?: boolean | number): string {
    const keyOctetLength = Math.ceil(key.n.bitLength() / 8);

    if (encryptedData.length !== keyOctetLength) {
      const error = new Error('Encrypted message length is invalid.') as Error & {
        length?: number;
        expected?: number;
      };
      error.length = encryptedData.length;
      error.expected = keyOctetLength;
      throw error;
    }

    const ciphertextInteger = new BigInteger(new ByteStringBuffer(encryptedData).toHex(), 16);
    if (ciphertextInteger.compareTo(key.n) >= 0) {
      throw new Error('Encrypted message is invalid.');
    }

    const plaintextInteger = this.#modPow(ciphertextInteger, key, usePublicKey);
    const plaintextHex = plaintextInteger.toString(16);
    const encodingBlock = new ByteStringBuffer();
    let zeros = keyOctetLength - Math.ceil(plaintextHex.length / 2);
    while (zeros > 0) {
      encodingBlock.putByte(0x00);
      --zeros;
    }
    encodingBlock.putBytes(UtilNamespace.hexToBytes(plaintextHex));

    if (decodePadding !== false) {
      return this.#decodePkcs1v15(encodingBlock.getBytes(), key, usePublicKey);
    }
    return encodingBlock.getBytes();
  }

  setPublicKey(modulus: BigInteger, publicExponent: BigInteger): RsaPublicKey {
    const service = this;
    const key = { n: modulus, e: publicExponent } as RsaPublicKey;

    key.encrypt = function (data, scheme, schemeOptions) {
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      } else if (scheme === undefined) {
        scheme = 'RSAES-PKCS1-V1_5';
      }

      let schemeObj: { encode: (message: string, key: RsaKeyMaterial, pub?: boolean) => string };
      if (scheme === 'RSAES-PKCS1-V1_5') {
        schemeObj = {
          encode(message, keyMaterial) {
            return service.#encodePkcs1v15(message, keyMaterial, 0x02).getBytes();
          }
        };
      } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
        schemeObj = {
          encode(message, keyMaterial) {
            return Pkcs1Codec.encodeRsaOaep(
              keyMaterial,
              message,
              schemeOptions as Parameters<typeof Pkcs1Codec.encodeRsaOaep>[2],
              undefined,
              undefined,
              (count) => service.#random.getBytesSync(count)
            );
          }
        };
      } else if (['RAW', 'NONE', 'NULL', null].indexOf(scheme as string | null) !== -1) {
        schemeObj = {
          encode(encodedData) {
            return encodedData;
          }
        };
      } else if (typeof scheme === 'string') {
        throw new Error('Unsupported encryption scheme: "' + scheme + '".');
      } else {
        schemeObj = scheme as typeof schemeObj;
      }

      const encoded = schemeObj.encode(data, key, true);
      return service.encrypt(encoded, key, true);
    };

    key.verify = function (digest, signature, scheme, options) {
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      } else if (scheme === undefined) {
        scheme = 'RSASSA-PKCS1-V1_5';
      }
      if (options === undefined) {
        options = { _parseAllDigestBytes: true, _skipPaddingChecks: false };
      }
      const verifyOptions: RsaVerifyInternalOptions = {
        _parseAllDigestBytes: (options as RsaVerifyInternalOptions)._parseAllDigestBytes !== false,
        _skipPaddingChecks: (options as RsaVerifyInternalOptions)._skipPaddingChecks === true
      };

      let schemeObj: { verify: (digest: string, decrypted: string, modBits?: number) => boolean };
      if (scheme === 'RSASSA-PKCS1-V1_5') {
        schemeObj = {
          verify(expectedDigest, decryptedPayload) {
            decryptedPayload = service.#decodePkcs1v15(decryptedPayload, key, true, undefined, verifyOptions);
            const asn1Object = service.#asn1.fromDer(decryptedPayload, {
              parseAllBytes: verifyOptions._parseAllDigestBytes
            });
            const capture: Record<string, string> = {};
            const errors: string[] = [];
            if (
              !service.#asn1.validate(asn1Object, service.digestInfoValidator, capture, errors) ||
              !Array.isArray(asn1Object.value) ||
              asn1Object.value.length !== 2
            ) {
              const error = new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value.'
              ) as Error & {
                errors?: string[];
              };
              error.errors = errors;
              throw error;
            }
            const oid = service.#asn1.derToOid(capture.algorithmIdentifier);
            const oids = service.#oids;
            if (!(
              oid === oids.md2 ||
              oid === oids.md5 ||
              oid === oids.sha1 ||
              oid === oids.sha224 ||
              oid === oids.sha256 ||
              oid === oids.sha384 ||
              oid === oids.sha512 ||
              oid === oids['sha512-224'] ||
              oid === oids['sha512-256']
            )) {
              const error = new Error('Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier.') as Error & {
                oid?: string;
              };
              error.oid = oid;
              throw error;
            }
            if (oid === oids.md2 || oid === oids.md5) {
              if (!('parameters' in capture)) {
                throw new Error(
                  'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value. ' +
                    'Missing algorithm identifier NULL parameters.'
                );
              }
            }
            const canonicalDigestInfo = service.#encodeDigestInfo(oid, 'parameters' in capture, capture.digest);
            if (decryptedPayload.substring(0, canonicalDigestInfo.length) !== canonicalDigestInfo) {
              throw new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value. ' +
                  'Non-canonical DigestInfo encoding.'
              );
            }
            return constantTimeEquals(expectedDigest, capture.digest);
          }
        };
      } else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
        schemeObj = {
          verify(expectedDigest, decryptedPayload) {
            decryptedPayload = service.#decodePkcs1v15(decryptedPayload, key, true, undefined, verifyOptions);
            return expectedDigest === decryptedPayload;
          }
        };
      } else {
        schemeObj = scheme as typeof schemeObj;
      }

      const decryptedPayload = service.decrypt(signature, key, true, false);
      return schemeObj.verify(digest, decryptedPayload, key.n.bitLength());
    };

    return key;
  }

  setPrivateKey(
    modulus: BigInteger,
    publicExponent: BigInteger,
    privateExponent: BigInteger,
    primeP: BigInteger,
    primeQ: BigInteger,
    crtExponentP: BigInteger,
    crtExponentQ: BigInteger,
    qInv: BigInteger
  ): RsaPrivateKey {
    const service = this;
    const key = {
      n: modulus,
      e: publicExponent,
      d: privateExponent,
      p: primeP,
      q: primeQ,
      dP: crtExponentP,
      dQ: crtExponentQ,
      qInv
    } as RsaPrivateKey;

    key.decrypt = function (data, scheme, schemeOptions) {
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      } else if (scheme === undefined) {
        scheme = 'RSAES-PKCS1-V1_5';
      }

      const decrypted = service.decrypt(data, key, false, false);

      let schemeObj: { decode: (ciphertext: string, key: RsaKeyMaterial, pub?: boolean) => string };
      if (scheme === 'RSAES-PKCS1-V1_5') {
        schemeObj = {
          decode: (ciphertext, keyMaterial, usePublicKey) =>
            service.#decodePkcs1v15(ciphertext, keyMaterial, usePublicKey!)
        };
      } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
        schemeObj = {
          decode(ciphertext, keyMaterial) {
            return Pkcs1Codec.decodeRsaOaep(
              keyMaterial,
              ciphertext,
              schemeOptions as Parameters<typeof Pkcs1Codec.decodeRsaOaep>[2]
            );
          }
        };
      } else if (['RAW', 'NONE', 'NULL', null].indexOf(scheme as string | null) !== -1) {
        schemeObj = {
          decode(ciphertext) {
            return ciphertext;
          }
        };
      } else {
        const schemeLabel = typeof scheme === 'string' ? scheme : 'unknown';
        throw new Error('Unsupported encryption scheme: "' + schemeLabel + '".');
      }

      return schemeObj.decode(decrypted, key, false);
    };

    key.sign = function (messageDigest, scheme) {
      let blockType: boolean | number = false;
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      }

      let schemeObj: { encode: (messageDigest: unknown, modBits?: number) => string };
      if (scheme === undefined || scheme === 'RSASSA-PKCS1-V1_5') {
        schemeObj = {
          encode: (digestHandle) =>
            service.#emsaPkcs1v15encode(digestHandle as { algorithm: string; digest(): ByteStringBuffer })
        };
        blockType = 0x01;
      } else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
        schemeObj = { encode: () => messageDigest as string };
        blockType = 0x01;
      } else {
        schemeObj = scheme as typeof schemeObj;
      }

      const encodedDigestInfo = schemeObj.encode(messageDigest, key.n.bitLength());
      return service.encrypt(encodedDigestInfo, key, blockType);
    };

    return key;
  }

  createKeyPairGenerationState(
    bits?: number | string,
    exponent?: number,
    options?: Record<string, unknown>
  ): KeyPairGenerationState {
    if (typeof bits === 'string') {
      bits = parseInt(bits, 10);
    }
    bits = bits || 2048;

    options = options || {};
    const prng = (options.prng as { getBytesSync(count: number): string }) || this.#random;
    const rng: BigIntegerRandomSource = {
      nextBytes(byteArray: number[]): void {
        const randomBytes = prng.getBytesSync(byteArray.length);
        for (let index = 0; index < byteArray.length; ++index) {
          byteArray[index] = randomBytes.charCodeAt(index);
        }
      }
    };

    const algorithm = options.algorithm || 'PRIMEINC';
    if (algorithm === 'PRIMEINC') {
      const generationState: KeyPairGenerationState = {
        algorithm,
        state: 0,
        bits,
        rng,
        eInt: exponent || 65537,
        e: new BigInteger(null),
        p: null,
        q: null,
        qBits: bits >> 1,
        pBits: bits - (bits >> 1),
        pqState: 0,
        num: null,
        keys: null
      };
      (generationState.e as BigInteger).fromInt(generationState.eInt as number);
      return generationState;
    }
    const algorithmLabel = typeof algorithm === 'string' ? algorithm : 'unknown';
    throw new Error('Invalid key generation algorithm: ' + algorithmLabel);
  }

  stepKeyPairGenerationState(state: KeyPairGenerationState, timeBudgetMs: number): boolean {
    if (!('algorithm' in state)) {
      state.algorithm = 'PRIMEINC';
    }

    const THIRTY = new BigInteger(null);
    THIRTY.fromInt(30);
    let deltaIdx = 0;
    const bitwiseOr = (left: number, right: number) => left | right;

    let loopStart = +new Date();
    let loopEnd: number;
    let total = 0;
    while (state.keys === null && (timeBudgetMs <= 0 || total < timeBudgetMs)) {
      if (state.state === 0) {
        const bits = state.p === null ? state.pBits : state.qBits;
        const bits1 = (bits as number) - 1;

        if (state.pqState === 0) {
          state.num = new BigInteger(bits as number, state.rng as BigIntegerRandomSource);
          if (!(state.num as BigInteger).testBit(bits1)) {
            (state.num as BigInteger).bitwiseTo(BigInteger.ONE.shiftLeft(bits1), bitwiseOr, state.num as BigInteger);
          }
          (state.num as BigInteger).dAddOffset(31 - (state.num as BigInteger).mod(THIRTY).byteValue(), 0);
          deltaIdx = 0;
          state.pqState = 1;
        } else if (state.pqState === 1) {
          if ((state.num as BigInteger).bitLength() > (bits as number)) {
            state.pqState = 0;
          } else if (
            (state.num as BigInteger).isProbablePrime(getMillerRabinTests((state.num as BigInteger).bitLength()))
          ) {
            state.pqState = 2;
          } else {
            (state.num as BigInteger).dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
          }
        } else if (state.pqState === 2) {
          state.pqState =
            (state.num as BigInteger)
              .subtract(BigInteger.ONE)
              .gcd(state.e as BigInteger)
              .compareTo(BigInteger.ONE) === 0
              ? 3
              : 0;
        } else if (state.pqState === 3) {
          state.pqState = 0;
          if (state.p === null) {
            state.p = state.num;
          } else {
            state.q = state.num;
          }
          if (state.p !== null && state.q !== null) {
            state.state = 1;
          }
          state.num = null;
        }
      } else if (state.state === 1) {
        if ((state.p as BigInteger).compareTo(state.q as BigInteger) < 0) {
          state.num = state.p;
          state.p = state.q;
          state.q = state.num;
        }
        state.state = 2;
      } else if (state.state === 2) {
        state.p1 = (state.p as BigInteger).subtract(BigInteger.ONE);
        state.q1 = (state.q as BigInteger).subtract(BigInteger.ONE);
        state.phi = (state.p1 as BigInteger).multiply(state.q1 as BigInteger);
        state.state = 3;
      } else if (state.state === 3) {
        if ((state.phi as BigInteger).gcd(state.e as BigInteger).compareTo(BigInteger.ONE) === 0) {
          state.state = 4;
        } else {
          state.p = null;
          state.q = null;
          state.state = 0;
        }
      } else if (state.state === 4) {
        state.n = (state.p as BigInteger).multiply(state.q as BigInteger);
        if ((state.n as BigInteger).bitLength() === state.bits) {
          state.state = 5;
        } else {
          state.q = null;
          state.state = 0;
        }
      } else if (state.state === 5) {
        const privateExponent = (state.e as BigInteger).modInverse(state.phi as BigInteger);
        state.keys = {
          privateKey: this.setPrivateKey(
            state.n as BigInteger,
            state.e as BigInteger,
            privateExponent,
            state.p as BigInteger,
            state.q as BigInteger,
            privateExponent.mod(state.p1 as BigInteger),
            privateExponent.mod(state.q1 as BigInteger),
            (state.q as BigInteger).modInverse(state.p as BigInteger)
          ),
          publicKey: this.setPublicKey(state.n as BigInteger, state.e as BigInteger)
        };
      }

      loopEnd = +new Date();
      total += loopEnd - loopStart;
      loopStart = loopEnd;
    }

    return state.keys !== null;
  }

  generateKeyPair(bits?: unknown, exponent?: unknown, options?: unknown, callback?: unknown): RsaKeyPair | void {
    if (arguments.length === 1) {
      if (typeof bits === 'object') {
        options = bits;
        bits = undefined;
      } else if (typeof bits === 'function') {
        callback = bits;
        bits = undefined;
      }
    } else if (arguments.length === 2) {
      if (typeof bits === 'number') {
        if (typeof exponent === 'function') {
          callback = exponent;
          exponent = undefined;
        } else if (typeof exponent !== 'number') {
          options = exponent;
          exponent = undefined;
        }
      } else {
        options = bits;
        callback = exponent;
        bits = undefined;
        exponent = undefined;
      }
    } else if (arguments.length === 3) {
      if (typeof exponent === 'number') {
        if (typeof options === 'function') {
          callback = options;
          options = undefined;
        }
      } else {
        callback = options;
        options = exponent;
        exponent = undefined;
      }
    }

    const opts = (options || {}) as Record<string, unknown>;
    if (bits === undefined) {
      bits = opts.bits || 2048;
    }
    if (exponent === undefined) {
      exponent = opts.e || 0x10001;
    }

    const pemCodec = this.#getPemKeyCodec();
    const nativeCrypto = this.#nativeCrypto;

    if (
      !this.#usePureJavaScript &&
      !opts.prng &&
      (bits as number) >= 256 &&
      (bits as number) <= 16384 &&
      (exponent === 0x10001 || exponent === 3)
    ) {
      if (callback) {
        if (nativeCrypto && typeof nativeCrypto.generateKeyPair === 'function') {
          return nativeCrypto.generateKeyPair(
            'rsa',
            {
              modulusLength: bits as number,
              publicExponent: exponent,
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            },
            (err, pub, priv) => {
              if (err) {
                return (callback as (err: Error | null) => void)(err);
              }
              (callback as (err: Error | null, keypair?: RsaKeyPair) => void)(null, {
                privateKey: pemCodec.privateKeyFromPem(priv),
                publicKey: pemCodec.publicKeyFromPem(pub)
              });
            }
          );
        }
      } else {
        if (nativeCrypto && typeof nativeCrypto.generateKeyPairSync === 'function') {
          const keypair = nativeCrypto.generateKeyPairSync('rsa', {
            modulusLength: bits as number,
            publicExponent: exponent,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
          });
          return {
            privateKey: pemCodec.privateKeyFromPem(keypair.privateKey),
            publicKey: pemCodec.publicKeyFromPem(keypair.publicKey)
          };
        }
      }
    }

    const state = this.createKeyPairGenerationState(bits as number, exponent as number, opts);
    if (!callback) {
      this.stepKeyPairGenerationState(state, 0);
      return state.keys as RsaKeyPair;
    }
    this.#generateKeyPairAsync(state, opts, callback as (err: Error | null, keypair?: RsaKeyPair) => void);
  }

  #generateKeyPairAsync(
    state: KeyPairGenerationState,
    options: Record<string, unknown>,
    callback: (err: Error | null, keypair?: RsaKeyPair) => void
  ): void {
    const opts = {
      algorithm: {
        name: options.algorithm || 'PRIMEINC',
        options: {
          workers: options.workers || 2,
          workLoad: options.workLoad || 100,
          workerScript: options.workerScript
        }
      }
    } as Record<string, unknown>;
    if ('prng' in options) {
      opts.prng = options.prng;
    }

    const service = this;
    generate();

    function generate(): void {
      getPrime(state.pBits as number, (err, num) => {
        if (err) {
          return callback(err);
        }
        state.p = num;
        if (state.q !== null) {
          return finish(err, state.q as BigInteger);
        }
        getPrime(state.qBits as number, finish);
      });
    }

    function getPrime(bits: number, primeCallback: (err: Error | null, num?: BigInteger) => void): void {
      service.#primeGenerator.generateProbablePrime(bits, opts, (err, num) => {
        primeCallback(err, num);
      });
    }

    function finish(err: Error | null, num?: BigInteger): void {
      if (err) {
        return callback(err);
      }

      state.q = num;

      if ((state.p as BigInteger).compareTo(state.q as BigInteger) < 0) {
        const swappedPrime = state.p;
        state.p = state.q;
        state.q = swappedPrime;
      }

      if (
        (state.p as BigInteger)
          .subtract(BigInteger.ONE)
          .gcd(state.e as BigInteger)
          .compareTo(BigInteger.ONE) !== 0
      ) {
        state.p = null;
        generate();
        return;
      }

      if (
        (state.q as BigInteger)
          .subtract(BigInteger.ONE)
          .gcd(state.e as BigInteger)
          .compareTo(BigInteger.ONE) !== 0
      ) {
        state.q = null;
        getPrime(state.qBits as number, finish);
        return;
      }

      state.p1 = (state.p as BigInteger).subtract(BigInteger.ONE);
      state.q1 = (state.q as BigInteger).subtract(BigInteger.ONE);
      state.phi = (state.p1 as BigInteger).multiply(state.q1 as BigInteger);

      if ((state.phi as BigInteger).gcd(state.e as BigInteger).compareTo(BigInteger.ONE) !== 0) {
        state.p = state.q = null;
        generate();
        return;
      }

      state.n = (state.p as BigInteger).multiply(state.q as BigInteger);
      if ((state.n as BigInteger).bitLength() !== state.bits) {
        state.q = null;
        getPrime(state.qBits as number, finish);
        return;
      }

      const privateExponent = (state.e as BigInteger).modInverse(state.phi as BigInteger);
      callback(null, {
        privateKey: service.setPrivateKey(
          state.n as BigInteger,
          state.e as BigInteger,
          privateExponent,
          state.p as BigInteger,
          state.q as BigInteger,
          privateExponent.mod(state.p1 as BigInteger),
          privateExponent.mod(state.q1 as BigInteger),
          (state.q as BigInteger).modInverse(state.p as BigInteger)
        ),
        publicKey: service.setPublicKey(state.n as BigInteger, state.e as BigInteger)
      });
    }
  }

  wrapRsaPrivateKey(rsaKey: Asn1Object): Asn1Object {
    const asn1 = this.#asn1;
    return this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(0).getBytes()),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        this.#createAsn1(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(this.#oids.rsaEncryption).getBytes()
        ),
        this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
      ]),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, asn1.toDer(rsaKey).getBytes())
    ]);
  }

  privateKeyFromAsn1(asn1Object: Asn1Object): RsaPrivateKey {
    const asn1 = this.#asn1;
    let capture: Record<string, string> = {};
    let errors: string[] = [];
    if (asn1.validate(asn1Object, this.privateKeyValidator, capture, errors)) {
      asn1Object = asn1.fromDer(new ByteStringBuffer(capture.privateKey), {});
    }

    capture = {};
    errors = [];
    if (!asn1.validate(asn1Object, this.rsaPrivateKeyValidator, capture, errors)) {
      const error = new Error('Cannot read private key. ASN.1 object does not contain an RSAPrivateKey.') as Error & {
        errors?: string[];
      };
      error.errors = errors;
      throw error;
    }

    return this.setPrivateKey(
      new BigInteger(new ByteStringBuffer(capture.privateKeyModulus).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPublicExponent).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrivateExponent).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrime1).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrime2).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyExponent1).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyExponent2).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyCoefficient).toHex(), 16)
    );
  }

  privateKeyToRSAPrivateKey(key: RsaPrivateKey): Asn1Object {
    const asn1 = this.#asn1;
    return this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(0).getBytes()),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.n)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.e)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.d)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.p!)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.q!)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.dP!)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.dQ!)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.qInv!))
    ]);
  }

  publicKeyFromAsn1(asn1Object: Asn1Object): RsaPublicKey {
    const asn1 = this.#asn1;
    const capture: Record<string, unknown> = {};
    const errors: string[] = [];
    if (asn1.validate(asn1Object, this.publicKeyValidator, capture, errors)) {
      const oid = asn1.derToOid(capture.publicKeyOid as string);
      if (oid !== this.#oids.rsaEncryption) {
        const error = new Error('Cannot read public key. Unknown OID.') as Error & { oid?: string };
        error.oid = oid;
        throw error;
      }
      asn1Object = capture.rsaPublicKey as Asn1Object;
    }

    const rsaKeyCapture: Record<string, string> = {};
    if (!asn1.validate(asn1Object, this.rsaPublicKeyValidator, rsaKeyCapture, errors)) {
      const error = new Error('Cannot read public key. ASN.1 object does not contain an RSAPublicKey.') as Error & {
        errors?: string[];
      };
      error.errors = errors;
      throw error;
    }

    return this.setPublicKey(
      new BigInteger(new ByteStringBuffer(rsaKeyCapture.publicKeyModulus).toHex(), 16),
      new BigInteger(new ByteStringBuffer(rsaKeyCapture.publicKeyExponent).toHex(), 16)
    );
  }

  publicKeyToSubjectPublicKeyInfo(key: RsaPublicKey): Asn1Object {
    const asn1 = this.#asn1;
    return this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        this.#createAsn1(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(this.#oids.rsaEncryption).getBytes()
        ),
        this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
      ]),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [this.publicKeyToRSAPublicKey(key)])
    ]);
  }

  publicKeyToRSAPublicKey(key: RsaPublicKey): Asn1Object {
    const asn1 = this.#asn1;
    return this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.n)),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, bnToBytes(key.e))
    ]);
  }

  createCertkitNamespace(): CertkitRsaNamespace {
    const service = this;
    const rsa: Record<string, unknown> = {
      encrypt: service.encrypt.bind(service),
      decrypt: service.decrypt.bind(service),
      createKeyPairGenerationState: service.createKeyPairGenerationState.bind(service),
      stepKeyPairGenerationState: service.stepKeyPairGenerationState.bind(service),
      generateKeyPair: service.generateKeyPair.bind(service),
      setPublicKey: service.setPublicKey.bind(service),
      setPrivateKey: service.setPrivateKey.bind(service),
      publicKeyValidator: service.publicKeyValidator
    };
    return rsa as CertkitRsaNamespace;
  }

  attachToPki(pki: Partial<CertkitPki>): void {
    const rsa = this.createCertkitNamespace();
    pki.rsa = rsa;
    pki.setRsaPublicKey = this.setPublicKey.bind(this);
    pki.setRsaPrivateKey = this.setPrivateKey.bind(this) as CertkitPki['setRsaPrivateKey'];
    pki.wrapRsaPrivateKey = this.wrapRsaPrivateKey.bind(this);
    pki.privateKeyFromAsn1 = this.privateKeyFromAsn1.bind(this);
    pki.privateKeyToAsn1 = this.privateKeyToRSAPrivateKey.bind(this);
    pki.privateKeyToRSAPrivateKey = this.privateKeyToRSAPrivateKey.bind(this);
    pki.publicKeyFromAsn1 = this.publicKeyFromAsn1.bind(this);
    pki.publicKeyToAsn1 = this.publicKeyToSubjectPublicKeyInfo.bind(this);
    pki.publicKeyToSubjectPublicKeyInfo = this.publicKeyToSubjectPublicKeyInfo.bind(this);
    pki.publicKeyToRSAPublicKey = this.publicKeyToRSAPublicKey.bind(this);
  }
}

export default RsaService;

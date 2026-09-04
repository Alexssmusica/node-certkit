/* eslint-disable @typescript-eslint/no-this-alias -- legacy node-forge RSA key POJO pattern */
import type { Asn1Object, Asn1Validator } from '../asn1/Asn1Types.js';
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
import type { CertkitRsaNamespace } from './CertkitPkiTypes.js';

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

function bnToBytes(b: BigInteger): string {
  let hex = b.toString(16);
  if (hex[0]! >= '8') {
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

  #createAsn1(tagClass: number, type: number, constructed: boolean, value: unknown): Asn1Object {
    return this.#asn1.create(tagClass, type, constructed, value, null) as Asn1Object;
  }

  createDefaultPemKeyCodec(): PemKeyCodec {
    const self = this;
    return {
      privateKeyFromPem(pem: string) {
        const msg = PemCodec.decode(pem)[0]!;
        if (msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
          const error = new Error(
            'Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".'
          ) as Error & {
            headerType?: string;
          };
          error.headerType = msg.type;
          throw error;
        }
        if (msg.procType?.type === 'ENCRYPTED') {
          throw new Error('Could not convert private key from PEM; PEM is encrypted.');
        }
        const obj = self.#asn1.fromDer(msg.body, {});
        return self.privateKeyFromAsn1(obj);
      },
      publicKeyFromPem(pem: string) {
        const msg = PemCodec.decode(pem)[0]!;
        if (msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
          const error = new Error(
            'Could not convert public key from PEM; PEM header type is not "PUBLIC KEY" or "RSA PUBLIC KEY".'
          ) as Error & {
            headerType?: string;
          };
          error.headerType = msg.type;
          throw error;
        }
        if (msg.procType?.type === 'ENCRYPTED') {
          throw new Error('Could not convert public key from PEM; PEM is encrypted.');
        }
        const obj = self.#asn1.fromDer(msg.body, {});
        return self.publicKeyFromAsn1(obj);
      }
    };
  }

  #getPemKeyCodec(): PemKeyCodec {
    if (!this.#pemKeyCodec) {
      this.#pemKeyCodec = this.createDefaultPemKeyCodec();
    }
    return this.#pemKeyCodec;
  }

  #emsaPkcs1v15encode(md: { algorithm: string; digest(): ByteStringBuffer }): string {
    const asn1 = this.#asn1;
    let oid: string;
    if (md.algorithm in this.#oids) {
      oid = this.#oids[md.algorithm]!;
    } else {
      const error = new Error('Unknown message digest algorithm.') as Error & { algorithm?: string };
      error.algorithm = md.algorithm;
      throw error;
    }
    const oidBytes = asn1.oidToDer(oid).getBytes();
    const digestInfo = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
    const digestAlgorithm = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
    (digestAlgorithm.value as Asn1Object[]).push(
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OID, false, oidBytes)
    );
    (digestAlgorithm.value as Asn1Object[]).push(this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''));
    const digest = this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, md.digest().getBytes());
    (digestInfo.value as Asn1Object[]).push(digestAlgorithm);
    (digestInfo.value as Asn1Object[]).push(digest);
    return asn1.toDer(digestInfo).getBytes();
  }

  #modPow(x: BigInteger, key: RsaKeyMaterial, pub: boolean): BigInteger {
    if (pub) {
      return x.modPow(key.e, key.n);
    }

    if (!key.p || !key.q) {
      return x.modPow(key.d!, key.n);
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

    let r: BigInteger;
    do {
      r = new BigInteger(UtilNamespace.bytesToHex(this.#random.getBytesSync(key.n.bitLength() / 8)), 16);
    } while (r.compareTo(key.n) >= 0 || !r.gcd(key.n).equals(BigInteger.ONE));
    x = x.multiply(r.modPow(key.e, key.n)).mod(key.n);

    let xp = x.mod(key.p).modPow(key.dP, key.p);
    const xq = x.mod(key.q).modPow(key.dQ, key.q);

    while (xp.compareTo(xq) < 0) {
      xp = xp.add(key.p);
    }

    let y = xp.subtract(xq).multiply(key.qInv).mod(key.p).multiply(key.q).add(xq);
    y = y.multiply(r.modInverse(key.n)).mod(key.n);
    return y;
  }

  #encodePkcs1v15(m: string, key: RsaKeyMaterial, bt: number): ByteStringBuffer {
    const eb = new ByteStringBuffer();
    const k = Math.ceil(key.n.bitLength() / 8);

    if (m.length > k - 11) {
      const error = new Error('Message is too long for PKCS#1 v1.5 padding.') as Error & {
        length?: number;
        max?: number;
      };
      error.length = m.length;
      error.max = k - 11;
      throw error;
    }

    eb.putByte(0x00);
    eb.putByte(bt);

    let padNum = k - 3 - m.length;
    if (bt === 0x00 || bt === 0x01) {
      const padByte = bt === 0x00 ? 0x00 : 0xff;
      for (let i = 0; i < padNum; ++i) {
        eb.putByte(padByte);
      }
    } else {
      while (padNum > 0) {
        let numZeros = 0;
        const padBytes = this.#random.getBytes(padNum);
        for (let i = 0; i < padNum; ++i) {
          const padByte = padBytes.charCodeAt(i);
          if (padByte === 0) {
            ++numZeros;
          } else {
            eb.putByte(padByte);
          }
        }
        padNum = numZeros;
      }
    }

    eb.putByte(0x00);
    eb.putBytes(m);
    return eb;
  }

  #decodePkcs1v15(
    em: string,
    key: RsaKeyMaterial,
    pub: boolean,
    ml?: number | false,
    options?: { _skipPaddingChecks?: boolean }
  ): string {
    const k = Math.ceil(key.n.bitLength() / 8);
    const eb = new ByteStringBuffer(em);
    const first = eb.getByte();
    const bt = eb.getByte();
    if (
      first !== 0x00 ||
      (pub && bt !== 0x00 && bt !== 0x01) ||
      (!pub && bt !== 0x02) ||
      (pub && bt === 0x00 && typeof ml === 'undefined')
    ) {
      throw new Error('Encryption block is invalid.');
    }

    let padNum = 0;
    if (bt === 0x00) {
      padNum = k - 3 - (ml as number);
      for (let i = 0; i < padNum; ++i) {
        if (eb.getByte() !== 0x00) {
          throw new Error('Encryption block is invalid.');
        }
      }
    } else if (bt === 0x01) {
      padNum = 0;
      while (eb.length() > 1) {
        if (eb.getByte() !== 0xff) {
          --eb.read;
          break;
        }
        ++padNum;
      }
      if (padNum < 8 && !options?._skipPaddingChecks) {
        throw new Error('Encryption block is invalid.');
      }
    } else if (bt === 0x02) {
      padNum = 0;
      while (eb.length() > 1) {
        if (eb.getByte() === 0x00) {
          --eb.read;
          break;
        }
        ++padNum;
      }
      if (padNum < 8 && !options?._skipPaddingChecks) {
        throw new Error('Encryption block is invalid.');
      }
    }

    const zero = eb.getByte();
    if (zero !== 0x00 || padNum !== k - 3 - eb.length()) {
      throw new Error('Encryption block is invalid.');
    }

    return eb.getBytes();
  }

  encrypt(m: string, key: RsaKeyMaterial, bt: boolean | number): string {
    let pub = bt;
    let eb: ByteStringBuffer;

    const k = Math.ceil(key.n.bitLength() / 8);

    if (bt !== false && bt !== true) {
      pub = bt === 0x02;
      eb = this.#encodePkcs1v15(m, key, bt as number);
    } else {
      eb = new ByteStringBuffer();
      eb.putBytes(m);
    }

    const x = new BigInteger(eb.toHex(), 16);
    const y = this.#modPow(x, key, pub as boolean);
    const yhex = y.toString(16);
    const ed = new ByteStringBuffer();
    let zeros = k - Math.ceil(yhex.length / 2);
    while (zeros > 0) {
      ed.putByte(0x00);
      --zeros;
    }
    ed.putBytes(UtilNamespace.hexToBytes(yhex));
    return ed.getBytes();
  }

  decrypt(ed: string, key: RsaKeyMaterial, pub: boolean, ml?: boolean | number): string {
    const k = Math.ceil(key.n.bitLength() / 8);

    if (ed.length !== k) {
      const error = new Error('Encrypted message length is invalid.') as Error & {
        length?: number;
        expected?: number;
      };
      error.length = ed.length;
      error.expected = k;
      throw error;
    }

    const y = new BigInteger(new ByteStringBuffer(ed).toHex(), 16);
    if (y.compareTo(key.n) >= 0) {
      throw new Error('Encrypted message is invalid.');
    }

    const x = this.#modPow(y, key, pub);
    const xhex = x.toString(16);
    const eb = new ByteStringBuffer();
    let zeros = k - Math.ceil(xhex.length / 2);
    while (zeros > 0) {
      eb.putByte(0x00);
      --zeros;
    }
    eb.putBytes(UtilNamespace.hexToBytes(xhex));

    if (ml !== false) {
      return this.#decodePkcs1v15(eb.getBytes(), key, pub);
    }
    return eb.getBytes();
  }

  setPublicKey(n: BigInteger, e: BigInteger): RsaPublicKey {
    const service = this;
    const key = { n, e } as RsaPublicKey;

    key.encrypt = function (data, scheme, schemeOptions) {
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      } else if (scheme === undefined) {
        scheme = 'RSAES-PKCS1-V1_5';
      }

      let schemeObj: { encode: (m: string, key: RsaKeyMaterial, pub?: boolean) => string };
      if (scheme === 'RSAES-PKCS1-V1_5') {
        schemeObj = {
          encode(m, k) {
            return service.#encodePkcs1v15(m, k, 0x02).getBytes();
          }
        };
      } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
        schemeObj = {
          encode(m, k) {
            return Pkcs1Codec.encodeRsaOaep(
              k,
              m,
              schemeOptions as Parameters<typeof Pkcs1Codec.encodeRsaOaep>[2],
              undefined,
              undefined,
              (count) => service.#random.getBytesSync(count)
            );
          }
        };
      } else if (['RAW', 'NONE', 'NULL', null].indexOf(scheme as string | null) !== -1) {
        schemeObj = {
          encode(e) {
            return e;
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

      let schemeObj: { verify: (digest: string, d: string, modBits?: number) => boolean };
      if (scheme === 'RSASSA-PKCS1-V1_5') {
        schemeObj = {
          verify(dig, d) {
            d = service.#decodePkcs1v15(d, key, true, undefined, verifyOptions);
            const obj = service.#asn1.fromDer(d, { parseAllBytes: verifyOptions._parseAllDigestBytes });
            const capture: Record<string, string> = {};
            const errors: unknown[] = [];
            if (
              !service.#asn1.validate(obj, service.digestInfoValidator, capture, errors) ||
              !Array.isArray((obj as Asn1Object).value) ||
              ((obj as Asn1Object).value as unknown[]).length !== 2
            ) {
              const error = new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value.'
              ) as Error & {
                errors?: unknown[];
              };
              error.errors = errors;
              throw error;
            }
            const oid = service.#asn1.derToOid(capture.algorithmIdentifier!);
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
            return constantTimeEquals(dig, capture.digest!);
          }
        };
      } else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
        schemeObj = {
          verify(dig, d) {
            d = service.#decodePkcs1v15(d, key, true, undefined, verifyOptions);
            return dig === d;
          }
        };
      } else {
        schemeObj = scheme as typeof schemeObj;
      }

      const d = service.decrypt(signature, key, true, false);
      return schemeObj.verify(digest, d, key.n.bitLength());
    };

    return key;
  }

  setPrivateKey(
    n: BigInteger,
    e: BigInteger,
    d: BigInteger,
    p: BigInteger,
    q: BigInteger,
    dP: BigInteger,
    dQ: BigInteger,
    qInv: BigInteger
  ): RsaPrivateKey {
    const service = this;
    const key = { n, e, d, p, q, dP, dQ, qInv } as RsaPrivateKey;

    key.decrypt = function (data, scheme, schemeOptions) {
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      } else if (scheme === undefined) {
        scheme = 'RSAES-PKCS1-V1_5';
      }

      const decrypted = service.decrypt(data, key, false, false);

      let schemeObj: { decode: (d: string, key: RsaKeyMaterial, pub?: boolean) => string };
      if (scheme === 'RSAES-PKCS1-V1_5') {
        schemeObj = { decode: (d, k, pub) => service.#decodePkcs1v15(d, k, pub!) };
      } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
        schemeObj = {
          decode(d, k) {
            return Pkcs1Codec.decodeRsaOaep(k, d, schemeOptions as Parameters<typeof Pkcs1Codec.decodeRsaOaep>[2]);
          }
        };
      } else if (['RAW', 'NONE', 'NULL', null].indexOf(scheme as string | null) !== -1) {
        schemeObj = {
          decode(d) {
            return d;
          }
        };
      } else {
        throw new Error('Unsupported encryption scheme: "' + scheme + '".');
      }

      return schemeObj.decode(decrypted, key, false);
    };

    key.sign = function (md, scheme) {
      let bt: boolean | number = false;
      if (typeof scheme === 'string') {
        scheme = scheme.toUpperCase();
      }

      let schemeObj: { encode: (md: unknown, modBits?: number) => string };
      if (scheme === undefined || scheme === 'RSASSA-PKCS1-V1_5') {
        schemeObj = {
          encode: (m) => service.#emsaPkcs1v15encode(m as { algorithm: string; digest(): ByteStringBuffer })
        };
        bt = 0x01;
      } else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
        schemeObj = { encode: () => md as string };
        bt = 0x01;
      } else {
        schemeObj = scheme as typeof schemeObj;
      }

      const d = schemeObj.encode(md, key.n.bitLength());
      return service.encrypt(d, key, bt);
    };

    return key;
  }

  createKeyPairGenerationState(
    bits?: number | string,
    e?: number,
    options?: Record<string, unknown>
  ): KeyPairGenerationState {
    if (typeof bits === 'string') {
      bits = parseInt(bits, 10);
    }
    bits = bits || 2048;

    options = options || {};
    const prng = (options.prng as { getBytesSync(count: number): string }) || this.#random;
    const rng: BigIntegerRandomSource = {
      nextBytes(x: number[]): void {
        const b = prng.getBytesSync(x.length);
        for (let i = 0; i < x.length; ++i) {
          x[i] = b.charCodeAt(i);
        }
      }
    };

    const algorithm = options.algorithm || 'PRIMEINC';
    if (algorithm === 'PRIMEINC') {
      const rval: KeyPairGenerationState = {
        algorithm,
        state: 0,
        bits,
        rng,
        eInt: e || 65537,
        e: new BigInteger(null),
        p: null,
        q: null,
        qBits: (bits as number) >> 1,
        pBits: (bits as number) - ((bits as number) >> 1),
        pqState: 0,
        num: null,
        keys: null
      };
      (rval.e as BigInteger).fromInt(rval.eInt as number);
      return rval;
    }
    throw new Error('Invalid key generation algorithm: ' + algorithm);
  }

  stepKeyPairGenerationState(state: KeyPairGenerationState, n: number): boolean {
    if (!('algorithm' in state)) {
      state.algorithm = 'PRIMEINC';
    }

    const THIRTY = new BigInteger(null);
    THIRTY.fromInt(30);
    let deltaIdx = 0;
    const op_or = (x: number, y: number) => x | y;

    let t1 = +new Date();
    let t2: number;
    let total = 0;
    while (state.keys === null && (n <= 0 || total < n)) {
      if (state.state === 0) {
        const bits = state.p === null ? state.pBits : state.qBits;
        const bits1 = (bits as number) - 1;

        if (state.pqState === 0) {
          state.num = new BigInteger(bits as number, state.rng as BigIntegerRandomSource);
          if (!(state.num as BigInteger).testBit(bits1)) {
            (state.num as BigInteger).bitwiseTo(BigInteger.ONE.shiftLeft(bits1), op_or, state.num as BigInteger);
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
        const d = (state.e as BigInteger).modInverse(state.phi as BigInteger);
        state.keys = {
          privateKey: this.setPrivateKey(
            state.n as BigInteger,
            state.e as BigInteger,
            d,
            state.p as BigInteger,
            state.q as BigInteger,
            d.mod(state.p1 as BigInteger),
            d.mod(state.q1 as BigInteger),
            (state.q as BigInteger).modInverse(state.p as BigInteger)
          ),
          publicKey: this.setPublicKey(state.n as BigInteger, state.e as BigInteger)
        };
      }

      t2 = +new Date();
      total += t2 - t1;
      t1 = t2;
    }

    return state.keys !== null;
  }

  generateKeyPair(bits?: unknown, e?: unknown, options?: unknown, callback?: unknown): RsaKeyPair | void {
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
        if (typeof e === 'function') {
          callback = e;
          e = undefined;
        } else if (typeof e !== 'number') {
          options = e;
          e = undefined;
        }
      } else {
        options = bits;
        callback = e;
        bits = undefined;
        e = undefined;
      }
    } else if (arguments.length === 3) {
      if (typeof e === 'number') {
        if (typeof options === 'function') {
          callback = options;
          options = undefined;
        }
      } else {
        callback = options;
        options = e;
        e = undefined;
      }
    }

    const opts = (options || {}) as Record<string, unknown>;
    if (bits === undefined) {
      bits = opts.bits || 2048;
    }
    if (e === undefined) {
      e = opts.e || 0x10001;
    }

    const pemCodec = this.#getPemKeyCodec();
    const nativeCrypto = this.#nativeCrypto;

    if (
      !this.#usePureJavaScript &&
      !opts.prng &&
      (bits as number) >= 256 &&
      (bits as number) <= 16384 &&
      (e === 0x10001 || e === 3)
    ) {
      if (callback) {
        if (nativeCrypto && typeof nativeCrypto.generateKeyPair === 'function') {
          return nativeCrypto.generateKeyPair(
            'rsa',
            {
              modulusLength: bits,
              publicExponent: e,
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            },
            (err, pub, priv) => {
              if (err) {
                return (callback as (err: Error | null) => void)(err);
              }
              (callback as (err: Error | null, keypair?: RsaKeyPair) => void)(null, {
                privateKey: pemCodec.privateKeyFromPem(priv) as RsaPrivateKey,
                publicKey: pemCodec.publicKeyFromPem(pub) as RsaPublicKey
              });
            }
          );
        }
      } else {
        if (nativeCrypto && typeof nativeCrypto.generateKeyPairSync === 'function') {
          const keypair = nativeCrypto.generateKeyPairSync('rsa', {
            modulusLength: bits,
            publicExponent: e,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
          });
          return {
            privateKey: pemCodec.privateKeyFromPem(keypair.privateKey) as RsaPrivateKey,
            publicKey: pemCodec.publicKeyFromPem(keypair.publicKey) as RsaPublicKey
          };
        }
      }
    }

    const state = this.createKeyPairGenerationState(bits as number, e as number, opts);
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

    function getPrime(bits: number, cb: (err: Error | null, num?: BigInteger) => void): void {
      service.#primeGenerator.generateProbablePrime(bits, opts, (err, num) => {
        cb(err, num as BigInteger | undefined);
      });
    }

    function finish(err: Error | null, num?: BigInteger): void {
      if (err) {
        return callback(err);
      }

      state.q = num;

      if ((state.p as BigInteger).compareTo(state.q as BigInteger) < 0) {
        const tmp = state.p;
        state.p = state.q;
        state.q = tmp;
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

      const d = (state.e as BigInteger).modInverse(state.phi as BigInteger);
      callback(null, {
        privateKey: service.setPrivateKey(
          state.n as BigInteger,
          state.e as BigInteger,
          d,
          state.p as BigInteger,
          state.q as BigInteger,
          d.mod(state.p1 as BigInteger),
          d.mod(state.q1 as BigInteger),
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
          asn1.oidToDer(this.#oids.rsaEncryption!).getBytes()
        ),
        this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
      ]),
      this.#createAsn1(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, asn1.toDer(rsaKey).getBytes())
    ]);
  }

  privateKeyFromAsn1(obj: Asn1Object): RsaPrivateKey {
    const asn1 = this.#asn1;
    let capture: Record<string, string> = {};
    let errors: unknown[] = [];
    if (asn1.validate(obj, this.privateKeyValidator, capture, errors)) {
      obj = asn1.fromDer(new ByteStringBuffer(capture.privateKey!), {}) as Asn1Object;
    }

    capture = {};
    errors = [];
    if (!asn1.validate(obj, this.rsaPrivateKeyValidator, capture, errors)) {
      const error = new Error('Cannot read private key. ASN.1 object does not contain an RSAPrivateKey.') as Error & {
        errors?: unknown[];
      };
      error.errors = errors;
      throw error;
    }

    return this.setPrivateKey(
      new BigInteger(new ByteStringBuffer(capture.privateKeyModulus!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPublicExponent!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrivateExponent!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrime1!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyPrime2!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyExponent1!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyExponent2!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(capture.privateKeyCoefficient!).toHex(), 16)
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

  publicKeyFromAsn1(obj: Asn1Object): RsaPublicKey {
    const asn1 = this.#asn1;
    const capture: Record<string, unknown> = {};
    const errors: unknown[] = [];
    if (asn1.validate(obj, this.publicKeyValidator, capture, errors)) {
      const oid = asn1.derToOid(capture.publicKeyOid as string);
      if (oid !== this.#oids.rsaEncryption) {
        const error = new Error('Cannot read public key. Unknown OID.') as Error & { oid?: string };
        error.oid = oid;
        throw error;
      }
      obj = capture.rsaPublicKey as Asn1Object;
    }

    const cap: Record<string, string> = {};
    if (!asn1.validate(obj, this.rsaPublicKeyValidator, cap, errors)) {
      const error = new Error('Cannot read public key. ASN.1 object does not contain an RSAPublicKey.') as Error & {
        errors?: unknown[];
      };
      error.errors = errors;
      throw error;
    }

    return this.setPublicKey(
      new BigInteger(new ByteStringBuffer(cap.publicKeyModulus!).toHex(), 16),
      new BigInteger(new ByteStringBuffer(cap.publicKeyExponent!).toHex(), 16)
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
          asn1.oidToDer(this.#oids.rsaEncryption!).getBytes()
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

  attachToPki(pki: Record<string, unknown>): void {
    const rsa = this.createCertkitNamespace();
    pki.rsa = rsa;
    pki.setRsaPublicKey = this.setPublicKey.bind(this);
    pki.setRsaPrivateKey = this.setPrivateKey.bind(this);
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

import type {Asn1NamespaceObject} from '../asn1/Asn1Types.js';
import type {BigInteger} from '../math/BigInteger.js';
import type {NativeCryptoProvider, PemKeyCodec, PrimeGenerator} from '../ports/index.js';

export type RsaKeyMaterial = {
  n: BigInteger;
  e: BigInteger;
  d?: BigInteger;
  p?: BigInteger;
  q?: BigInteger;
  dP?: BigInteger;
  dQ?: BigInteger;
  qInv?: BigInteger;
};

export type RsaPublicKey = RsaKeyMaterial & {
  encrypt: (data: string, scheme?: unknown, schemeOptions?: unknown) => string;
  verify: (digest: string, signature: string, scheme?: unknown, options?: unknown) => boolean;
};

export type RsaPrivateKey = RsaKeyMaterial & {
  d: BigInteger;
  decrypt: (data: string, scheme?: unknown, schemeOptions?: unknown) => string;
  sign: (md: unknown, scheme?: unknown) => string;
};

export type RsaKeyPair = {
  publicKey: RsaPublicKey;
  privateKey: RsaPrivateKey;
};

export type KeyPairGenerationState = Record<string, unknown>;

export type RsaServiceDeps = {
  oids: Record<string, string>;
  asn1: Asn1NamespaceObject;
  random: {getBytesSync(count: number): string; getBytes(count: number): string};
  primeGenerator: PrimeGenerator;
  nativeCrypto?: NativeCryptoProvider | null;
  pemKeyCodec?: PemKeyCodec | null;
  usePureJavaScript?: boolean;
};

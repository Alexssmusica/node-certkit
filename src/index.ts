import type { Asn1Object } from './domain/asn1/Asn1Types.js';
import type { ByteStringBuffer } from './domain/buffer/ByteStringBuffer.js';
import type {
  Pkcs12Bag as Pkcs12BagType,
  Pkcs12BagsFilter as Pkcs12BagsFilterType,
  Pkcs12Bags as Pkcs12BagsType,
  Pkcs12CreateOptions as Pkcs12CreateOptionsType,
  Pkcs12Pfx as Pkcs12PfxType
} from './domain/pki/Pkcs12Types.js';
import type { RsaKeyPair, RsaPrivateKey, RsaPublicKey } from './domain/pki/RsaTypes.js';
import type {
  DnAttribute as DnAttributeType,
  X509CaStore,
  X509Certificate,
  X509CertificationRequest
} from './domain/pki/x509/X509Types.js';
import certkitInstance, { createCertkit } from './presentation/index.js';

export namespace certkit {
  export namespace pkcs12 {
    export type Pkcs12Pfx = Pkcs12PfxType;
    export type Bag = Pkcs12BagType;
    export type Bags = Pkcs12BagsType;
    export type BagsFilter = Pkcs12BagsFilterType;
    export type CreateOptions = Pkcs12CreateOptionsType;
  }

  export namespace pki {
    export type Certificate = X509Certificate;
    export type CertificationRequest = X509CertificationRequest;
    export type PrivateKey = RsaPrivateKey;
    export type PublicKey = RsaPublicKey;
    export type CAStore = X509CaStore;
    export type DnAttribute = DnAttributeType;

    export namespace rsa {
      export type PrivateKey = RsaPrivateKey;
      export type PublicKey = RsaPublicKey;
      export type KeyPair = RsaKeyPair;
    }
  }

  export namespace asn1 {
    export type Asn1 = Asn1Object;
  }

  export namespace util {
    export type ByteBuffer = ByteStringBuffer;
  }
}

export { certkitInstance as certkit, createCertkit };
export default certkitInstance;
export type { Asn1Object } from './domain/asn1/Asn1Types.js';
export type { ByteStringBuffer } from './domain/buffer/ByteStringBuffer.js';
export type {
  Pkcs12Bag,
  Pkcs12Bags,
  Pkcs12BagsFilter,
  Pkcs12CreateOptions,
  Pkcs12Pfx
} from './domain/pki/Pkcs12Types.js';
export type { RsaKeyPair, RsaPrivateKey, RsaPublicKey } from './domain/pki/RsaTypes.js';
export type {
  DnAttribute,
  X509CaStore,
  X509Certificate,
  X509CertificationRequest,
  X509Extension
} from './domain/pki/x509/X509Types.js';
export type { Certkit } from './presentation/createCertkit.js';

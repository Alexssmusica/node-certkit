import type {Md5Digest} from './Md5.js';
import type {Sha1Digest} from './Sha1.js';
import type {Sha256Digest} from './Sha256.js';
import type {Sha512Digest} from './Sha512.js';

export type DigestFactory<T = unknown> = {
  create: () => T;
};

export type MdRegistry = {
  algorithms: Record<string, DigestFactory>;
  md5: DigestFactory<Md5Digest>;
  sha1: DigestFactory<Sha1Digest>;
  sha256: DigestFactory<Sha256Digest>;
  sha384: DigestFactory<Sha512Digest>;
  sha512: DigestFactory<Sha512Digest>;
  'sha512/256': DigestFactory<Sha512Digest>;
  'sha512/224': DigestFactory<Sha512Digest>;
};

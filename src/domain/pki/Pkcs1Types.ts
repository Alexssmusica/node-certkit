import type { MessageDigest } from './MgfTypes.js';

export type RsaOaepKey = {
  n: { bitLength(): number };
};

export type RsaOaepOptions = {
  label?: string;
  seed?: string;
  md?: MessageDigest;
  mgf1?: { md?: MessageDigest };
};

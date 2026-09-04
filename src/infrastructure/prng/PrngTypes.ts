type MessageDigestInstance = {
  messageLength: number;
  start: () => void;
  update: (bytes: string) => void;
  digest: () => { getBytes: () => string };
};

export type PrngPlugin = {
  md: {
    create: () => MessageDigestInstance;
  };
  cipher: (key: unknown, seed: unknown) => string;
  increment: (seed: unknown) => unknown;
  formatKey: (keyBytes: string) => unknown;
  formatSeed: (seedBytes: string) => unknown;
};

export type PrngContext = {
  plugin: PrngPlugin;
  key: unknown;
  seed: unknown;
  time: unknown;
  reseeds: number;
  generated: number;
  keyBytes: string;
  pools: MessageDigestInstance[];
  pool: number;
  generate: (count: number, callback?: (err: Error | null, bytes?: string) => void) => string | void;
  generateSync: (count: number) => string;
  seedFile: (needed: number, callback: (err: Error | null, bytes?: string) => void) => void;
  seedFileSync: (needed: number) => string;
  collect: (bytes: string) => void;
  collectInt: (i: number, n: number) => void;
};

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
  cipher: (key: number[], seed: number[]) => string;
  increment: (seed: number[]) => number[];
  formatKey: (keyBytes: string) => number[];
  formatSeed: (seedBytes: string) => number[];
};

export type PrngContext = {
  plugin: PrngPlugin;
  key: number[] | null;
  seed: number[] | null;
  time: null;
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

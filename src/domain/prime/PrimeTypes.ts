export type PrimeGenerateOptions = Record<string, unknown> & {
  algorithm?: string | { name: string; options?: Record<string, unknown> };
  prng?: { getBytesSync(count: number): string };
};

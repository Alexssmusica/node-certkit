import type { ByteStringBuffer } from './ByteStringBuffer.js';

export type ByteStringBufferInput =
  string | ArrayBuffer | ArrayBufferView | Buffer | ByteStringBuffer | { data: string; read: number };

export interface DataBufferOptions {
  readOffset?: number;
  writeOffset?: number;
  growSize?: number;
  encoding?: string;
}

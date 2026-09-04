export function isArray(x: unknown): x is unknown[] {
  return Array.isArray(x) || Object.prototype.toString.call(x) === '[object Array]';
}

export function isArrayBuffer(x: unknown): x is ArrayBuffer {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
}

export function isArrayBufferView(x: unknown): x is ArrayBufferView {
  return !!x && isArrayBuffer((x as ArrayBufferView).buffer) &&
    (x as ArrayBufferView).byteLength !== undefined;
}

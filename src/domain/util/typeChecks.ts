export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value) || Object.prototype.toString.call(value) === '[object Array]';
}

export function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer;
}

export function isArrayBufferView(value: unknown): value is ArrayBufferView {
  return (
    !!value && isArrayBuffer((value as ArrayBufferView).buffer) && (value as ArrayBufferView).byteLength !== undefined
  );
}

export function encodeUtf8(str: string): string {
  return unescape(encodeURIComponent(str));
}

export function decodeUtf8(str: string): string {
  return decodeURIComponent(escape(str));
}

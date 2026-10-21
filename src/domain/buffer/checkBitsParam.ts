export function checkBitsParam(bits: number): void {
  if (!(bits === 8 || bits === 16 || bits === 24 || bits === 32)) {
    throw new Error('Only 8, 16, 24, or 32 bits supported: ' + bits);
  }
}

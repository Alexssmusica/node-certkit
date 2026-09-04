import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from 'vitest';
import certkit from '../../src/presentation/index.js';
const UTIL = certkit.util;
const bytesFromIP = UTIL.bytesFromIP as (addr: string) => string;
const bytesToIP = UTIL.bytesToIP as (bytes: string) => string;
// custom assertion to test array-like objects
function assertArrayEqual(actual: ArrayLike<unknown>, expected: ArrayLike<unknown>) {
  expect(actual.length).toBe(expected.length);
  for (let idx = 0; idx < expected.length; idx++) {
    expect(actual[idx]).toBe(expected[idx]);
  }
}

describe('util', () => {
  it('should put bytes into a buffer', (ctx) => {
    const b = UTIL.createBuffer();
    b.putByte(1);
    b.putByte(2);
    b.putByte(3);
    b.putByte(4);
    b.putInt32(4);
    b.putByte(1);
    b.putByte(2);
    b.putByte(3);
    b.putInt32(4294967295);
    const hex = b.toHex();
    expect(hex).toBe('0102030400000004010203ffffffff');

    const bytes = [];
    while (b.length() > 0) {
      bytes.push(b.getByte());
    }
    expect(bytes).toEqual([1, 2, 3, 4, 0, 0, 0, 4, 1, 2, 3, 255, 255, 255, 255]);
  });

  it('should put bytes from an Uint8Array into a buffer', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const data = [1, 2, 3, 4, 0, 0, 0, 4, 1, 2, 3, 255, 255, 255, 255];
    const ab = new Uint8Array(data);
    const b = UTIL.createBuffer(ab);
    const hex = b.toHex();
    expect(hex).toBe('0102030400000004010203ffffffff');

    const bytes = [];
    while (b.length() > 0) {
      bytes.push(b.getByte());
    }
    expect(bytes).toEqual(data);
  });

  it('should convert bytes from hex', (ctx) => {
    const hex = '0102030400000004010203ffffffff';
    const b = UTIL.createBuffer();
    b.putBytes(UTIL.hexToBytes(hex));
    expect(b.toHex()).toBe(hex);
  });

  it("should put 0 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(0, 8);
    expect(b.toHex()).toBe('00');
  });

  it("should put 0 into a buffer using two's complement w/2 bytes", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(0, 16);
    expect(b.toHex()).toBe('0000');
  });

  it("should put 127 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(127, 8);
    expect(b.toHex()).toBe('7f');
  });

  it("should put 127 into a buffer using two's complement w/2 bytes", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(127, 16);
    expect(b.toHex()).toBe('007f');
  });

  it("should put 128 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(128, 16);
    expect(b.toHex()).toBe('0080');
  });

  it("should put 256 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(256, 16);
    expect(b.toHex()).toBe('0100');
  });

  it("should put -128 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(-128, 8);
    expect(b.toHex()).toBe('80');
  });

  it("should put -129 into a buffer using two's complement", (ctx) => {
    const b = UTIL.createBuffer();
    b.putSignedInt(-129, 16);
    expect(b.toHex()).toBe('ff7f');
  });

  it("should get 0 from a buffer using two's complement", (ctx) => {
    const x = 0;
    const n = 8;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it("should get 127 from a buffer using two's complement", (ctx) => {
    const x = 127;
    const n = 8;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it("should get 128 from a buffer using two's complement", (ctx) => {
    const x = 128;
    const n = 16;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it("should get 256 from a buffer using two's complement", (ctx) => {
    const x = 256;
    const n = 16;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it("should get -128 from a buffer using two's complement", (ctx) => {
    const x = -128;
    const n = 8;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it("should get -129 from a buffer using two's complement", (ctx) => {
    const x = -129;
    const n = 16;
    const b = UTIL.createBuffer();
    b.putSignedInt(x, n);
    expect(b.getSignedInt(n)).toBe(x);
  });

  it('should getInt(8) from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('12'));
    expect(b.getInt(8)).toBe(0x12);
    expect(b.length()).toBe(0);
  });

  it('should getInt(8)x2 from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('1221'));
    expect(b.getInt(8)).toBe(0x12);
    expect(b.getInt(8)).toBe(0x21);
    expect(b.length()).toBe(0);
  });

  it('should getInt(16) from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('1234'));
    expect(b.getInt(16)).toBe(0x1234);
    expect(b.length()).toBe(0);
  });

  it('should getInt(16)x2 from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('12344321'));
    expect(b.getInt(16)).toBe(0x1234);
    expect(b.getInt(16)).toBe(0x4321);
    expect(b.length()).toBe(0);
  });

  it('should getInt(24) from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('123456'));
    expect(b.getInt(24)).toBe(0x123456);
    expect(b.length()).toBe(0);
  });

  it('should getInt(24)x2 from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('123456654321'));
    expect(b.getInt(24)).toBe(0x123456);
    expect(b.getInt(24)).toBe(0x654321);
    expect(b.length()).toBe(0);
  });

  it('should getInt(32) from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('12345678'));
    expect(b.getInt(32)).toBe(0x12345678);
    expect(b.length()).toBe(0);
  });

  it('should getInt(32)x2 from buffer', (ctx) => {
    const b = UTIL.createBuffer(UTIL.hexToBytes('1234567887654321'));
    expect(b.getInt(32)).toBe(0x12345678);
    // FIXME: getInt bit shifts create signed int
    expect(b.getInt(32)).toBe(0x87654321 << 0);
    expect(b.length()).toBe(0);
  });

  it('should throw for getInt(1) from buffer', (ctx) => {
    const b = UTIL.createBuffer();
    expect(() => {
      b.getInt(1);
    }).toThrow();
  });

  it('should throw for getInt(33) from buffer', (ctx) => {
    const b = UTIL.createBuffer();
    expect(() => {
      b.getInt(33);
    }).toThrow();
  });

  // TODO: add get/put tests at limits of signed/unsigned types

  it('should base64 encode some bytes', (ctx) => {
    const s1 = '00010203050607080A0B0C0D0F1011121415161719';
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
    expect(UTIL.encode64(s1)).toBe(s2);
  });

  it('should base64 decode some bytes', (ctx) => {
    const s1 = '00010203050607080A0B0C0D0F1011121415161719';
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
    expect(UTIL.decode64(s2)).toBe(s1);
  });

  it('should base64 encode some bytes using util.binary.base64', (ctx) => {
    const s1 = new Uint8Array([
      0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41, 0x30,
      0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36,
      0x31, 0x37, 0x31, 0x39
    ]);
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
    expect(UTIL.binary.base64.encode(s1)).toBe(s2);
  });

  it('should base64 encode some odd-length bytes using util.binary.base64', (ctx) => {
    const s1 = new Uint8Array([
      0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41, 0x30,
      0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36,
      0x31, 0x37, 0x31, 0x39, 0x31, 0x41, 0x31, 0x42
    ]);
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5MUExQg==';
    expect(UTIL.binary.base64.encode(s1)).toBe(s2);
  });

  it('should base64 decode some bytes using util.binary.base64', (ctx) => {
    const s1 = new Uint8Array([
      0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41, 0x30,
      0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36,
      0x31, 0x37, 0x31, 0x39
    ]);
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
    expect(UTIL.binary.base64.decode(s2)).toEqual(s1);
  });

  it('should base64 decode some odd-length bytes using util.binary.base64', (ctx) => {
    const s1 = new Uint8Array([
      0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41, 0x30,
      0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36,
      0x31, 0x37, 0x31, 0x39, 0x31, 0x41, 0x31, 0x42
    ]);
    const s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5MUExQg==';
    assertArrayEqual(UTIL.binary.base64.decode(s2), s1);
  });

  it('should base58 encode some bytes', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const buffer = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const encoded = UTIL.binary.base58.encode(buffer);
    expect(encoded).toBe('13DUyZY2dc');
  });

  it('should base58 encode some bytes from a ByteBuffer', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const buffer = UTIL.createBuffer(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]));
    const encoded = UTIL.binary.base58.encode(buffer);
    expect(encoded).toBe('13DUyZY2dc');
  });

  it('should base58 decode some bytes', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const decoded = UTIL.binary.base58.decode('13DUyZY2dc');
    const buffer = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    expect(UTIL.createBuffer(decoded).toHex()).toBe(UTIL.createBuffer(buffer).toHex());
  });

  it('should base58 encode some bytes with whitespace', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const buffer = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const encoded = UTIL.binary.base58.encode(buffer, 4);
    expect(encoded).toBe('13DU\r\nyZY2\r\ndc');
  });

  it('should base58 decode some bytes with whitespace', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const decoded = UTIL.binary.base58.decode('13DU\r\nyZY2\r\ndc');
    const buffer = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    expect(UTIL.createBuffer(decoded).toHex()).toBe(UTIL.createBuffer(buffer).toHex());
  });

  it('should convert IPv4 0.0.0.0 textual address to 4-byte address', (ctx) => {
    const bytes = bytesFromIP('0.0.0.0');
    const b = UTIL.createBuffer().fillWithByte(0, 4);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv4 127.0.0.1 textual address to 4-byte address', (ctx) => {
    const bytes = bytesFromIP('127.0.0.1');
    const b = UTIL.createBuffer();
    b.putByte(127);
    b.putByte(0);
    b.putByte(0);
    b.putByte(1);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 :: textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('::');
    const b = UTIL.createBuffer().fillWithByte(0, 16);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 ::0 textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('::0');
    const b = UTIL.createBuffer().fillWithByte(0, 16);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 0:: textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('0::');
    const b = UTIL.createBuffer().fillWithByte(0, 16);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 ::1 textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('::1');
    const b = UTIL.createBuffer().fillWithByte(0, 14);
    b.putBytes(UTIL.hexToBytes('0001'));
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 1:: textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('1::');
    const b = UTIL.createBuffer();
    b.putBytes(UTIL.hexToBytes('0001'));
    b.fillWithByte(0, 14);
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 1::1 textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('1::1');
    const b = UTIL.createBuffer();
    b.putBytes(UTIL.hexToBytes('0001'));
    b.fillWithByte(0, 12);
    b.putBytes(UTIL.hexToBytes('0001'));
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 1::1:0 textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('1::1:0');
    const b = UTIL.createBuffer();
    b.putBytes(UTIL.hexToBytes('0001'));
    b.fillWithByte(0, 10);
    b.putBytes(UTIL.hexToBytes('0001'));
    b.putBytes(UTIL.hexToBytes('0000'));
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv6 2001:db8:0:1:1:1:1:1 textual address to 16-byte address', (ctx) => {
    const bytes = bytesFromIP('2001:db8:0:1:1:1:1:1');
    const b = UTIL.createBuffer();
    b.putBytes(UTIL.hexToBytes('2001'));
    b.putBytes(UTIL.hexToBytes('0db8'));
    b.putBytes(UTIL.hexToBytes('0000'));
    b.putBytes(UTIL.hexToBytes('0001'));
    b.putBytes(UTIL.hexToBytes('0001'));
    b.putBytes(UTIL.hexToBytes('0001'));
    b.putBytes(UTIL.hexToBytes('0001'));
    b.putBytes(UTIL.hexToBytes('0001'));
    expect(bytes).toBe(b.getBytes());
  });

  it('should convert IPv4 0.0.0.0 byte address to textual representation', (ctx) => {
    const bytes = UTIL.createBuffer().fillWithByte(0, 4).getBytes();
    const addr = bytesToIP(bytes);
    expect(addr).toBe('0.0.0.0');
  });

  it('should convert IPv4 0.0.0.0 byte address to textual representation', (ctx) => {
    const expected = '127.0.0.1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe(expected);
  });

  it('should convert IPv6 :: byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const bytes = UTIL.createBuffer().fillWithByte(0, 16).getBytes();
    const addr = bytesToIP(bytes);
    expect(addr).toBe('::');
  });

  it('should convert IPv6 ::1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '::1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe(expected);
  });

  it('should convert IPv6 1:: byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1::';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe(expected);
  });

  it('should convert IPv6 0:0:0:0:0:0:0:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '0:0:0:0:0:0:0:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('::1');
  });

  it('should convert IPv6 1:0:0:0:0:0:0:0 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1:0:0:0:0:0:0:0';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('1::');
  });

  it('should convert IPv6 1::1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1::1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe(expected);
  });

  it('should convert IPv6 1:0:0:0:0:0:0:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1:0:0:0:0:0:0:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('1::1');
  });

  it('should convert IPv6 1:0000:0000:0000:0000:0000:0000:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1:0000:0000:0000:0000:0000:0000:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('1::1');
  });

  it('should convert IPv6 1:0:0:1:1:1:0:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1:0:0:1:1:1:0:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('1::1:1:1:0:1');
  });

  it('should convert IPv6 1:0:1:1:1:0:0:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '1:0:1:1:1:0:0:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe('1:0:1:1:1::1');
  });

  it('should convert IPv6 2001:db8:0:1:1:1:1:1 byte address to canonical textual representation (RFC 5952)', (ctx) => {
    const expected = '2001:db8:0:1:1:1:1:1';
    const bytes = bytesFromIP(expected);
    const addr = bytesToIP(bytes);
    expect(addr).toBe(expected);
  });

  it('should convert "foo" to its UTF-8 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const result = UTIL.text.utf8.encode('foo') as Uint8Array;
    expect(result.byteLength).toBe(3);
    expect(result[0]).toBe(102);
    expect(result[1]).toBe(111);
    expect(result[2]).toBe(111);
  });

  it('should convert "foo" from its UTF-8 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const bytes = new Uint8Array([102, 111, 111]);
    const result = UTIL.text.utf8.decode(bytes);
    expect(result).toBe('foo');
  });

  it('should convert "\ud83c\udc00" to its UTF-8 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const result = UTIL.text.utf8.encode('\ud83c\udc00') as Uint8Array;
    expect(result.byteLength).toBe(4);
    expect(result[0]).toBe(240);
    expect(result[1]).toBe(159);
    expect(result[2]).toBe(128);
    expect(result[3]).toBe(128);
  });

  it('should convert "\ud83c\udc00" from its UTF-8 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const bytes = new Uint8Array([240, 159, 128, 128]);
    const result = UTIL.text.utf8.decode(bytes);
    expect(result).toBe('\ud83c\udc00');
  });

  it('should convert "foo" to its UTF-16 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const result = UTIL.text.utf16.encode('foo') as Uint8Array;
    expect(result.byteLength).toBe(6);
    expect(result[0]).toBe(102);
    expect(result[1]).toBe(0);
    expect(result[2]).toBe(111);
    expect(result[3]).toBe(0);
    expect(result[4]).toBe(111);
    expect(result[5]).toBe(0);
  });

  it('should convert "foo" from its UTF-16 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const bytes = new Uint8Array([102, 0, 111, 0, 111, 0]);
    const result = UTIL.text.utf16.decode(bytes);
    expect(result).toBe('foo');
  });

  it('should convert "\ud83c\udc00" to its UTF-16 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const result = UTIL.text.utf16.encode('\ud83c\udc00') as Uint8Array;
    expect(result.byteLength).toBe(4);
    expect(result[0]).toBe(60);
    expect(result[1]).toBe(216);
    expect(result[2]).toBe(0);
    expect(result[3]).toBe(220);
  });

  it('should convert "\ud83c\udc00" from its UTF-16 representation', (ctx) => {
    if (typeof Uint8Array === 'undefined') {
      return;
    }
    const bytes = new Uint8Array([60, 216, 0, 220]);
    const result = UTIL.text.utf16.decode(bytes);
    expect(result).toBe('\ud83c\udc00');
  });
});

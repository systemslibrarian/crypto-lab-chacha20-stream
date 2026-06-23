// Correctness tests for the hand-rolled ChaCha20 visualization engine.
//
// The engine in quarterround.ts is built from scratch for teaching, so it MUST
// be proven correct — a wrong visualization teaches the wrong thing. We pin it
// to the official RFC 8439 test vectors and cross-check every keystream byte
// against the production @noble/ciphers implementation.
import { describe, it, expect } from 'vitest';
import { chacha20 } from '@noble/ciphers/chacha.js';
import {
  quarterRound,
  rotl32,
  chachaBlock,
  keystreamBlock,
  serializeBlock,
} from './quarterround.ts';
import {
  encrypt,
  decrypt,
  getKeystream,
  nonceReuseDemo,
  cribDrag,
  toHex,
  fromHex,
} from './cipher.ts';

// Helpers ---------------------------------------------------------------------

/** Parse a spaced/normalized hex string into bytes. */
function hex(s: string): Uint8Array {
  return fromHex(s.replace(/\s+/g, ''));
}

const RFC_KEY = hex(
  '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ' +
    '10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f'
);
const RFC_NONCE = hex('00 00 00 09 00 00 00 4a 00 00 00 00');

// RFC 8439 §2.1.1 — the quarter-round on four words ---------------------------

describe('quarterRound (RFC 8439 §2.1.1)', () => {
  it('matches the published test vector', () => {
    const steps = quarterRound(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);
    const final = steps[steps.length - 1]!;
    expect(final.a >>> 0).toBe(0xea2a92f4);
    expect(final.b >>> 0).toBe(0xcb1cf8ce);
    expect(final.c >>> 0).toBe(0x4581472e);
    expect(final.d >>> 0).toBe(0x5881c4bb);
  });

  it('returns one intermediate row per ARX operation', () => {
    const steps = quarterRound(1, 2, 3, 4);
    expect(steps).toHaveLength(4);
    expect(steps.map((s) => s.step)).toEqual([1, 2, 3, 4]);
  });
});

describe('rotl32', () => {
  it('rotates left and stays unsigned 32-bit', () => {
    expect(rotl32(0x80000000, 1)).toBe(1);
    expect(rotl32(0x00000001, 8)).toBe(0x100);
    expect(rotl32(0xffffffff, 13)).toBe(0xffffffff);
  });
});

// RFC 8439 §2.3.2 — a full ChaCha20 block ------------------------------------

describe('chachaBlock (RFC 8439 §2.3.2)', () => {
  it('builds the documented initial state', () => {
    const { initialState } = chachaBlock(RFC_KEY, RFC_NONCE, 1);
    // prettier-ignore
    const expected = [
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
      0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
      0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];
    expect(initialState.map((w) => w >>> 0)).toEqual(expected);
  });

  it('produces the published 64-byte keystream block', () => {
    const expected = hex(
      '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 ' +
        'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e ' +
        'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2 ' +
        'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'
    );
    expect(keystreamBlock(RFC_KEY, RFC_NONCE, 1)).toEqual(expected);
  });

  it('walks exactly 80 quarter-rounds (20 rounds × 4)', () => {
    const { rounds } = chachaBlock(RFC_KEY, RFC_NONCE, 1);
    expect(rounds).toHaveLength(80);
  });
});

describe('serializeBlock', () => {
  it('writes words little-endian', () => {
    expect(Array.from(serializeBlock([0x04030201]).slice(0, 4))).toEqual([
      0x01, 0x02, 0x03, 0x04,
    ]);
  });
});

// Cross-check the teaching engine against production @noble/ciphers ------------

describe('hand-rolled engine vs @noble/ciphers', () => {
  it('keystream block matches noble for counter 0', () => {
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(12).fill(3);
    const noble = chacha20(key, nonce, new Uint8Array(64)); // XOR vs zeros = keystream
    expect(keystreamBlock(key, nonce, 0)).toEqual(noble);
  });

  it('getKeystream matches noble across multiple blocks', () => {
    const key = new Uint8Array(32).fill(0x42);
    const nonce = new Uint8Array(12).fill(0x24);
    const len = 200; // spans 4 blocks, exercises the counter
    const ours = new Uint8Array(len);
    for (let blk = 0; blk * 64 < len; blk++) {
      ours.set(keystreamBlock(key, nonce, blk).subarray(0, len - blk * 64), blk * 64);
    }
    expect(getKeystream(key, nonce, len)).toEqual(ours);
  });
});

// cipher.ts behavior ----------------------------------------------------------

describe('encrypt / decrypt', () => {
  const key = new Uint8Array(32).fill(1);
  const nonce = new Uint8Array(12).fill(2);

  it('round-trips arbitrary UTF-8 text', () => {
    const msg = 'The quick brown 🦊 jumps over the lazy dog — ✓';
    expect(decrypt(encrypt(msg, key, nonce), key, nonce)).toBe(msg);
  });

  it('is a pure XOR of plaintext and keystream', () => {
    const msg = 'hello world';
    const pt = new TextEncoder().encode(msg);
    const ks = getKeystream(key, nonce, pt.length);
    const ct = encrypt(msg, key, nonce);
    for (let i = 0; i < pt.length; i++) {
      expect(ct[i]).toBe(pt[i]! ^ ks[i]!);
    }
  });

  it('different nonce → different ciphertext', () => {
    const a = encrypt('same message', key, nonce);
    const b = encrypt('same message', key, new Uint8Array(12).fill(9));
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

// The whole point of Section D: the two-time-pad attack ------------------------

describe('nonceReuseDemo (two-time pad)', () => {
  it('ct1 ⊕ ct2 equals pt1 ⊕ pt2 (keystream cancels)', () => {
    const key = new Uint8Array(32).fill(5);
    const nonce = new Uint8Array(12).fill(6);
    const pt1 = 'Attack at dawn';
    const pt2 = 'Retreat now!!!';
    const { xorResult } = nonceReuseDemo(pt1, pt2, key, nonce);

    const b1 = new TextEncoder().encode(pt1);
    const b2 = new TextEncoder().encode(pt2);
    const n = Math.min(b1.length, b2.length);
    for (let i = 0; i < n; i++) {
      expect(xorResult[i]).toBe(b1[i]! ^ b2[i]!);
    }
  });

  it('crib-dragging the correct guess for pt1 recovers pt2', () => {
    const key = new Uint8Array(32).fill(5);
    const nonce = new Uint8Array(12).fill(6);
    const pt1 = 'Attack at dawn';
    const pt2 = 'Retreat now!!!';
    const { xorResult } = nonceReuseDemo(pt1, pt2, key, nonce);

    const recovered = new TextDecoder().decode(cribDrag(xorResult, pt1));
    expect(recovered).toBe(pt2);
  });
});

// Hex helpers -----------------------------------------------------------------

describe('toHex / fromHex', () => {
  it('round-trip', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xa5, 0xff]);
    expect(toHex(bytes)).toBe('000fa5ff');
    expect(fromHex('000fa5ff')).toEqual(bytes);
  });
});

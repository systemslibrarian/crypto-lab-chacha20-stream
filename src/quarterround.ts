// ChaCha20 quarter-round engine — hand-rolled for visualization, not production use.

export interface QuarterRoundStep {
  step: number;
  a: number;
  b: number;
  c: number;
  d: number;
}

/** Left-rotate a 32-bit unsigned integer by n bits. */
export function rotl32(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

/**
 * ChaCha20 quarter-round on four 32-bit words.
 * Returns intermediate values after each of the 4 operations.
 */
export function quarterRound(
  a: number,
  b: number,
  c: number,
  d: number
): QuarterRoundStep[] {
  const steps: QuarterRoundStep[] = [];

  a = (a + b) >>> 0;
  d = (d ^ a) >>> 0;
  d = rotl32(d, 16);
  steps.push({ step: 1, a, b, c, d });

  c = (c + d) >>> 0;
  b = (b ^ c) >>> 0;
  b = rotl32(b, 12);
  steps.push({ step: 2, a, b, c, d });

  a = (a + b) >>> 0;
  d = (d ^ a) >>> 0;
  d = rotl32(d, 8);
  steps.push({ step: 3, a, b, c, d });

  c = (c + d) >>> 0;
  b = (b ^ c) >>> 0;
  b = rotl32(b, 7);
  steps.push({ step: 4, a, b, c, d });

  return steps;
}

/** Read a 32-bit little-endian word from a byte array at offset. */
function littleEndian32(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset]!) |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16) |
    (bytes[offset + 3]! << 24)
  ) >>> 0;
}

/**
 * The 8 quarter-rounds of one double-round, as the matrix indices [a,b,c,d]
 * each touches. Rows 0–3 are the column rounds; rows 4–7 the diagonal rounds.
 * (RFC 8439 §2.3.1.)
 */
export const QR_INDICES: ReadonlyArray<readonly [number, number, number, number]> = [
  [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15], // columns
  [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14], // diagonals
];

export interface ChachaBlockResult {
  initialState: number[];
  rounds: QuarterRoundStep[][];
  /** The four matrix indices [a,b,c,d] each quarter-round operated on (len 80). */
  active: ReadonlyArray<readonly [number, number, number, number]>;
  /** Full 16-word working matrix after each quarter-round (len 80). */
  snapshots: number[][];
  finalState: number[];
}

/**
 * Compute a full ChaCha20 block.
 * key: 32 bytes, nonce: 12 bytes, counter: 32-bit unsigned.
 */
export function chachaBlock(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number
): ChachaBlockResult {
  // Build initial state (16 × 32-bit words)
  const state = new Uint32Array(16);
  // Constants: "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  // Key (8 words)
  for (let i = 0; i < 8; i++) {
    state[4 + i] = littleEndian32(key, i * 4);
  }
  // Counter
  state[12] = counter >>> 0;
  // Nonce (3 words)
  for (let i = 0; i < 3; i++) {
    state[13 + i] = littleEndian32(nonce, i * 4);
  }

  const initialState = Array.from(state);
  const working = new Uint32Array(state);
  const rounds: QuarterRoundStep[][] = [];
  const active: [number, number, number, number][] = [];
  const snapshots: number[][] = [];

  // 20 rounds = 10 double-rounds, each = 4 column + 4 diagonal quarter-rounds.
  for (let dr = 0; dr < 10; dr++) {
    for (const [ia, ib, ic, id] of QR_INDICES) {
      const qr = quarterRound(working[ia]!, working[ib]!, working[ic]!, working[id]!);
      const last = qr[3]!;
      working[ia] = last.a;
      working[ib] = last.b;
      working[ic] = last.c;
      working[id] = last.d;
      rounds.push(qr);
      active.push([ia, ib, ic, id]);
      snapshots.push(Array.from(working));
    }
  }

  // Add initial state to working state (mod 2^32)
  const finalState: number[] = [];
  for (let i = 0; i < 16; i++) {
    finalState.push(((working[i]!) + (state[i]!)) >>> 0);
  }

  return { initialState, rounds, active, snapshots, finalState };
}

/**
 * Serialize the 16 words of a finished block into 64 little-endian keystream
 * bytes — the exact output ChaCha20 XORs against plaintext (RFC 8439 §2.3).
 * Lets us prove the hand-rolled engine matches @noble/ciphers byte-for-byte.
 */
export function serializeBlock(words: number[]): Uint8Array {
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const w = words[i]! >>> 0;
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

/**
 * Produce the 64-byte keystream block from the hand-rolled engine.
 * Convenience wrapper over {@link chachaBlock} + {@link serializeBlock}.
 */
export function keystreamBlock(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number
): Uint8Array {
  return serializeBlock(chachaBlock(key, nonce, counter).finalState);
}

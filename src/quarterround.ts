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

export interface ChachaBlockResult {
  initialState: number[];
  rounds: QuarterRoundStep[][];
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

  // 20 rounds = 10 double-rounds (column + diagonal)
  for (let i = 0; i < 10; i++) {
    // Column rounds
    let qr: QuarterRoundStep[];
    qr = quarterRound(working[0]!, working[4]!, working[8]!, working[12]!);
    working[0] = qr[3]!.a; working[4] = qr[3]!.b; working[8] = qr[3]!.c; working[12] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[1]!, working[5]!, working[9]!, working[13]!);
    working[1] = qr[3]!.a; working[5] = qr[3]!.b; working[9] = qr[3]!.c; working[13] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[2]!, working[6]!, working[10]!, working[14]!);
    working[2] = qr[3]!.a; working[6] = qr[3]!.b; working[10] = qr[3]!.c; working[14] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[3]!, working[7]!, working[11]!, working[15]!);
    working[3] = qr[3]!.a; working[7] = qr[3]!.b; working[11] = qr[3]!.c; working[15] = qr[3]!.d;
    rounds.push(qr);

    // Diagonal rounds
    qr = quarterRound(working[0]!, working[5]!, working[10]!, working[15]!);
    working[0] = qr[3]!.a; working[5] = qr[3]!.b; working[10] = qr[3]!.c; working[15] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[1]!, working[6]!, working[11]!, working[12]!);
    working[1] = qr[3]!.a; working[6] = qr[3]!.b; working[11] = qr[3]!.c; working[12] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[2]!, working[7]!, working[8]!, working[13]!);
    working[2] = qr[3]!.a; working[7] = qr[3]!.b; working[8] = qr[3]!.c; working[13] = qr[3]!.d;
    rounds.push(qr);

    qr = quarterRound(working[3]!, working[4]!, working[9]!, working[14]!);
    working[3] = qr[3]!.a; working[4] = qr[3]!.b; working[9] = qr[3]!.c; working[14] = qr[3]!.d;
    rounds.push(qr);
  }

  // Add initial state to working state (mod 2^32)
  const finalState: number[] = [];
  for (let i = 0; i < 16; i++) {
    finalState.push(((working[i]!) + (state[i]!)) >>> 0);
  }

  return { initialState, rounds, finalState };
}

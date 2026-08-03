import { createCipheriv } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';

/**
 * Claims gate. The a11y suite proves the page is *reachable*; this suite proves
 * the page is *right*. Every headline number the demo shows is re-derived here
 * and compared, and every failure path it offers is driven to its failure state.
 *
 * Two independent oracles are used on purpose:
 *  - OpenSSL's own ChaCha20 (`node:crypto`, a third implementation that shares
 *    no code with either the hand-rolled engine or @noble/ciphers) recomputes
 *    the keystream and ciphertext from the key/nonce the page displays;
 *  - the page's own sections, cross-checked against each other — the Section A
 *    XOR exhibit, the Section B keystream grid and the Section C quarter-round
 *    stepper all claim to describe the same 64 bytes, so they must agree.
 */

/** RFC 8439 §2.3.1 — the [a,b,c,d] indices of the 8 quarter-rounds. */
const QR_INDICES: ReadonlyArray<readonly number[]> = [
  [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15], // column rounds
  [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14], // diagonal rounds
];

/**
 * ChaCha20 keystream from OpenSSL. Independent of everything the page ships:
 * if the demo's engine drifts, this disagrees. OpenSSL's 16-byte IV is
 * counter (LE32) || nonce.
 */
function opensslKeystream(keyHex: string, nonceHex: string, len = 64, counter = 0): number[] {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(counter, 0);
  Buffer.from(nonceHex, 'hex').copy(iv, 4);
  const c = createCipheriv('chacha20', Buffer.from(keyHex, 'hex'), iv);
  return [...Buffer.concat([c.update(Buffer.alloc(len)), c.final()])];
}

function hexOf(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function popcountDiff(a: number[], b: number[]): number {
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i]! ^ b[i]!;
    while (x) {
      bits += x & 1;
      x >>= 1;
    }
  }
  return bits;
}

/**
 * A 512-bit avalanche is Binomial(512, 1/2): mean 256, sd ~11.3. This window is
 * ~6.7 sd wide on each side, so a healthy cipher lands inside it with
 * probability ~1 - 1e-10 while a broken one (no diffusion) lands far outside.
 */
function expectHealthyAvalanche(bits: number): void {
  expect(bits).toBeGreaterThan(180);
  expect(bits).toBeLessThan(332);
}

/** The three rows of the Section A byte-aligned XOR exhibit. */
async function xorRows(page: Page): Promise<{ pt: number[]; ks: number[]; ct: number[] }> {
  const hex = await page.locator('#xor-viz .xor-cell .xor-hex').allTextContents();
  expect(hex.length % 3).toBe(0);
  const bytes = hex.map((h) => parseInt(h, 16));
  const n = hex.length / 3;
  return { pt: bytes.slice(0, n), ks: bytes.slice(n, 2 * n), ct: bytes.slice(2 * n) };
}

/** The 64 bytes of the Section B keystream grid. */
async function keystreamGrid(page: Page): Promise<number[]> {
  const cells = await page.locator('#keystream-grid .ks-cell').allTextContents();
  return cells.map((h) => parseInt(h, 16));
}

async function miniGrid(page: Page, sel: string): Promise<number[]> {
  const cells = await page.locator(`${sel} .ac-cell`).allTextContents();
  return cells.map((h) => parseInt(h, 16));
}

interface MatrixCell {
  value: number;
  active: boolean;
  changed: boolean;
  role: string | null;
  label: string;
}

async function matrixCells(page: Page): Promise<MatrixCell[]> {
  return page.locator('#state-matrix .matrix-cell').evaluateAll((cells) =>
    cells.map((c) => ({
      value: parseInt((c.querySelector('.matrix-val') as HTMLElement).textContent!.slice(2), 16),
      active: c.classList.contains('matrix-active'),
      changed: c.classList.contains('matrix-changed'),
      role: c.querySelector('.matrix-role')?.textContent ?? null,
      label: (c.querySelector('.matrix-lbl') as HTMLElement).textContent!,
    })),
  );
}

/** Little-endian serialization of the 16-word state, per RFC 8439 §2.3. */
function serialize(words: number[]): number[] {
  const out: number[] = [];
  for (const w of words) {
    out.push(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
  }
  return out;
}

/** Parse "<n> of 512 keystream bits flipped (<pct>%)" out of a readout. */
function parseAvalanche(text: string): { bits: number; pct: string } {
  const m = /(\d+) of 512\s+keystream bits flipped \(([\d.]+)%\)/.exec(text.replace(/\s+/g, ' '));
  expect(m, `avalanche readout not found in: ${text}`).not.toBeNull();
  return { bits: Number(m![1]), pct: m![2]! };
}

async function keyNonce(page: Page): Promise<{ key: string; nonce: string }> {
  return {
    key: (await page.locator('#key-display').textContent())!.trim(),
    nonce: (await page.locator('#nonce-display').textContent())!.trim(),
  };
}

// ─── Section A — ciphertext = plaintext ⊕ keystream ────────────────────────────

test('Section A: the ciphertext shown is ChaCha20 of the key and nonce shown', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);
  expect(key).toMatch(/^[0-9a-f]{64}$/);
  expect(nonce).toMatch(/^[0-9a-f]{24}$/);
  // The byte tags must describe the values actually displayed, not fixed text.
  expect(await page.locator('#key-len').textContent()).toBe(`${key.length / 2} bytes`);
  expect(await page.locator('#nonce-len').textContent()).toBe(`${nonce.length / 2} bytes`);

  const plaintext = await page.locator('#plaintext-input').inputValue();
  const ptBytes = [...Buffer.from(plaintext, 'utf8')];

  // Independent oracle: OpenSSL ChaCha20 under the displayed key/nonce.
  const ks = opensslKeystream(key, nonce, ptBytes.length);
  const expected = hexOf(ptBytes.map((b, i) => b ^ ks[i]!));
  expect(await page.locator('#ciphertext-display').textContent()).toBe(expected);

  // Counters: bytes in = bytes out for a stream cipher, and the hex is 2 chars/byte.
  expect(await page.locator('#pt-len').textContent()).toBe(`${ptBytes.length} bytes`);
  expect(await page.locator('#ct-len').textContent()).toBe(`${ptBytes.length} bytes`);
  expect(expected).toHaveLength(ptBytes.length * 2);
});

test('Section A: the XOR exhibit is honest — pt ⊕ ks = ct, and its ct row is the ciphertext', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);
  await page.locator('#plaintext-input').fill('ct = pt XOR ks');

  const { pt, ks, ct } = await xorRows(page);
  expect(pt).toHaveLength('ct = pt XOR ks'.length);

  // Row 1 is the real plaintext, row 2 the real keystream (OpenSSL agrees),
  // row 3 their XOR — the exhibit cannot be faking any of the three rows.
  expect(pt).toEqual([...Buffer.from('ct = pt XOR ks', 'utf8')]);
  expect(ks).toEqual(opensslKeystream(key, nonce, pt.length));
  for (let i = 0; i < pt.length; i++) {
    expect(ct[i]).toBe(pt[i]! ^ ks[i]!);
  }
  // ...and the exhibit's ciphertext row is the same ciphertext the output box shows.
  expect(await page.locator('#ciphertext-display').textContent()).toBe(hexOf(ct));

  // The printable glyph row must show the characters actually typed.
  const glyphs = await page.locator('#xor-viz .xor-row-pt .xor-glyph').allTextContents();
  expect(glyphs.join('').replace(/␣/g, ' ')).toBe('ct = pt XOR ks');
});

test('Section A: decrypt round-trips exactly, including multi-byte UTF-8', async ({ page }) => {
  await page.goto('.');
  const message = 'café — naïve ✓ 🦊';
  const byteLen = Buffer.byteLength(message, 'utf8');
  expect(byteLen).toBeGreaterThan(message.length); // genuinely multi-byte

  await page.locator('#plaintext-input').fill(message);
  expect(await page.locator('#pt-len').textContent()).toBe(`${byteLen} bytes`);
  // Encrypting is live, but the button must produce the same thing.
  const live = await page.locator('#ciphertext-display').textContent();
  await page.locator('#btn-encrypt').click();
  expect(await page.locator('#ciphertext-display').textContent()).toBe(live);
  expect(live).toHaveLength(byteLen * 2);

  await page.locator('#btn-decrypt').click();
  await expect(page.locator('#decrypted-display')).toHaveText(message);
});

test('Section A: emptying the plaintext clears every derived output', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#ciphertext-display')).not.toBeEmpty();
  await page.locator('#plaintext-input').fill('');
  await expect(page.locator('#ciphertext-display')).toBeEmpty();
  await expect(page.locator('#decrypted-display')).toBeEmpty();
  expect(await page.locator('#ct-len').textContent()).toBe('');
  expect(await page.locator('#pt-len').textContent()).toBe('0 bytes');
  expect(await page.locator('#xor-viz .xor-cell').count()).toBe(0);
  // Decrypt with nothing to decrypt must not invent a recovery.
  await page.locator('#btn-decrypt').click();
  await expect(page.locator('#decrypted-display')).toBeEmpty();
});

// ─── Section B — keystream + avalanche ────────────────────────────────────────

test('Section B: the keystream grid is the real ChaCha20 block, and Section A visualizes the same bytes', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);

  const grid = await keystreamGrid(page);
  expect(grid).toHaveLength(64);
  // The grid is the hand-rolled engine's block; OpenSSL says it is correct.
  expect(grid).toEqual(opensslKeystream(key, nonce));

  // Cross-path: Section A's keystream row comes from a different code path
  // (@noble/ciphers, arbitrary length) and must be byte-identical for 64 bytes.
  await page.locator('#plaintext-input').fill('x'.repeat(64));
  const { ks } = await xorRows(page);
  expect(ks).toEqual(grid);
});

test('Section B: a new nonce rekeys the stream and the avalanche readout matches the two grids it compares', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-show-keystream').click();
  await expect(page.locator('#avalanche')).toBeHidden();

  const before = await keystreamGrid(page);
  const { key: keyBefore, nonce: nonceBefore } = await keyNonce(page);

  await page.locator('#btn-new-nonce-ks').click();
  await expect(page.locator('#avalanche')).toBeVisible();

  const { key, nonce } = await keyNonce(page);
  expect(nonce).not.toBe(nonceBefore);
  expect(key).toBe(keyBefore); // same key: this is a nonce-only change

  const after = await keystreamGrid(page);
  expect(after).not.toEqual(before);
  expect(after).toEqual(opensslKeystream(key, nonce));

  // The headline number must be the diff of the two blocks the page rendered,
  // and the percentage must be that number over 512 — not a decorative string.
  const { bits, pct } = parseAvalanche((await page.locator('#avalanche').textContent())!);
  expect(bits).toBe(popcountDiff(before, after));
  expect(pct).toBe(((bits / 512) * 100).toFixed(1));
  expectHealthyAvalanche(bits);
});

test('Section B: regenerating the key refreshes the grid and retracts the stale avalanche stat', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-new-nonce-ks').click();
  await expect(page.locator('#avalanche')).toBeVisible();
  const before = await keystreamGrid(page);

  await page.locator('#btn-regen-key').click();
  // The stat compared two nonces under one key; after a key change it would be
  // a lie, so the page must withdraw it rather than leave it standing.
  await expect(page.locator('#avalanche')).toBeHidden();

  const { key, nonce } = await keyNonce(page);
  const after = await keystreamGrid(page);
  expect(after).not.toEqual(before);
  expect(after).toEqual(opensslKeystream(key, nonce));
});

test('Section B: one flipped nonce bit avalanches into ~half the keystream', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);
  await expect(page.locator('#avalanche-compare')).toBeHidden();
  await page.locator('#btn-flip-bit').click();
  await expect(page.locator('#avalanche-compare')).toBeVisible();

  const before = await miniGrid(page, '#ac-grid-before');
  const after = await miniGrid(page, '#ac-grid-after');
  expect(before).toHaveLength(64);
  expect(after).toHaveLength(64);

  // "Before" must be the block for the nonce on screen — the same 64 bytes the
  // main grid shows — and "after" the block for that nonce with byte 0's low
  // bit flipped, exactly as the caption claims. One bit in, nothing else.
  expect(before).toEqual(await keystreamGrid(page));
  expect(before).toEqual(opensslKeystream(key, nonce));
  const flipped = Buffer.from(nonce, 'hex');
  flipped[0] ^= 0x01;
  expect(after).toEqual(opensslKeystream(key, flipped.toString('hex')));

  const { bits, pct } = parseAvalanche((await page.locator('#ac-caption').textContent())!);
  expect(bits).toBe(popcountDiff(before, after));
  expect(pct).toBe(((bits / 512) * 100).toFixed(1));
  expectHealthyAvalanche(bits);

  // Highlighted cells must be exactly the bytes that differ — on both sides.
  const changedBytes = before.filter((b, i) => b !== after[i]).length;
  expect(await page.locator('#ac-grid-before .ac-cell-changed').count()).toBe(changedBytes);
  expect(await page.locator('#ac-grid-after .ac-cell-changed').count()).toBe(changedBytes);
  // A changed byte carries between 1 and 8 changed bits: the cell count and the
  // bit count have to be consistent with each other.
  expect(changedBytes).toBeLessThanOrEqual(bits);
  expect(bits).toBeLessThanOrEqual(changedBytes * 8);
});

test('Section B: the grid colours encode byte value and stay readable', async ({ page }) => {
  await page.goto('.');
  const cells = await page.locator('#keystream-grid .ks-cell').evaluateAll((els) =>
    els.map((el) => {
      const cs = getComputedStyle(el);
      return { value: parseInt(el.textContent!, 16), bg: cs.backgroundColor, fg: cs.color };
    }),
  );
  expect(cells).toHaveLength(64);

  const rgb = (s: string) => s.match(/\d+/g)!.map(Number);
  const lum = (c: number[]) => {
    const lin = (v: number) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * lin(c[0]!) + 0.7152 * lin(c[1]!) + 0.0722 * lin(c[2]!);
  };

  // Claim: "low = blue, high = red" — the red channel must rise with the byte
  // value and the blue channel fall, with no inversions anywhere in the ramp.
  const sorted = [...cells].sort((a, b) => a.value - b.value);
  for (let i = 1; i < sorted.length; i++) {
    const prev = rgb(sorted[i - 1]!.bg);
    const cur = rgb(sorted[i]!.bg);
    expect(cur[0]).toBeGreaterThanOrEqual(prev[0]!);
    expect(cur[2]).toBeLessThanOrEqual(prev[2]!);
  }
  // Claim: the visual encoding never costs legibility (>= WCAG AA 4.5:1).
  for (const cell of cells) {
    const ratio = (Math.max(lum(rgb(cell.fg)), lum(rgb(cell.bg))) + 0.05) /
      (Math.min(lum(rgb(cell.fg)), lum(rgb(cell.bg))) + 0.05);
    expect(ratio, `byte ${cell.value} contrast`).toBeGreaterThanOrEqual(4.5);
  }
});

// ─── Section C — quarter-round stepper ────────────────────────────────────────

test('Section C: the initial state is built from the key and nonce shown above it', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);
  await page.locator('#btn-run-qr').click();

  const cells = await matrixCells(page);
  expect(cells).toHaveLength(16);
  expect(cells.filter((c) => c.active)).toHaveLength(0); // nothing mixed yet
  expect(await page.locator('#round-label').textContent()).toContain('0 of 80');
  expect(await page.locator('.qr-progress').getAttribute('aria-valuenow')).toBe('0');

  // "expand 32-byte k" — RFC 8439 §2.3.
  expect(cells.slice(0, 4).map((c) => c.value)).toEqual([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  const le32 = (hex: string, word: number) => Buffer.from(hex, 'hex').readUInt32LE(word * 4);
  for (let i = 0; i < 8; i++) {
    expect(cells[4 + i]!.value, `key word ${i}`).toBe(le32(key, i));
  }
  expect(cells[12]!.value).toBe(0); // block counter starts at 0
  for (let i = 0; i < 3; i++) {
    expect(cells[13 + i]!.value, `nonce word ${i}`).toBe(le32(nonce, i));
  }
  expect(cells.map((c) => c.label)).toEqual([
    'const', 'const', 'const', 'const',
    'key', 'key', 'key', 'key', 'key', 'key', 'key', 'key',
    'ctr', 'nonce', 'nonce', 'nonce',
  ]);
});

test('Section C: each quarter-round mixes the words its label names, alternating column and diagonal', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-run-qr').click();
  const next = page.locator('#btn-next-round');

  const OPS = [
    'a += b; d ^= a; d <<<= 16',
    'c += d; b ^= c; b <<<= 12',
    'a += b; d ^= a; d <<<= 8',
    'c += d; b ^= c; b <<<= 7',
  ];

  // One full double-round: 4 column quarter-rounds then 4 diagonal ones.
  for (let step = 1; step <= 8; step++) {
    await next.click();
    const label = (await page.locator('#round-label').textContent())!.replace(/\s+/g, ' ');
    const isColumn = step <= 4;
    expect(label).toContain('Double-round 1/10');
    expect(label).toContain(isColumn ? 'Column round' : 'Diagonal round');
    expect(label).toContain(`quarter-round ${step}/80`);
    const indices = QR_INDICES[step - 1]!;
    expect(label).toContain(`mixing words (${indices.join(', ')})`);

    // The narration must describe the same kind of round the label does.
    const narration = (await page.locator('#qr-narrate').textContent())!;
    expect(narration).toContain(`a=${indices[0]}, b=${indices[1]}, c=${indices[2]}, d=${indices[3]}`);
    expect(narration.toLowerCase()).toContain(isColumn ? 'column' : 'diagonal');

    // Exactly the four named words are highlighted, labelled a/b/c/d in order.
    const cells = await matrixCells(page);
    expect(cells.map((c, i) => (c.active ? i : -1)).filter((i) => i >= 0)).toEqual([...indices].sort((x, y) => x - y));
    expect(indices.map((i) => cells[i]!.role)).toEqual(['a', 'b', 'c', 'd']);
    // A quarter-round changes all four of its words; the flags say which.
    expect(cells.filter((c) => c.changed).length).toBeGreaterThan(0);

    // The step table shows the four ARX operations, and its last row must be
    // the values the matrix is now displaying for a, b, c, d.
    const rows = page.locator('#qr-step-table tbody tr');
    await expect(rows).toHaveCount(4);
    expect(await page.locator('#qr-step-table .op-cell').allTextContents()).toEqual(OPS);
    const lastRow = (await rows.nth(3).locator('td').allTextContents()).map((t) => t.trim());
    expect(lastRow[0]).toBe('4');
    expect(lastRow.slice(2)).toEqual(indices.map((i) => '0x' + cells[i]!.value.toString(16).padStart(8, '0')));

    // Progress tracks the step, in the bar's own geometry as well as its ARIA.
    expect(await page.locator('.qr-progress').getAttribute('aria-valuenow')).toBe(String(step));
    expect(await page.locator('#qr-progress-bar').getAttribute('style')).toContain(`width: ${(step / 80) * 100}%`);
  }
});

test('Section C: stepping all 80 quarter-rounds yields exactly the keystream Section B shows', async ({ page }) => {
  await page.goto('.');
  const { key, nonce } = await keyNonce(page);
  const grid = await keystreamGrid(page);

  await page.locator('#btn-run-qr').click();
  const next = page.locator('#btn-next-round');
  for (let i = 0; i < 81; i++) await next.click(); // 80 quarter-rounds + the final add

  await expect(page.locator('#round-label')).toContainText('Complete');
  await expect(next).toBeDisabled();
  await expect(page.locator('#qr-step-table')).toContainText('All 80 quarter-rounds complete');
  expect(await page.locator('.qr-progress').getAttribute('aria-valuenow')).toBe('80');
  expect(await page.locator('#qr-progress-bar').getAttribute('style')).toContain('width: 100%');

  // The payoff: serialize the 16 final words little-endian and you get the
  // exact 64 bytes Section B renders — and OpenSSL agrees with both.
  const finalState = (await matrixCells(page)).map((c) => c.value);
  const serialized = serialize(finalState);
  expect(serialized).toEqual(grid);
  expect(serialized).toEqual(opensslKeystream(key, nonce));
});

test('Section C: play auto-advances and pause stops it', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-run-qr').click();
  const play = page.locator('#btn-play-qr');
  const progress = page.locator('.qr-progress');

  await play.click();
  await expect(play).toHaveText('⏸ Pause');
  await expect
    .poll(async () => Number(await progress.getAttribute('aria-valuenow')), { timeout: 5000 })
    .toBeGreaterThan(2);

  await play.click();
  await expect(play).toHaveText('▶ Play');
  const stopped = await progress.getAttribute('aria-valuenow');
  await page.waitForTimeout(1200); // several play intervals
  expect(await progress.getAttribute('aria-valuenow')).toBe(stopped);
});

// ─── Section D — nonce reuse (the failure path the whole page is about) ───────

test('Section D: reusing a nonce cancels the keystream, and the page shows the leak byte-for-byte', async ({ page }) => {
  await page.goto('.');
  const m1 = 'Attack at dawn!';
  const m2 = 'Retreat to base';
  await page.locator('#nonce-msg1').fill(m1);
  await page.locator('#nonce-msg2').fill(m2);
  await page.locator('#btn-nonce-reuse').click();

  const ct1 = (await page.locator('#nr-ct1').textContent())!;
  const ct2 = (await page.locator('#nr-ct2').textContent())!;
  expect(ct1).toMatch(/^[0-9a-f]+$/);
  expect(ct2).toMatch(/^[0-9a-f]+$/);
  expect(ct1).not.toBe(ct2);

  const b1 = [...Buffer.from(m1, 'utf8')];
  const b2 = [...Buffer.from(m2, 'utf8')];
  const leak = b1.map((b, i) => b ^ b2[i]!);

  // The exhibit's headline equation, checked twice: the rendered XOR equals
  // ct1 ⊕ ct2 (what an attacker actually computes) AND equals pt1 ⊕ pt2 (what
  // that turns out to be). If the keystream did not cancel, these differ.
  const shown = (await page.locator('#nr-xor').textContent())!.trim();
  const x1 = Buffer.from(ct1, 'hex');
  const x2 = Buffer.from(ct2, 'hex');
  expect(shown).toBe(hexOf([...x1].map((b, i) => b ^ x2[i]!)));
  expect(shown).toBe(hexOf(leak));

  // The page flags every byte that matches pt1 ⊕ pt2; none may be unflagged.
  await expect(page.locator('#nr-xor .xor-match')).toHaveCount(leak.length);
  await expect(page.locator('#nr-xor .xor-byte')).toHaveCount(0);

  // ...and it says why, rather than just showing hex.
  const why = (await page.locator('#nr-explanation').textContent())!;
  expect(why).toContain('keystream cancels out');
  expect(why).toContain('two-time pad');
  expect(why).toContain('Never reuse a nonce with the same key');
  await expect(page.locator('.warning-banner')).toContainText('Never reuse a nonce');
});

test('Section D: crib-dragging the right guess recovers the other message with no key', async ({ page }) => {
  await page.goto('.');
  const m1 = 'Attack at dawn!';
  const m2 = 'Retreat to base';
  await page.locator('#nonce-msg1').fill(m1);
  await page.locator('#nonce-msg2').fill(m2);
  await expect(page.locator('#crib-drag')).toBeHidden();
  await page.locator('#btn-nonce-reuse').click();
  await expect(page.locator('#crib-drag')).toBeVisible();

  // Pre-filled with the true Message 1 -> Message 2 comes back verbatim.
  expect(await page.locator('#crib-guess').inputValue()).toBe(m1);
  const recovered = async () =>
    (await page.locator('#crib-output').textContent())!.replace(/\u00a0/g, ' ');
  expect(await recovered()).toBe(m2);
});

test('Section D: a wrong guess degrades the recovery exactly where it is wrong', async ({ page }) => {
  await page.goto('.');
  const m1 = 'Attack at dawn!';
  const m2 = 'Retreat to base';
  await page.locator('#nonce-msg1').fill(m1);
  await page.locator('#nonce-msg2').fill(m2);
  await page.locator('#btn-nonce-reuse').click();
  const out = page.locator('#crib-output');
  const recovered = async () => (await out.textContent())!.replace(/\u00a0/g, ' ');

  // Corrupt exactly one character of the guess: exactly one recovered
  // character must change, and it must change to guess[i] ⊕ leak[i].
  const wrong = 'Bttack at dawn!';
  await page.locator('#crib-guess').fill(wrong);
  const after = await recovered();
  expect(after).toHaveLength(m2.length);
  expect(after[0]).not.toBe(m2[0]);
  expect(after.slice(1)).toBe(m2.slice(1));
  const leaked = m1.charCodeAt(0) ^ m2.charCodeAt(0);
  expect(after.charCodeAt(0)).toBe(wrong.charCodeAt(0) ^ leaked);

  // A guess that is wrong everywhere recovers nothing readable...
  await page.locator('#crib-guess').fill('x'.repeat(m1.length));
  const garbage = await recovered();
  expect(garbage).not.toBe(m2);
  // ...non-printable results are shown as gaps rather than silently dropped,
  // so the rendered length still accounts for every byte.
  const chars = await page.locator('#crib-output .crib-char').count();
  const gaps = await page.locator('#crib-output .crib-gap').count();
  expect(chars + gaps).toBe(m1.length);

  // A truncated guess recovers only as far as it reaches — the attack is
  // bounded by the guess, not by any secret.
  await page.locator('#crib-guess').fill(m1.slice(0, 7));
  expect(await recovered()).toBe(m2.slice(0, 7));

  // Restoring the true guess restores the full recovery.
  await page.locator('#crib-guess').fill(m1);
  expect(await recovered()).toBe(m2);
});

test('Section D: shorter of the two messages bounds the leak', async ({ page }) => {
  await page.goto('.');
  const m1 = 'Attack at dawn';   // 14 bytes
  const m2 = 'Retreat to base';  // 15 bytes
  await page.locator('#nonce-msg1').fill(m1);
  await page.locator('#nonce-msg2').fill(m2);
  await page.locator('#btn-nonce-reuse').click();

  // Only the overlapping prefix leaks; the 15th byte of Message 2 is never
  // covered by the keystream cancellation.
  const shown = (await page.locator('#nr-xor').textContent())!.trim();
  expect(shown).toHaveLength(Math.min(m1.length, m2.length) * 2);
  const recovered = (await page.locator('#crib-output').textContent())!.replace(/\u00a0/g, ' ');
  expect(recovered).toBe(m2.slice(0, m1.length));
});

// ─── Cross-section consistency ────────────────────────────────────────────────

test('a nonce change anywhere keeps every section describing the same key and nonce', async ({ page }) => {
  await page.goto('.');
  await page.locator('#plaintext-input').fill('consistency across sections');
  await page.locator('#btn-run-qr').click();

  // Regenerate from Section B; Sections A and C must both follow.
  await page.locator('#btn-new-nonce-ks').click();
  const { key, nonce } = await keyNonce(page);

  // Section A re-encrypted under the new nonce (not left stale) ...
  const ptBytes = [...Buffer.from('consistency across sections', 'utf8')];
  const ks = opensslKeystream(key, nonce, ptBytes.length);
  expect(await page.locator('#ciphertext-display').textContent())
    .toBe(hexOf(ptBytes.map((b, i) => b ^ ks[i]!)));
  await page.locator('#btn-decrypt').click();
  await expect(page.locator('#decrypted-display')).toHaveText('consistency across sections');

  // ... Section B's grid is the new block ...
  expect(await keystreamGrid(page)).toEqual(opensslKeystream(key, nonce));

  // ... and Section C's matrix was rebuilt from the new nonce, not the old one.
  const cells = await matrixCells(page);
  const le32 = (hex: string, word: number) => Buffer.from(hex, 'hex').readUInt32LE(word * 4);
  for (let i = 0; i < 3; i++) {
    expect(cells[13 + i]!.value, `nonce word ${i}`).toBe(le32(nonce, i));
  }
});

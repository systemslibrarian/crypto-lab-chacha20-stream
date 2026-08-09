// UI wiring — connects DOM to cipher.ts and quarterround.ts
import {
  encrypt,
  decrypt,
  generateKey,
  generateNonce,
  nonceReuseDemo,
  cribDrag,
  toHex,
  getKeystream,
} from './cipher.ts';
import { chachaBlock, keystreamBlock } from './quarterround.ts';
import type { ChachaBlockResult } from './quarterround.ts';

// ─── State ───────────────────────────────────────────────────
let currentKey = generateKey();
let currentNonce = generateNonce();
let lastCiphertext: Uint8Array | null = null;

// Quarter-round stepper state
let blockResult: ChachaBlockResult | null = null;

// The key and nonce are shared across sections (Section A shows them, B derives
// the keystream, C steps the block). Route every mutation through setKey/setNonce
// so all sections re-render in sync — otherwise one section's regenerate leaves
// another showing stale ciphertext / keystream.
type KeyNonceReason = 'key' | 'nonce';
const keyNonceListeners: Array<(reason: KeyNonceReason) => void> = [];

function onKeyNonce(fn: (reason: KeyNonceReason) => void) {
  keyNonceListeners.push(fn);
}

function emitKeyNonce(reason: KeyNonceReason) {
  for (const fn of keyNonceListeners) fn(reason);
}

function setKey(k: Uint8Array) {
  currentKey = k;
  emitKeyNonce('key');
}

function setNonce(n: Uint8Array) {
  currentNonce = n;
  emitKeyNonce('nonce');
}

// ─── Helpers ─────────────────────────────────────────────────
function $(sel: string): HTMLElement {
  return document.querySelector(sel)!;
}

function copyToClipboard(text: string, btn: HTMLElement) {
  const orig = btn.textContent;
  const restore = (msg: string) => {
    btn.textContent = msg;
    setTimeout(() => (btn.textContent = orig), 1200);
  };
  // Clipboard API is unavailable outside secure contexts; fail gracefully.
  if (!navigator.clipboard?.writeText) {
    restore('Unavailable');
    return;
  }
  navigator.clipboard
    .writeText(text)
    .then(() => restore('Copied!'))
    .catch(() => restore('Failed'));
}

/** WCAG relative luminance of an sRGB colour (0–1). */
function relLuminance(r: number, g: number, b: number): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** WCAG contrast ratio between two relative luminances. */
function contrast(l1: number, l2: number): number {
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * Map a keystream byte to a {bg, fg} pair for its grid cell. The hue still
 * encodes magnitude (low = blue, high = red), but every colour is dark enough
 * that white label text clears the WCAG AA 4.5:1 contrast threshold — the
 * a11y gate scans this grid, so the visual encoding can't cost readability.
 */
function byteColor(byte: number): { bg: string; fg: string } {
  const t = byte / 255;
  // Darkened blue→red gradient; endpoints chosen so the brightest cell keeps
  // white text >=4.5:1 (relative luminance stays below ~0.18 across the ramp).
  let r = Math.round(37 + t * (176 - 37));
  let g = Math.round(78 + t * (30 - 78));
  let b = Math.round(148 + t * (30 - 148));
  // Defensive guard: if any interpolated colour ever crept above the threshold,
  // scale it down until white text passes. Keeps the fix robust to tweaks.
  const white = 1;
  while (contrast(relLuminance(r, g, b), white) < 4.5) {
    r = Math.round(r * 0.92);
    g = Math.round(g * 0.92);
    b = Math.round(b * 0.92);
  }
  return { bg: `rgb(${r},${g},${b})`, fg: '#ffffff' };
}

// ─── Section A: Encrypt/Decrypt ──────────────────────────────
function initEncryptDecrypt() {
  const keyDisplay = $('#key-display') as HTMLElement;
  const nonceDisplay = $('#nonce-display') as HTMLElement;
  const ptInput = $('#plaintext-input') as HTMLTextAreaElement;
  const ctDisplay = $('#ciphertext-display') as HTMLElement;
  const decryptedDisplay = $('#decrypted-display') as HTMLElement;
  const keyLen = $('#key-len') as HTMLElement;
  const nonceLen = $('#nonce-len') as HTMLElement;
  const ptLen = $('#pt-len') as HTMLElement;
  const ctLen = $('#ct-len') as HTMLElement;
  const xorViz = $('#xor-viz') as HTMLElement;

  const hx = (b: number) => b.toString(16).padStart(2, '0');

  /**
   * Draw the load-bearing intuition: for each byte, a column showing
   * pt[i] ⊕ ks[i] = ct[i]. Keystream comes from the SAME hand-rolled engine
   * Section 3 steps through (getKeystream), so the numbers are honest, not faked.
   * Hover/focus a column highlights that byte across all three rows.
   */
  function renderXorViz(pt: string) {
    xorViz.innerHTML = '';
    const ptBytes = new TextEncoder().encode(pt);
    if (ptBytes.length === 0) return;
    const ks = getKeystream(currentKey, currentNonce, ptBytes.length);

    const rows = [
      { cls: 'xor-row-pt', op: '', name: 'plaintext' },
      { cls: 'xor-row-ks', op: '⊕', name: 'keystream' },
      { cls: 'xor-row-ct', op: '=', name: 'ciphertext' },
    ];
    // Build one grid; each byte is a column of 3 stacked cells so columns align.
    const grid = document.createElement('div');
    grid.className = 'xor-grid';
    grid.style.gridTemplateColumns = `repeat(${ptBytes.length}, minmax(1.7rem, 1fr))`;

    for (let r = 0; r < rows.length; r++) {
      for (let i = 0; i < ptBytes.length; i++) {
        const ct = (ptBytes[i]! ^ ks[i]!) >>> 0;
        const cell = document.createElement('div');
        cell.className = `xor-cell ${rows[r]!.cls}`;
        cell.dataset.col = String(i);
        let val: string;
        if (r === 0) {
          const b = ptBytes[i]!;
          const printable = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·';
          val = `<span class="xor-glyph">${printable === ' ' ? '␣' : printable
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span><span class="xor-hex">${hx(b)}</span>`;
        } else if (r === 1) {
          val = `<span class="xor-glyph">${rows[r]!.op}</span><span class="xor-hex">${hx(ks[i]!)}</span>`;
        } else {
          val = `<span class="xor-glyph">${rows[r]!.op}</span><span class="xor-hex">${hx(ct)}</span>`;
        }
        cell.innerHTML = val;
        grid.appendChild(cell);
      }
    }
    xorViz.appendChild(grid);

    // Column highlight on hover/focus — learner traces one byte through the XOR.
    let active = -1;
    const setActive = (col: number) => {
      if (col === active) return;
      grid.querySelectorAll('.xor-col-active').forEach((el) => el.classList.remove('xor-col-active'));
      if (col >= 0) {
        grid.querySelectorAll(`.xor-cell[data-col="${col}"]`).forEach((el) => el.classList.add('xor-col-active'));
      }
      active = col;
    };
    grid.addEventListener('mouseover', (e) => {
      const c = (e.target as HTMLElement).closest('.xor-cell') as HTMLElement | null;
      if (c) setActive(Number(c.dataset.col));
    });
    grid.addEventListener('mouseleave', () => setActive(-1));
    // Keyboard: the container is focusable; arrow keys walk columns.
    let kb = 0;
    xorViz.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        kb = Math.max(0, Math.min(ptBytes.length - 1, kb + (e.key === 'ArrowRight' ? 1 : -1)));
        setActive(kb);
        e.preventDefault();
      }
    });
  }

  function refreshKeyNonce() {
    keyDisplay.textContent = toHex(currentKey);
    nonceDisplay.textContent = toHex(currentNonce);
    keyLen.textContent = `${currentKey.length} bytes`;
    nonceLen.textContent = `${currentNonce.length} bytes`;
  }

  // Re-encrypt live whenever plaintext, key, or nonce changes. The decrypted
  // box is cleared because any prior recovery is now stale.
  function liveEncrypt() {
    const pt = ptInput.value;
    ptLen.textContent = `${new TextEncoder().encode(pt).length} bytes`;
    if (!pt) {
      lastCiphertext = null;
      ctDisplay.textContent = '';
      ctLen.textContent = '';
      decryptedDisplay.textContent = '';
      xorViz.innerHTML = '';
      return;
    }
    lastCiphertext = encrypt(pt, currentKey, currentNonce);
    ctDisplay.textContent = toHex(lastCiphertext);
    ctLen.textContent = `${lastCiphertext.length} bytes`;
    decryptedDisplay.textContent = '';
    renderXorViz(pt);
  }

  refreshKeyNonce();
  liveEncrypt();

  // Keep this section in sync no matter which section changed the key/nonce.
  onKeyNonce(() => {
    refreshKeyNonce();
    liveEncrypt();
  });

  ptInput.addEventListener('input', liveEncrypt);

  $('#btn-regen-key').addEventListener('click', () => setKey(generateKey()));
  $('#btn-regen-nonce').addEventListener('click', () => setNonce(generateNonce()));

  $('#btn-copy-key').addEventListener('click', () => {
    copyToClipboard(toHex(currentKey), $('#btn-copy-key'));
  });

  $('#btn-copy-nonce').addEventListener('click', () => {
    copyToClipboard(toHex(currentNonce), $('#btn-copy-nonce'));
  });

  $('#btn-encrypt').addEventListener('click', liveEncrypt);

  $('#btn-decrypt').addEventListener('click', () => {
    if (!lastCiphertext) return;
    const pt = decrypt(lastCiphertext, currentKey, currentNonce);
    decryptedDisplay.textContent = pt;
    decryptedDisplay.classList.add('recovered');
    setTimeout(() => decryptedDisplay.classList.remove('recovered'), 600);
  });

  $('#btn-copy-ct').addEventListener('click', () => {
    if (lastCiphertext) {
      copyToClipboard(toHex(lastCiphertext), $('#btn-copy-ct'));
    }
  });
}

// ─── Section B: Keystream Visualizer ─────────────────────────
function initKeystreamViz() {
  const grid = $('#keystream-grid') as HTMLElement;
  const avalanche = $('#avalanche') as HTMLElement;
  // Baseline keystream to measure the avalanche against. Tracks the same key,
  // so a nonce change shows a true "one nonce → this much diffusion" stat.
  let baseline = keystreamBlock(currentKey, currentNonce, 0);

  /** Count differing bits between two equal-length byte arrays. */
  function bitsDiffer(a: Uint8Array, b: Uint8Array): number {
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      let x = a[i]! ^ b[i]!;
      while (x) {
        diff += x & 1;
        x >>= 1;
      }
    }
    return diff;
  }

  function renderGrid(ks: Uint8Array) {
    // Use the hand-rolled, RFC-verified engine — the same block you step
    // through in Section C produces exactly these 64 bytes.
    grid.innerHTML = '';
    for (let i = 0; i < ks.length; i++) {
      const cell = document.createElement('div');
      cell.className = 'ks-cell';
      cell.textContent = ks[i]!.toString(16).padStart(2, '0');
      cell.title = `byte ${i}: ${ks[i]} (0x${ks[i]!.toString(16).padStart(2, '0')})`;
      const { bg, fg } = byteColor(ks[i]!);
      cell.style.backgroundColor = bg;
      cell.style.color = fg;
      grid.appendChild(cell);
    }
  }

  function showAvalanche(before: Uint8Array, after: Uint8Array) {
    const bits = bitsDiffer(before, after);
    const pct = ((bits / 512) * 100).toFixed(1);
    avalanche.hidden = false;
    avalanche.innerHTML =
      `<strong>Avalanche:</strong> ${bits} of 512 keystream bits flipped (${pct}%) ` +
      `from a single new nonce — an ideal cipher changes ~50%.`;
  }

  // ── Single-bit avalanche: flip ONE nonce bit and compare keystreams ──
  const compareBox = $('#avalanche-compare') as HTMLElement;
  const gridBefore = $('#ac-grid-before') as HTMLElement;
  const gridAfter = $('#ac-grid-after') as HTMLElement;
  const acCaption = $('#ac-caption') as HTMLElement;

  /** Render a compact 8-col keystream grid; `diff` marks changed bytes. */
  function renderMiniGrid(target: HTMLElement, ks: Uint8Array, diff?: Uint8Array) {
    target.innerHTML = '';
    for (let i = 0; i < ks.length; i++) {
      const cell = document.createElement('div');
      const changed = diff && ks[i] !== diff[i];
      cell.className = `ac-cell${changed ? ' ac-cell-changed' : ''}`;
      cell.textContent = ks[i]!.toString(16).padStart(2, '0');
      const { bg, fg } = byteColor(ks[i]!);
      cell.style.backgroundColor = bg;
      cell.style.color = fg;
      target.appendChild(cell);
    }
  }

  function runSingleBitAvalanche() {
    const before = keystreamBlock(currentKey, currentNonce, 0);
    // Flip the lowest bit of the first nonce byte — a genuine one-bit change.
    const flipped = new Uint8Array(currentNonce);
    flipped[0] = flipped[0]! ^ 0x01;
    const after = keystreamBlock(currentKey, flipped, 0);

    renderMiniGrid(gridBefore, before, after);
    renderMiniGrid(gridAfter, after, before);

    const bits = bitsDiffer(before, after);
    const pct = ((bits / 512) * 100).toFixed(1);
    acCaption.innerHTML =
      `One nonce bit changed (the low bit of byte 0). Result: <strong>${bits} of 512</strong> ` +
      `keystream bits flipped (<strong>${pct}%</strong>), spread across the whole block — ` +
      `an ideal cipher flips ~50%. Highlighted cells changed value. This is diffusion: ` +
      `a single input bit avalanches into half the output.`;
    compareBox.hidden = false;
  }

  $('#btn-flip-bit').addEventListener('click', runSingleBitAvalanche);

  // Re-render whenever the key or nonce changes anywhere. A nonce change shows
  // the avalanche stat; a key change just refreshes the grid (and hides a now
  // meaningless stat).
  onKeyNonce((reason) => {
    const ks = keystreamBlock(currentKey, currentNonce, 0);
    renderGrid(ks);
    if (reason === 'nonce') showAvalanche(baseline, ks);
    else avalanche.hidden = true;
    baseline = ks;
  });

  $('#btn-show-keystream').addEventListener('click', () => {
    renderGrid(keystreamBlock(currentKey, currentNonce, 0));
    avalanche.hidden = true;
  });

  $('#btn-new-nonce-ks').addEventListener('click', () => setNonce(generateNonce()));

  // Render once on load so the section is never empty.
  renderGrid(baseline);
}

// ─── Section C: Quarter-Round Stepper ────────────────────────
function initQuarterRoundStepper() {
  const stateGrid = $('#state-matrix') as HTMLElement;
  const stepTable = $('#qr-step-table') as HTMLElement;
  const narrate = $('#qr-narrate') as HTMLElement;
  const roundLabel = $('#round-label') as HTMLElement;
  const progress = $('.qr-progress') as HTMLElement;
  const progressBar = $('#qr-progress-bar') as HTMLElement;
  const prevBtn = $('#btn-prev-round') as HTMLButtonElement;
  const playBtn = $('#btn-play-qr') as HTMLButtonElement;
  const nextBtn = $('#btn-next-round') as HTMLButtonElement;

  const LABELS = [
    'const', 'const', 'const', 'const',
    'key', 'key', 'key', 'key',
    'key', 'key', 'key', 'key',
    'ctr', 'nonce', 'nonce', 'nonce',
  ];
  const TOTAL = 80;

  // step 0 = initial state; 1..80 = after that quarter-round; 81 = final (after add).
  let step = 0;
  let playTimer: ReturnType<typeof setInterval> | null = null;

  function hex32(v: number): string {
    return '0x' + (v >>> 0).toString(16).padStart(8, '0');
  }

  function renderMatrix(
    state: number[],
    active: readonly number[] = [],
    changed: ReadonlySet<number> = new Set(),
  ) {
    const activeSet = new Set(active);
    stateGrid.innerHTML = '';
    for (let i = 0; i < 16; i++) {
      const cell = document.createElement('div');
      const role = active.indexOf(i);
      const changedCls = changed.has(i) ? ' matrix-changed' : '';
      cell.className = `matrix-cell matrix-${LABELS[i]}${activeSet.has(i) ? ' matrix-active' : ''}${changedCls}`;
      const tag = role >= 0 ? `<span class="matrix-role">${'abcd'[role]}</span>` : '';
      cell.innerHTML = `${tag}<span class="matrix-val">${hex32(state[i]!)}</span><span class="matrix-lbl">${LABELS[i]}</span>`;
      stateGrid.appendChild(cell);
    }
  }

  function renderSteps(steps: { step: number; a: number; b: number; c: number; d: number }[]) {
    const ops = [
      'a += b; d ^= a; d <<<= 16',
      'c += d; b ^= c; b <<<= 12',
      'a += b; d ^= a; d <<<= 8',
      'c += d; b ^= c; b <<<= 7',
    ];
    let html = '<table><thead><tr><th>Step</th><th>Operation</th><th>a</th><th>b</th><th>c</th><th>d</th></tr></thead><tbody>';
    for (const s of steps) {
      html += `<tr>
        <td>${s.step}</td>
        <td class="op-cell">${ops[s.step - 1]}</td>
        <td>${hex32(s.a)}</td>
        <td>${hex32(s.b)}</td>
        <td>${hex32(s.c)}</td>
        <td>${hex32(s.d)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    stepTable.innerHTML = html;
    // The table is `min-width: 500px` inside an `overflow-x: auto` box and holds
    // nothing focusable, so below ~540px a keyboard user has no way to scroll to
    // the c and d columns (WCAG 2.1.1). Make the container itself the focus
    // target while the table is in it; `showStepMessage` takes it back out.
    stepTable.tabIndex = 0;
  }

  /** Replace the step table with a one-line message — and retire its tab stop. */
  function showStepMessage(html: string) {
    stepTable.innerHTML = html;
    stepTable.removeAttribute('tabindex');
  }

  function setProgress(value: number) {
    progressBar.style.width = `${(value / TOTAL) * 100}%`;
    progress.setAttribute('aria-valuenow', String(value));
  }

  function render() {
    if (!blockResult) return;

    if (step === 0) {
      renderMatrix(blockResult.initialState);
      showStepMessage(
        '<p class="hint-msg">Initial state: constants + key + counter + nonce. Press <strong>Next ▶</strong> to apply the first quarter-round.</p>'
      );
      roundLabel.innerHTML = 'Initial state — <strong>0 of 80</strong> quarter-rounds applied';
      narrate.hidden = true;
      setProgress(0);
    } else if (step <= TOTAL) {
      const idx = step - 1;
      const active = blockResult.active[idx]!;
      const snap = blockResult.snapshots[idx]!;
      // Which of the 16 words changed value in THIS quarter-round.
      const prev = idx === 0 ? blockResult.initialState : blockResult.snapshots[idx - 1]!;
      const changed = new Set<number>();
      for (const i of active) if (snap[i] !== prev[i]) changed.add(i);
      renderMatrix(snap, active, changed);
      renderSteps(blockResult.rounds[idx]!);
      const local = idx % 8;
      const isColumn = local < 4;
      const dr = Math.floor(idx / 8) + 1;
      const positions = `(${active.join(', ')})`;
      roundLabel.innerHTML =
        `Double-round <strong>${dr}/10</strong> · <span class="${isColumn ? 'rt-col' : 'rt-diag'}">${isColumn ? 'Column' : 'Diagonal'} round</span> · ` +
        `quarter-round <strong>${step}/80</strong> mixing words ${positions}`;
      narrate.hidden = false;
      const [ia, ib, ic, id] = active;
      const roundKind = isColumn
        ? `This is a <span class="rt-col">column</span> round: it mixes four words stacked <em>vertically</em>.`
        : `This is a <span class="rt-diag">diagonal</span> round: it mixes four words along a <em>diagonal</em>. Alternating column and diagonal rounds is what carries a change in one word out to <em>every</em> word — that cross-wiring is exactly what the diagonal rounds buy you.`;
      narrate.innerHTML =
        `<strong>What this quarter-round does</strong> to words a=${ia}, b=${ib}, c=${ic}, d=${id}: ` +
        `it runs four <strong>Add–Rotate–XOR</strong> (ARX) steps — e.g. <em>add b into a (wrapping at 2³²), ` +
        `XOR that result into d, then rotate d left 16 bits</em>, repeated with rotations of 12, 8, and 7. ` +
        `Add and rotate move bits between positions; XOR blends them. Together they take a one-bit change ` +
        `and smear it across the whole word — that spreading is <strong>diffusion</strong>, the source of the ` +
        `pseudorandom keystream. ${roundKind}`;
      setProgress(step);
    } else {
      renderMatrix(blockResult.finalState);
      showStepMessage(
        '<p class="done-msg">✓ All 80 quarter-rounds complete. Final state = scrambled working state + initial state (mod 2³²). Serializing these 16 words little-endian yields the 64-byte keystream.</p>'
      );
      roundLabel.innerHTML = '<strong>Complete</strong> — final state ready to serialize into keystream';
      narrate.hidden = false;
      narrate.innerHTML =
        `<strong>Why 80 quarter-rounds?</strong> That is 10 double-rounds (20 rounds). Each double-round is ` +
        `4 column + 4 diagonal quarter-rounds; the alternation guarantees full <strong>avalanche</strong> — ` +
        `every input bit reaches every output word — with a comfortable security margin against known attacks. ` +
        `Fewer rounds diffuse less; 20 is the standardized count.`;
      setProgress(TOTAL);
    }

    prevBtn.disabled = step <= 0;
    nextBtn.disabled = step > TOTAL;
  }

  function stopPlay() {
    if (playTimer !== null) {
      clearInterval(playTimer);
      playTimer = null;
    }
    playBtn.textContent = '▶ Play';
    playBtn.setAttribute('aria-label', 'Auto-play quarter-rounds');
  }

  function goTo(target: number) {
    if (!blockResult) return;
    step = Math.max(0, Math.min(TOTAL + 1, target));
    render();
  }

  $('#btn-run-qr').addEventListener('click', () => {
    stopPlay();
    blockResult = chachaBlock(currentKey, currentNonce, 0);
    step = 0;
    render();
    playBtn.disabled = false;
    nextBtn.disabled = false;
  });

  prevBtn.addEventListener('click', () => {
    stopPlay();
    goTo(step - 1);
  });

  nextBtn.addEventListener('click', () => goTo(step + 1));

  playBtn.addEventListener('click', () => {
    if (!blockResult) return;
    if (playTimer !== null) {
      stopPlay();
      return;
    }
    if (step > TOTAL) goTo(0); // replay from the start
    playBtn.textContent = '⏸ Pause';
    playBtn.setAttribute('aria-label', 'Pause auto-play');
    playTimer = setInterval(() => {
      if (step > TOTAL) {
        stopPlay();
        return;
      }
      goTo(step + 1);
    }, 350);
  });

  // If the key/nonce changes after a block was initialized, recompute so the
  // matrix never disagrees with the key/nonce shown above.
  onKeyNonce(() => {
    if (!blockResult) return;
    stopPlay();
    blockResult = chachaBlock(currentKey, currentNonce, 0);
    render();
  });
}

// ─── Section D: Nonce Reuse Attack ───────────────────────────
function initNonceReuse() {
  const msg1 = $('#nonce-msg1') as HTMLTextAreaElement;
  const msg2 = $('#nonce-msg2') as HTMLTextAreaElement;
  const ct1Display = $('#nr-ct1') as HTMLElement;
  const ct2Display = $('#nr-ct2') as HTMLElement;
  const xorDisplay = $('#nr-xor') as HTMLElement;
  const explDisplay = $('#nr-explanation') as HTMLElement;
  const cribBlock = $('#crib-drag') as HTMLElement;
  const cribGuess = $('#crib-guess') as HTMLInputElement;
  const cribOutput = $('#crib-output') as HTMLElement;

  // The leak (pt1 ⊕ pt2) from the most recent attack, used for crib-dragging.
  let lastXor: Uint8Array | null = null;

  /** Render recovered bytes: printable ASCII as-is, others as a dim dot. */
  function renderRecovered(bytes: Uint8Array): string {
    let html = '';
    for (const b of bytes) {
      if (b >= 0x20 && b < 0x7f) {
        const ch = String.fromCharCode(b)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
        html += `<span class="crib-char">${ch === ' ' ? '&nbsp;' : ch}</span>`;
      } else {
        html += '<span class="crib-gap">·</span>';
      }
    }
    return html;
  }

  function updateCrib() {
    if (!lastXor) return;
    cribOutput.innerHTML = renderRecovered(cribDrag(lastXor, cribGuess.value));
  }

  cribGuess.addEventListener('input', updateCrib);

  $('#btn-nonce-reuse').addEventListener('click', () => {
    const text1 = msg1.value || 'Attack at dawn';
    const text2 = msg2.value || 'Retreat to base';
    const key = generateKey();
    const nonce = generateNonce();
    const result = nonceReuseDemo(text1, text2, key, nonce);

    ct1Display.textContent = toHex(result.ct1);
    ct2Display.textContent = toHex(result.ct2);

    // Render XOR result with highlighting
    let xorHtml = '';
    const pt1Bytes = new TextEncoder().encode(text1);
    const pt2Bytes = new TextEncoder().encode(text2);
    const minLen = Math.min(pt1Bytes.length, pt2Bytes.length);
    for (let i = 0; i < result.xorResult.length; i++) {
      const expectedXor = i < minLen ? (pt1Bytes[i]! ^ pt2Bytes[i]!) >>> 0 : 0;
      const match = i < minLen && result.xorResult[i] === expectedXor;
      const hex = result.xorResult[i]!.toString(16).padStart(2, '0');
      xorHtml += `<span class="${match ? 'xor-match' : 'xor-byte'}">${hex}</span>`;
    }
    xorDisplay.innerHTML = xorHtml;
    explDisplay.textContent = result.explanation;

    // Set up the crib-drag: pre-fill with the real Message 1 so recovery is
    // perfect, then let the user degrade it to see how the attack depends on
    // the guess — not on any secret.
    lastXor = result.xorResult;
    cribGuess.value = text1;
    cribBlock.hidden = false;
    updateCrib();
  });
}

// ─── Theme toggle ────────────────────────────────────────────
function initThemeToggle() {
  const toggle = $('#theme-toggle') as HTMLButtonElement;
  const root = document.documentElement;

  function update() {
    const theme = root.getAttribute('data-theme') ?? 'dark';
    const isDark = theme === 'dark';
    toggle.textContent = isDark ? '🌙' : '☀️';
    toggle.setAttribute('aria-label',
      isDark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  toggle.addEventListener('click', () => {
    const current = root.getAttribute('data-theme') ?? 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try {
      localStorage.setItem('theme', next);
    } catch {
      // localStorage can be unavailable (private browsing); theme still applies.
    }
    update();
  });

  update();
}

// ─── Info Tabs ───────────────────────────────────────────────
function initInfoTabs() {
  const tabs = document.querySelectorAll('.info-tab-btn');
  const panels = document.querySelectorAll('.info-tab-panel');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
      });
      panels.forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      const target = (tab as HTMLElement).dataset.tab!;
      $(`#tab-${target}`).classList.add('active');
    });
  });
}

// ─── Init ────────────────────────────────────────────────────
export function initUI() {
  initEncryptDecrypt();
  initKeystreamViz();
  initQuarterRoundStepper();
  initNonceReuse();
  initThemeToggle();
  initInfoTabs();
}

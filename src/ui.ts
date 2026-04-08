// UI wiring — connects DOM to cipher.ts and quarterround.ts
import {
  encrypt,
  decrypt,
  generateKey,
  generateNonce,
  nonceReuseDemo,
  getKeystream,
  toHex,
} from './cipher.ts';
import { chachaBlock } from './quarterround.ts';
import type { ChachaBlockResult } from './quarterround.ts';

// ─── State ───────────────────────────────────────────────────
let currentKey = generateKey();
let currentNonce = generateNonce();
let lastCiphertext: Uint8Array | null = null;

// Quarter-round stepper state
let blockResult: ChachaBlockResult | null = null;
let currentRoundIndex = 0;

// ─── Helpers ─────────────────────────────────────────────────
function $(sel: string): HTMLElement {
  return document.querySelector(sel)!;
}

function copyToClipboard(text: string, btn: HTMLElement) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => (btn.textContent = orig), 1200);
  });
}

function byteColor(byte: number): string {
  // gradient: low=blue (#3b82f6), high=red (#ef4444)
  const t = byte / 255;
  const r = Math.round(59 + t * (239 - 59));
  const g = Math.round(130 + t * (68 - 130));
  const b = Math.round(246 + t * (68 - 246));
  return `rgb(${r},${g},${b})`;
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

  function refreshKeyNonce() {
    keyDisplay.textContent = toHex(currentKey);
    nonceDisplay.textContent = toHex(currentNonce);
    keyLen.textContent = `${currentKey.length} bytes`;
    nonceLen.textContent = `${currentNonce.length} bytes`;
  }

  refreshKeyNonce();

  ptInput.addEventListener('input', () => {
    const len = new TextEncoder().encode(ptInput.value).length;
    ptLen.textContent = `${len} bytes`;
  });

  $('#btn-regen-key').addEventListener('click', () => {
    currentKey = generateKey();
    refreshKeyNonce();
  });

  $('#btn-regen-nonce').addEventListener('click', () => {
    currentNonce = generateNonce();
    refreshKeyNonce();
  });

  $('#btn-copy-key').addEventListener('click', () => {
    copyToClipboard(toHex(currentKey), $('#btn-copy-key'));
  });

  $('#btn-copy-nonce').addEventListener('click', () => {
    copyToClipboard(toHex(currentNonce), $('#btn-copy-nonce'));
  });

  $('#btn-encrypt').addEventListener('click', () => {
    const pt = ptInput.value;
    if (!pt) return;
    lastCiphertext = encrypt(pt, currentKey, currentNonce);
    const hex = toHex(lastCiphertext);
    ctDisplay.textContent = hex;
    ctLen.textContent = `${lastCiphertext.length} bytes`;
    decryptedDisplay.textContent = '';
  });

  $('#btn-decrypt').addEventListener('click', () => {
    if (!lastCiphertext) return;
    const pt = decrypt(lastCiphertext, currentKey, currentNonce);
    decryptedDisplay.textContent = pt;
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

  function renderKeystream() {
    const ks = getKeystream(currentKey, currentNonce, 64);
    grid.innerHTML = '';
    for (let i = 0; i < ks.length; i++) {
      const cell = document.createElement('div');
      cell.className = 'ks-cell';
      cell.textContent = ks[i]!.toString(16).padStart(2, '0');
      cell.style.backgroundColor = byteColor(ks[i]!);
      cell.style.color = ks[i]! > 140 ? '#fff' : '#1e1e2e';
      grid.appendChild(cell);
    }
  }

  $('#btn-show-keystream').addEventListener('click', renderKeystream);

  $('#btn-new-nonce-ks').addEventListener('click', () => {
    currentNonce = generateNonce();
    $('#nonce-display').textContent = toHex(currentNonce);
    $('#nonce-len').textContent = `${currentNonce.length} bytes`;
    renderKeystream();
  });
}

// ─── Section C: Quarter-Round Stepper ────────────────────────
function initQuarterRoundStepper() {
  const stateGrid = $('#state-matrix') as HTMLElement;
  const stepTable = $('#qr-step-table') as HTMLElement;
  const roundLabel = $('#round-label') as HTMLElement;

  function renderMatrix(state: number[]) {
    stateGrid.innerHTML = '';
    const labels = [
      'const', 'const', 'const', 'const',
      'key', 'key', 'key', 'key',
      'key', 'key', 'key', 'key',
      'ctr', 'nonce', 'nonce', 'nonce',
    ];
    for (let i = 0; i < 16; i++) {
      const cell = document.createElement('div');
      cell.className = `matrix-cell matrix-${labels[i]}`;
      cell.innerHTML = `<span class="matrix-val">0x${state[i]!.toString(16).padStart(8, '0')}</span><span class="matrix-lbl">${labels[i]}</span>`;
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
        <td>0x${s.a.toString(16).padStart(8, '0')}</td>
        <td>0x${s.b.toString(16).padStart(8, '0')}</td>
        <td>0x${s.c.toString(16).padStart(8, '0')}</td>
        <td>0x${s.d.toString(16).padStart(8, '0')}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    stepTable.innerHTML = html;
  }

  $('#btn-run-qr').addEventListener('click', () => {
    blockResult = chachaBlock(currentKey, currentNonce, 0);
    currentRoundIndex = 0;
    renderMatrix(blockResult.initialState);
    renderSteps(blockResult.rounds[0]!);
    roundLabel.textContent = 'Round 1 of 80 quarter-rounds (20 rounds × 4 QRs)';
    $('#btn-next-round').removeAttribute('disabled');
  });

  $('#btn-next-round').addEventListener('click', () => {
    if (!blockResult) return;
    currentRoundIndex++;
    if (currentRoundIndex >= blockResult.rounds.length) {
      roundLabel.textContent = 'All 80 quarter-rounds complete — showing final state';
      renderMatrix(blockResult.finalState);
      stepTable.innerHTML = '<p class="done-msg">✓ Final state = working state + initial state (mod 2³²)</p>';
      $('#btn-next-round').setAttribute('disabled', '');
      return;
    }
    renderSteps(blockResult.rounds[currentRoundIndex]!);
    roundLabel.textContent = `Quarter-round ${currentRoundIndex + 1} of 80`;
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
  });
}

// ─── Theme toggle ────────────────────────────────────────────
function initThemeToggle() {
  const toggle = $('#theme-toggle') as HTMLButtonElement;
  const root = document.documentElement;

  // Check system preference or stored preference
  const stored = localStorage.getItem('theme');
  if (stored) {
    root.setAttribute('data-theme', stored);
  }

  toggle.addEventListener('click', () => {
    const current = root.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    toggle.textContent = next === 'dark' ? '☀️' : '🌙';
  });

  // Set initial icon
  const isDark =
    root.getAttribute('data-theme') === 'dark' ||
    (!stored && window.matchMedia('(prefers-color-scheme: dark)').matches);
  toggle.textContent = isDark ? '☀️' : '🌙';
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

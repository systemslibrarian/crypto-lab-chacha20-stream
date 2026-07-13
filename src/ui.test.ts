// @vitest-environment happy-dom
//
// Integration smoke test: boot the actual UI against the real index.html and
// drive each section the way a user would. Catches DOM-wiring regressions
// (missing IDs, broken handlers) that unit tests can't see.
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { initUI } from './ui.ts';

// vitest runs with cwd at the project root.
const html = readFileSync(join(process.cwd(), 'index.html'), 'utf-8');
// Use only the markup inside <body>, minus the module script tag (happy-dom
// would try to resolve the bundler-style import).
const body = html
  .slice(html.indexOf('<body>') + 6, html.indexOf('</body>'))
  .replace(/<script[\s\S]*?<\/script>/g, '');

function $(sel: string): HTMLElement {
  return document.querySelector(sel)!;
}
function click(sel: string) {
  ($(sel) as HTMLElement).click();
}

describe('UI integration', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.innerHTML = body;
    initUI();
  });

  it('boots and populates key, nonce, and live ciphertext', () => {
    expect($('#key-display').textContent).toMatch(/^[0-9a-f]{64}$/);
    expect($('#nonce-display').textContent).toMatch(/^[0-9a-f]{24}$/);
    // Plaintext is pre-filled, so live encryption should have produced hex.
    expect($('#ciphertext-display').textContent).toMatch(/^[0-9a-f]+$/);
  });

  it('Section A XOR visual is honest: pt ⊕ ks equals the ciphertext byte-for-byte', () => {
    // Three rows (pt, ks, ct), one column per plaintext byte. Read the hex out
    // of each row and verify pt[i] ^ ks[i] === ct[i] for every byte — this
    // guards against the visual ever faking the keystream or the XOR.
    const cells = [...$('#xor-viz').querySelectorAll('.xor-cell')] as HTMLElement[];
    expect(cells.length).toBeGreaterThan(0);
    expect(cells.length % 3).toBe(0);
    const n = cells.length / 3;
    const hexOf = (el: HTMLElement) =>
      parseInt(el.querySelector('.xor-hex')!.textContent!, 16);
    for (let i = 0; i < n; i++) {
      const pt = hexOf(cells[i]!);
      const ks = hexOf(cells[n + i]!);
      const ct = hexOf(cells[2 * n + i]!);
      expect((pt ^ ks) & 0xff).toBe(ct);
    }
    // And the ct row must equal the ciphertext shown in the output box.
    const ctHex = Array.from({ length: n }, (_, i) =>
      hexOf(cells[2 * n + i]!).toString(16).padStart(2, '0')).join('');
    expect($('#ciphertext-display').textContent).toBe(ctHex);
  });

  it('single-bit avalanche renders before/after grids with changed cells flagged', () => {
    click('#btn-flip-bit');
    expect($('#avalanche-compare').hasAttribute('hidden')).toBe(false);
    expect($('#ac-grid-before').children).toHaveLength(64);
    expect($('#ac-grid-after').children).toHaveLength(64);
    // A one-bit nonce change must flip a large fraction of bytes (diffusion).
    const changed = document.querySelectorAll('#ac-grid-after .ac-cell-changed').length;
    expect(changed).toBeGreaterThan(40);
    expect($('#ac-caption').textContent).toMatch(/512/);
  });

  it('round-trips: decrypt recovers the plaintext', () => {
    const pt = ($('#plaintext-input') as HTMLTextAreaElement).value;
    click('#btn-decrypt');
    expect($('#decrypted-display').textContent).toBe(pt);
  });

  it('renders a 64-cell keystream grid on load', () => {
    expect($('#keystream-grid').children).toHaveLength(64);
  });

  it('keystream visualizer shows an avalanche stat after a new nonce', () => {
    click('#btn-new-nonce-ks');
    expect($('#avalanche').hasAttribute('hidden')).toBe(false);
    expect($('#avalanche').textContent).toMatch(/bits flipped/);
  });

  it('regenerating the nonce in Section B keeps Section A consistent', () => {
    const input = $('#plaintext-input') as HTMLTextAreaElement;
    input.value = 'consistency check';
    input.dispatchEvent(new Event('input'));

    // Regenerate the nonce from the keystream section...
    click('#btn-new-nonce-ks');
    // ...the shared nonce display updates,
    expect($('#nonce-display').textContent).toMatch(/^[0-9a-f]{24}$/);
    // ...and decrypting in Section A still recovers the plaintext (the
    // ciphertext was re-encrypted under the new nonce, not left stale).
    click('#btn-decrypt');
    expect($('#decrypted-display').textContent).toBe('consistency check');
  });

  it('quarter-round stepper walks the full block', () => {
    click('#btn-run-qr');
    expect($('#state-matrix').children).toHaveLength(16);
    // No active highlight on the initial state.
    expect(document.querySelectorAll('.matrix-active')).toHaveLength(0);

    click('#btn-next-round'); // first quarter-round
    expect(document.querySelectorAll('.matrix-active')).toHaveLength(4);
    expect($('#round-label').textContent).toMatch(/quarter-round 1\/80/);
    // Plain-English narration is revealed and describes the ARX mechanism.
    expect($('#qr-narrate').hasAttribute('hidden')).toBe(false);
    expect($('#qr-narrate').textContent).toMatch(/Add.?Rotate.?XOR|diffusion/);
    // At least one active word changed value and is flagged.
    expect(document.querySelectorAll('.matrix-changed').length).toBeGreaterThan(0);

    // Step to the end.
    for (let i = 0; i < 81; i++) click('#btn-next-round');
    expect($('#round-label').textContent).toMatch(/Complete/);
    expect(($('#btn-next-round') as HTMLButtonElement).disabled).toBe(true);
  });

  it('nonce-reuse attack reveals the leak and enables crib-drag', () => {
    click('#btn-nonce-reuse');
    expect($('#nr-ct1').textContent).toMatch(/^[0-9a-f]+$/);
    expect($('#nr-xor').children.length).toBeGreaterThan(0);

    const crib = $('#crib-drag');
    expect(crib.hasAttribute('hidden')).toBe(false);
    // Guess is pre-filled with the real Message 1, so recovery is non-empty.
    expect($('#crib-output').textContent!.length).toBeGreaterThan(0);
  });

  it('theme toggle flips data-theme', () => {
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    click('#theme-toggle');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('info tabs switch panels', () => {
    click('#tabbtn-safety');
    expect($('#tab-safety').classList.contains('active')).toBe(true);
    expect($('#tabbtn-safety').getAttribute('aria-selected')).toBe('true');
    expect($('#tab-comparison').classList.contains('active')).toBe(false);
  });
});

// ADA / WCAG: every interactive control must expose an accessible name. -------
describe('accessibility', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.innerHTML = body;
    initUI();
    // Reveal the crib-drag controls so they're audited too.
    ($('#btn-nonce-reuse') as HTMLElement).click();
  });

  /** True if the element has a non-empty accessible name. */
  function hasName(el: Element): boolean {
    const aria = el.getAttribute('aria-label');
    if (aria && aria.trim()) return true;
    const labelledby = el.getAttribute('aria-labelledby');
    if (labelledby && labelledby.trim()) return true;
    if (el.id && document.querySelector(`label[for="${el.id}"]`)) return true;
    if (el.closest('label')) return true;
    return !!el.textContent && el.textContent.trim().length > 0;
  }

  it('every button has an accessible name', () => {
    const unnamed = [...document.querySelectorAll('button')]
      .filter((b) => !hasName(b))
      .map((b) => b.outerHTML);
    expect(unnamed).toEqual([]);
  });

  it('every text input and textarea has an associated label or aria-label', () => {
    const unnamed = [...document.querySelectorAll('input, textarea, select')]
      .filter((el) => !hasName(el))
      .map((el) => el.outerHTML);
    expect(unnamed).toEqual([]);
  });

  it('result regions announce updates via aria-live', () => {
    expect($('#ciphertext-display').getAttribute('aria-live')).toBe('polite');
    expect($('#avalanche').getAttribute('aria-live')).toBe('polite');
    expect($('#round-label').getAttribute('aria-live')).toBe('polite');
    expect($('.qr-progress').getAttribute('role')).toBe('progressbar');
  });
});

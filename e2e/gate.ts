import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here, each of them a correction to the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old gate pushed
 *     `animation-duration: 0s; transition-duration: 0s; scroll-behavior: auto`
 *     through `addStyleTag`. That overrides this lab's own
 *     `@media (prefers-reduced-motion: reduce)` blocks instead of exercising
 *     them, so it could not catch the defect where a reduced-motion path
 *     cancels an animation without restoring its end state. This lab has two
 *     such blocks — one collapsing `.matrix-cell`'s transition and
 *     `.matrix-active`'s 2px lift, one collapsing `.qr-progress-bar`'s width
 *     transition — and both were audited: neither declaration is anything but
 *     `transition: none` / `transform: none`, and neither is the only route to
 *     a visible state. `boot` asks for the preference, asserts it took effect,
 *     and `settle` waits for whatever is running to drain — the same
 *     determinism, obtained honestly.
 *
 *  2. IT THREW AWAY EVERY STATE IT BUILT. The old gate drove the whole lab —
 *     encrypt, decrypt, keystream, avalanche, stepper, tabs, nonce reuse — and
 *     then ran ONE axe pass at the very end. Each click overwrote the last, so
 *     the only state ever measured was the terminal one: the safety tab
 *     showing, the stepper parked on quarter-round 1, the crib-drag open. Here
 *     every step is scanned.
 *
 *  3. IT FORCE-OPENED WHAT A READER HAS TO CLICK. `openAllDetails` set
 *     `details.open = true` from script, so the shut state was never scanned
 *     and the open one was never reached the way a reader reaches it. `<details>`
 *     is opened by its `<summary>` here.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * Set `A11Y_COLLECT=1` and a run records every failed assertion instead of
 * stopping at the first, so a whole configuration's findings can be read off in
 * one pass and fixed together. Unset — which is every CI run, every local run,
 * and the default in every editor — `softExpect` is an ordinary strict
 * `expect`, so this costs the gate nothing.
 *
 * The one thing that must never happen is a collecting run being mistaken for a
 * passing gate. `reportCollected`, called at the end of every test, throws if
 * anything was recorded, so a collecting run with findings still exits red and
 * still prints them.
 */
const COLLECTING = process.env.A11Y_COLLECT === '1';
const collected: string[] = [];

function softExpect(received: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(received, message).toEqual(expected);
    return;
  }
  try {
    expect(received, message).toEqual(expected);
  } catch {
    collected.push(`${message}\n  ${JSON.stringify(received, null, 2).replace(/\n/g, '\n  ')}`);
  }
}

/** Fail a collecting run that recorded anything, after printing everything. */
export function reportCollected(): void {
  if (!COLLECTING || collected.length === 0) return;
  const report = collected.join('\n\n');
  collected.length = 0;
  throw new Error(
    `A11Y_COLLECT run recorded ${report.split('\n\n').length} failing assertions:\n\n${report}`
  );
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * declares no `@keyframes` at all and its two reduced-motion blocks only cancel
 * transitions and a decorative `translateY(-2px)`, so it is not currently
 * exposed. The assertion stays because it is the only thing standing between
 * that guarantee and the first `animation: fade-in` anyone adds, and because it
 * also catches the unrelated case of a panel revealed by clearing `hidden`
 * while something above it still holds `opacity: 0`.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`, []);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert THE LAB'S DEFAULTS rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The block of default assertions below is not decoration. A gate that scans
 * one configuration scans one half, and which half depends on the defaults. Two
 * of these in particular decide what the rest of the drive measures:
 *
 *  - THE PAGE ARRIVES ALREADY ENCRYPTED. `initEncryptDecrypt` calls
 *    `liveEncrypt()` at init, so `#ciphertext-display` and the whole `.xor-viz`
 *    grid — 3 rows x 43 columns of tinted cells, and the only place this lab's
 *    three fixed row tints are ever painted — exist at first paint. If that
 *    ever changed to a click-to-encrypt flow, the first-paint scan would
 *    silently stop covering them.
 *  - THE STEPPER ARRIVES LOCKED. Prev / Play / Next are all `disabled` until
 *    "Initialize Block" is pressed, and `#state-matrix` is empty. That locked
 *    state is a real state a visitor lands in, so it is asserted here and
 *    scanned before the unlock rather than skipped past.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  // Playwright may run two of the four configurations in one worker process, so
  // a collecting run that died mid-drive could otherwise carry its findings into
  // the next test and report them against the wrong configuration.
  collected.length = 0;
  await page.emulateMedia({ reducedMotion: 'reduce' });
  // Both the anti-flash script in index.html's <head> and the shared header's
  // toggle use the key 'theme'; seeding it is the same route a returning
  // visitor takes.
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // ── Section A arrives live ────────────────────────────────────────────────
  await expect(page.locator('#plaintext-input')).toHaveValue(
    'The quick brown fox jumps over the lazy dog'
  );
  await expect(page.locator('#key-display')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('#nonce-display')).toHaveText(/^[0-9a-f]{24}$/);
  await expect(page.locator('#ciphertext-display')).toHaveText(/^[0-9a-f]{86}$/);
  await expect(page.locator('#decrypted-display')).toBeEmpty();
  await expect(page.locator('.xor-cell')).toHaveCount(43 * 3);
  await expect(page.locator('.xor-col-active')).toHaveCount(0);

  // ── Section B: grid painted on load, both readouts still shut ─────────────
  await expect(page.locator('#keystream-grid .ks-cell')).toHaveCount(64);
  await expect(page.locator('#avalanche')).toBeHidden();
  await expect(page.locator('#avalanche-compare')).toBeHidden();

  // ── Section C: locked until the block is initialised ──────────────────────
  await expect(page.locator('#state-matrix')).toBeEmpty();
  await expect(page.locator('#qr-step-table')).toBeEmpty();
  // Empty, therefore not a scroller, therefore not a tab stop. The paired
  // assertions in the drive are what keep that conditional honest.
  await expect(page.locator('#qr-step-table')).not.toHaveAttribute('tabindex', /.*/);
  await expect(page.locator('.table-scroll')).toHaveAttribute('tabindex', '0');
  await expect(page.locator('#qr-narrate')).toBeHidden();
  for (const id of ['#btn-prev-round', '#btn-play-qr', '#btn-next-round']) {
    await expect(page.locator(id)).toBeDisabled();
  }
  await expect(page.locator('.qr-progress')).toHaveAttribute('aria-valuenow', '0');

  // ── Section D: no attack run yet, crib-drag shut ──────────────────────────
  await expect(page.locator('#nr-ct1')).toBeEmpty();
  await expect(page.locator('#crib-drag')).toBeHidden();

  // ── Info panel: tab 1 selected, tabs 2 and 3 not ──────────────────────────
  await expect(page.locator('#tabbtn-comparison')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#tabbtn-matrix')).toHaveAttribute('aria-selected', 'false');
  await expect(page.locator('#tabbtn-safety')).toHaveAttribute('aria-selected', 'false');
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: it prints a 64-hex-character key and an 86-char
 * ciphertext, lays 64 keystream bytes out on a fixed-column grid, draws a 4x4
 * state matrix of `0x`-prefixed 32-bit words, and renders one XOR column per
 * plaintext byte.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has three such decoys:
    // the XOR grid, the quarter-round step table and the state-matrix legend
    // all scroll sideways inside their own containers.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  softExpect(overflow, `page must not scroll horizontally in state: ${label}`, null);
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is the assertion that found most of this lab's defects, and all four of
 * them at once. `.xor-viz` was the only scroller the author had thought about —
 * it carries `tabindex="0"` and its own arrow-key handler. Four more were
 * `overflow: auto` around content that genuinely overflowed while holding
 * nothing focusable, so a keyboard-only reader could not reach what was inside:
 * `#qr-step-table` (500x232 in 322), `.table-scroll` (352x162 in 322),
 * `#key-display` (524x33 in 320) and, once a long enough message was typed,
 * `#ciphertext-display` (320x209 in 88). The two hex boxes were fixed by
 * letting the text wrap instead of scroll; the two tables, whose columns cannot
 * reflow, were made focus targets. See `style.css` for which fix went where and
 * why.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
    []
  );
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every tinted surface on the page is a translucent `rgba()` over a themed
 *    colour and the hero aside is a `color-mix()`, all of which axe declines to
 *    resolve. Everything else in that bucket is a real result axe simply could
 *    not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less div hides, a defect that never reaches the
 *    violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Measure contrast inside one subtree while a short-lived state is set, then
 * confirm the state was still set when the measurement finished.
 *
 * A full `scan` takes several seconds; `copyToClipboard` restores the button
 * label after 1200ms and `#btn-decrypt` drops `.recovered` after 600ms. Scoping
 * the walk to the element itself brings the measurement under a couple of
 * milliseconds, and re-reading the state afterwards is what makes the result an
 * assertion rather than a coin flip: a measurement taken after the class was
 * already gone would report the resting colours and quietly pass.
 */
async function expectTransientContrast(page: Page, selector: string, label: string): Promise<void> {
  const failures = Array.from(
    new Set(formatContrastFailures(await auditContrast(page, `${selector}, ${selector} *`)))
  );
  softExpect(failures, `measured contrast failures in transient state: ${label}`, []);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE THREE XOR ROW TINTS ARE THE EXHIBIT, and they are also where this
 *    lab's contrast defect lived. They are painted at first paint, survive
 *    every key/nonce change, and vanish entirely when the plaintext is emptied.
 *    All three of those states are scanned.
 *
 *  - THE EMPTY STATES ARE REAL STATES. Clearing the plaintext drops the whole
 *    XOR grid, the ciphertext, the byte counts and the decrypted box to nothing
 *    — `liveEncrypt` has an explicit branch for it — and clearing the crib-drag
 *    guess renders 15 `.crib-gap` dots and no recovered characters. Both are
 *    driven, because a panel that renders only placeholder glyphs is exactly
 *    where an ink chosen against a full-colour mock stops working.
 *
 *  - THE STEPPER IS 82 STATES WIDE AND THREE SHAPES DEEP. Rendering differs at
 *    step 0 (initial state, hint message, narration hidden), on a column round,
 *    on a diagonal round (`.rt-col` vs `.rt-diag` ink, different narration),
 *    and at step 81 (the `.done-msg` completion panel). Those four are scanned,
 *    plus the Play/Pause fork and the Prev branch; the intervening
 *    quarter-rounds are driven to reach step 81 but are the same rendering with
 *    different hex, and scanning all 80 would add nothing but an hour.
 *
 *  - `<details>` IS OPENED BY ITS SUMMARY, so the shut state is scanned too and
 *    the open one is reached the way a reader reaches it.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, live ciphertext and XOR grid');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── Section A — the XOR exhibit ──────────────────────────────────────────
  // Trace-a-byte highlight: the container is the focus target, arrows walk it.
  await page.locator('#xor-viz').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('.xor-col-active')).toHaveCount(3);
  await scanAt('XOR column 1 traced by keyboard');

  await page.locator('#btn-encrypt').click();
  await expect(page.locator('#ciphertext-display')).toHaveText(/^[0-9a-f]{86}$/);
  await scanAt('Encrypt pressed');

  await page.locator('#btn-decrypt').click();
  await expect(page.locator('#decrypted-display')).toHaveText(
    'The quick brown fox jumps over the lazy dog'
  );
  // `.recovered` lives 600ms — far shorter than a full scan, so it is measured
  // narrowly and its presence re-checked, rather than scanned and missed.
  await expect(page.locator('#decrypted-display')).toHaveClass(/recovered/);
  await expectTransientContrast(page, '#decrypted-display', `${theme} / decrypted box flashing`);
  await expect(page.locator('#decrypted-display')).toHaveClass(/recovered/);
  await scanAt('round-trip decrypted');

  // Clipboard feedback: the label is swapped for 1200ms whichever way the
  // Clipboard API resolves, so this is a real state regardless of permissions.
  await page.locator('#btn-copy-key').click();
  await expect(page.locator('#btn-copy-key')).toHaveText(/Copied!|Failed|Unavailable/);
  await expectTransientContrast(page, '#btn-copy-key', `${theme} / copy button feedback`);
  await expect(page.locator('#btn-copy-key')).toHaveText(/Copied!|Failed|Unavailable/);
  await expect(page.locator('#btn-copy-key')).toHaveText('Copy');
  await scanAt('copy button label restored');

  // The empty branch of `liveEncrypt`: no ciphertext, no grid, no byte counts.
  await page.locator('#plaintext-input').fill('');
  await expect(page.locator('.xor-cell')).toHaveCount(0);
  await expect(page.locator('#ciphertext-display')).toBeEmpty();
  await scanAt('plaintext emptied, XOR grid and ciphertext cleared');

  // A single multi-byte character: one plaintext char, three XOR columns, and
  // the non-printable placeholder glyph on two of them.
  await page.locator('#plaintext-input').fill('☃');
  await expect(page.locator('.xor-cell')).toHaveCount(9);
  await scanAt('multi-byte plaintext, placeholder glyphs in the XOR grid');

  // A LONG message. This state exists because a container that only overflows
  // after a long run is a systematic WCAG 2.1.1 miss: `.output-box` is capped at
  // 90px with `overflow-y: auto` below 600px, and the 43-byte default plaintext
  // produces an 86-character ciphertext that fits inside the cap, so no other
  // state in this drive ever makes it scroll. 160 bytes produce 320 hex
  // characters, which do.
  const LONG = 'Never repeat a nonce under the same key. '.repeat(4);
  await page.locator('#plaintext-input').fill(LONG);
  await expect(page.locator('#pt-len')).toHaveText(`${LONG.length} bytes`);
  await expect(page.locator('#ciphertext-display')).toHaveText(
    new RegExp(`^[0-9a-f]{${LONG.length * 2}}$`)
  );
  await scanAt('long plaintext, ciphertext overflowing the output box');

  await page.locator('#plaintext-input').fill('The quick brown fox jumps over the lazy dog');
  await expect(page.locator('.xor-cell')).toHaveCount(43 * 3);
  await scanAt('plaintext restored');

  // Regenerating the key re-encrypts everywhere and retires the avalanche stat.
  const key0 = await page.locator('#key-display').textContent();
  await page.locator('#btn-regen-key').click();
  await expect(page.locator('#key-display')).not.toHaveText(key0 ?? '');
  await expect(page.locator('#avalanche')).toBeHidden();
  await scanAt('key regenerated');

  // ── Section B — keystream, and both avalanche readouts ───────────────────
  await page.locator('#btn-show-keystream').click();
  await expect(page.locator('#keystream-grid .ks-cell')).toHaveCount(64);
  await scanAt('keystream shown');

  // A nonce change is the one route to the `.avalanche` stat panel.
  await page.locator('#btn-new-nonce-ks').click();
  await expect(page.locator('#avalanche')).toBeVisible();
  await expect(page.locator('#avalanche')).toContainText(/of 512 keystream bits flipped/);
  await scanAt('nonce regenerated, avalanche stat shown');

  // The single-bit comparison is a separate panel with its own `.ac-cell` /
  // `.ac-cell-changed` tones and its own caption.
  await page.locator('#btn-flip-bit').click();
  await expect(page.locator('#avalanche-compare')).toBeVisible();
  await expect(page.locator('.ac-cell')).toHaveCount(128);
  await expect(page.locator('.ac-cell-changed').first()).toBeVisible();
  await scanAt('single-bit avalanche comparison open');

  // ── Section C — the quarter-round stepper ────────────────────────────────
  await page.locator('#btn-run-qr').click();
  await expect(page.locator('.matrix-cell')).toHaveCount(16);
  await expect(page.locator('#round-label')).toContainText('0 of 80');
  await expect(page.locator('#qr-narrate')).toBeHidden();
  await expect(page.locator('#qr-step-table')).not.toHaveAttribute('tabindex', /.*/);
  await expect(page.locator('#btn-prev-round')).toBeDisabled();
  await expect(page.locator('#btn-next-round')).toBeEnabled();
  await scanAt('block initialised, step 0');

  // Quarter-round 1 is a COLUMN round: `.rt-col` ink, four `.matrix-active`
  // cells, the `▲ changed` markers, and the 4-row operation table.
  await page.locator('#btn-next-round').click();
  await expect(page.locator('#round-label .rt-col')).toHaveText('Column round');
  await expect(page.locator('.matrix-active')).toHaveCount(4);
  await expect(page.locator('#qr-step-table tbody tr')).toHaveCount(4);
  await expect(page.locator('#qr-step-table')).toHaveAttribute('tabindex', '0');
  await expect(page.locator('#qr-narrate')).toBeVisible();
  await scanAt('quarter-round 1 of 80, column round');

  // Quarter-round 5 is the first DIAGONAL round — a different ink (`.rt-diag`,
  // amber where the column round is accent-blue) and a longer narration.
  for (let i = 0; i < 4; i++) await page.locator('#btn-next-round').click();
  await expect(page.locator('#round-label .rt-diag')).toHaveText('Diagonal round');
  await scanAt('quarter-round 5 of 80, diagonal round');

  await page.locator('#btn-prev-round').click();
  await expect(page.locator('#round-label')).toContainText('quarter-round 4/80');
  await scanAt('stepped back to quarter-round 4');

  // Play / Pause is a genuine mode fork: the button relabels and re-aria-labels
  // itself, and a 350ms timer rewrites the matrix under the reader. That timer
  // is also why the RUNNING state gets a scoped measurement rather than a full
  // `scan`: an axe pass plus a contrast walk take seconds, and both would be
  // reading a DOM that changed several times beneath them — the contrast walk
  // memoises rects on the explicit promise that nothing mutates during the
  // pass. The running state's only rendering the paused state does not also
  // have is the button's own label, so that is what is measured here, and the
  // matrix it is advancing through is scanned in every shape it takes.
  await page.locator('#btn-play-qr').click();
  await expect(page.locator('#btn-play-qr')).toHaveText('⏸ Pause');
  await expect(page.locator('#btn-play-qr')).toHaveAttribute('aria-label', 'Pause auto-play');
  await expect(page.locator('#round-label')).not.toContainText('quarter-round 4/80');
  await expectTransientContrast(page, '#btn-play-qr', `${theme} / auto-play running`);

  await page.locator('#btn-play-qr').click();
  await expect(page.locator('#btn-play-qr')).toHaveText('▶ Play');
  await expect(page.locator('#btn-play-qr')).toHaveAttribute(
    'aria-label',
    'Auto-play quarter-rounds'
  );
  await scanAt('auto-play paused mid-run');

  // Walk to the terminal state. The intervening renderings are identical in
  // shape, so they are driven without a scan; step 81 is a different panel
  // (`.done-msg`, no active cells, Next disabled) and is scanned.
  const next = page.locator('#btn-next-round');
  while (await next.isEnabled()) await next.click();
  await expect(page.locator('.done-msg')).toBeVisible();
  await expect(page.locator('#qr-step-table')).not.toHaveAttribute('tabindex', /.*/);
  await expect(page.locator('.matrix-active')).toHaveCount(0);
  await expect(page.locator('.qr-progress')).toHaveAttribute('aria-valuenow', '80');
  await scanAt('all 80 quarter-rounds complete');

  // Re-initialising is this lab's Reset: it must return to the step-0 rendering.
  await page.locator('#btn-run-qr').click();
  await expect(page.locator('#round-label')).toContainText('0 of 80');
  await expect(page.locator('#qr-narrate')).toBeHidden();
  await expect(page.locator('#qr-step-table')).not.toHaveAttribute('tabindex', /.*/);
  await scanAt('stepper re-initialised back to step 0');

  // ── Section D — nonce reuse, and the crib-drag it unlocks ────────────────
  await page.locator('#btn-nonce-reuse').click();
  await expect(page.locator('#crib-drag')).toBeVisible();
  await expect(page.locator('#nr-xor .xor-match').first()).toBeVisible();
  await expect(page.locator('#crib-guess')).toHaveValue('Attack at dawn');
  await expect(page.locator('#crib-output .crib-char').first()).toBeVisible();
  await scanAt('nonce reused, crib-drag unlocked with a perfect guess');

  // Degrade the guess so `.crib-gap` and `.crib-char` are painted side by side
  // — the only state in which those two inks ever meet.
  //
  // The leading "Å" is not decoration. `renderRecovered` emits a `.crib-gap`
  // dot only for a byte outside printable ASCII, and recovered[i] is
  // pt1[i] ^ pt2[i] ^ guess[i]: three ASCII bytes XOR to another byte with the
  // high bit clear, and for these two messages the result never falls below
  // 0x20 either. So with an ASCII guess the recovery degrades into DIFFERENT
  // READABLE characters and never into dots, and a gate that typed a plausible
  // wrong English guess would have scanned a panel with no gap glyphs in it at
  // all. "Å" encodes as 0xC3 0x85, whose high bits carry two bytes out of range
  // and shift the rest of the guess by one, so the panel shows both inks.
  await page.locator('#crib-guess').fill('Åttack at dawn');
  await expect(page.locator('#crib-output .crib-gap')).toHaveCount(2);
  await expect(page.locator('#crib-output .crib-char')).toHaveCount(12);
  await scanAt('crib guess degraded, recovery partially garbled');

  // An empty guess is the floor: `cribDrag` takes min(leak, guess) bytes, so
  // the recovery box empties completely rather than filling with placeholders.
  await page.locator('#crib-guess').fill('');
  await expect(page.locator('#crib-output')).toBeEmpty();
  await scanAt('crib guess emptied, recovery box empty');

  // Blank messages take the `|| 'Attack at dawn'` fallback rather than
  // producing an empty attack — a branch the old gate never went near.
  await page.locator('#nonce-msg1').fill('');
  await page.locator('#nonce-msg2').fill('');
  await page.locator('#btn-nonce-reuse').click();
  await expect(page.locator('#crib-guess')).toHaveValue('Attack at dawn');
  await scanAt('nonce reuse rerun with both messages blank');

  // ── Info panel — every tab ───────────────────────────────────────────────
  for (const tab of ['matrix', 'safety', 'comparison']) {
    await page.locator(`#tabbtn-${tab}`).click();
    await expect(page.locator(`#tabbtn-${tab}`)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator(`#tab-${tab}`)).toBeVisible();
    await scanAt(`info tab "${tab}" selected`);
  }

  // ── The disclosure, opened the way a reader opens it ─────────────────────
  const count = await page.locator('details').count();
  for (let i = 0; i < count; i++) {
    const d = page.locator('details').nth(i);
    await d.locator('> summary').click();
    await expect(d).toHaveAttribute('open', '');
    await scanAt(`disclosure ${i + 1} of ${count} open`);
  }
}

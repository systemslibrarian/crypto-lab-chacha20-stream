import { test } from '@playwright/test';
import { boot, driveAllStates, reportCollected, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: a byte traced through the XOR
 * exhibit with the arrow keys, encrypt and decrypt round-tripped, the plaintext
 * emptied and refilled, the key regenerated, the keystream shown, a new nonce
 * taken so the avalanche stat appears, one nonce bit flipped for the
 * before/after comparison, the quarter-round stepper initialised and walked
 * through a column round, a diagonal round, auto-play, a step back, all 80
 * rounds and a re-initialise, the nonce-reuse attack run and its crib-drag
 * degraded to nothing, every info tab selected, and the disclosure opened by
 * its own summary. Every resulting state is scanned in both themes at desktop
 * and phone width — four configurations, because a gate that scans one scans
 * one half, and which half depends on the lab's defaults.
 *
 * See `gate.ts` for why nothing is injected into the page, why reduced motion
 * is asked for rather than forced, why the defaults are asserted rather than
 * assumed, why every step is scanned rather than only the last, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
  });
}

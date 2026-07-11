import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the ChaCha20 unit tests;
 * this gates them on accessibility the same way. Scans the full page with every
 * <details> expanded, every info tab activated, and the demo-driven panels
 * (keystream avalanche, nonce-reuse crib-drag) revealed — in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Neutralize animations/transitions so scans see settled, deterministic UI. */
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      transition-duration: 0s !important;
      transition-delay: 0s !important;
      scroll-behavior: auto !important;
    }`,
  });
}

/**
 * Drive every interactive section so the axe scan covers the states a user
 * actually reaches: live ciphertext, the keystream grid + avalanche readout,
 * the quarter-round stepper, all three info tabs, and the nonce-reuse
 * crib-drag panel — none of which exist in the initial DOM.
 */
async function driveDemos(page: Page): Promise<void> {
  // Section A — encrypt / decrypt.
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-decrypt').click();

  // Section B — keystream visualizer + avalanche panel (starts [hidden]).
  await page.locator('#btn-show-keystream').click();
  await page.locator('#btn-new-nonce-ks').click();

  // Section C — quarter-round stepper: build the matrix and step it.
  await page.locator('#btn-run-qr').click();
  await page.locator('#btn-next-round').click();

  // Section E info tabs — activate each so every panel renders.
  for (const id of ['tabbtn-comparison', 'tabbtn-matrix', 'tabbtn-safety']) {
    await page.locator(`#${id}`).click();
  }

  // Section D — nonce reuse: reveals the crib-drag panel (starts [hidden]).
  await page.locator('#btn-nonce-reuse').click();
  await expect(page.locator('#crib-drag')).toBeVisible();
}

/** Force-expand any collapsed disclosure widgets before scanning. */
async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await killMotion(page);
  await driveDemos(page);
  await openAllDetails(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await killMotion(page);
  await driveDemos(page);
  await openAllDetails(page);
  await scan(page);
});

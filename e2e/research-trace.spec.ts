import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
for (const width of [1280,380]) test(`research trace is separate from encryption at ${width}px`, async ({page})=>{
 await page.setViewportSize({width,height:900});await page.goto('.');
 const ciphertext=await page.locator('#ciphertext-display').innerText();
 for(const [rounds,limit] of [['6',24],['7',28],['20',80]] as const){
  await page.selectOption('#research-round-count',rounds);await page.click('#research-finish');
  await expect(page.locator('#research-step-status')).toContainText(`${limit} of ${limit}`);
  await expect(page.locator('#research-state td')).toHaveCount(16);
  if(rounds==='20')await expect(page.locator('#research-feedforward')).toContainText('10f1e7e4d13b5915500fdd1fa32071c4');
  else await expect(page.locator('#research-feedforward')).toContainText('No reduced-round keystream is offered');
  await expect(page.locator('#ciphertext-display')).toHaveText(ciphertext);
  await expect(page.locator('#research-next')).toBeDisabled();
  const scan=await new AxeBuilder({page}).include('#research-trace').withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze();expect(scan.violations).toEqual([]);
 }
 await page.click('#research-reset');await expect(page.locator('#research-step-status')).toContainText('0 of 80');
 await page.click('#research-next');await expect(page.locator('#research-step-status')).toContainText('Column round');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth)).toBeLessThanOrEqual(1);
});

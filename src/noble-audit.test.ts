/* What "audited" covers for the @noble/ciphers this lab points readers at.
 *
 * The README told readers that "real encryption should use the audited
 * `@noble/ciphers` (or platform crypto) path", with no version. The library
 * records its latest audit as "at version 1.0.0, in Sep 2024, independently, by
 * [cure53]", and this lab pins ^2.4.0, which that audit does not cover —
 * advice worth qualifying, since it is advice about what to use in production.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const nobleReadme = read('../node_modules/@noble/ciphers/README.md');
const readmeSource = read('../README.md');
const pkg = JSON.parse(read('../package.json'));

describe('the @noble/ciphers audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/ciphers']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 1\.0\.0, in Sep 2024, independently, by \[cure53\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.\d+\.\d+, in [A-Z]/);
  });

  it('states that version in the README', () => {
    const flat = readmeSource.replace(/\s+/g, ' ');
    expect(flat).not.toContain('use the audited `@noble/ciphers`');
    expect(flat).toContain('at version 1.0.0, in Sep 2024, independently, by [cure53]');
    expect(flat).toContain('pins `^2.4.0`');
  });
});

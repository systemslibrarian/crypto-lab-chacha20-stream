import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-chacha20-stream/',
  // Scope vitest to unit tests; e2e/*.spec.ts belongs to Playwright, which
  // would otherwise be swept up by vitest's default include glob.
  test: {
    include: ['src/**/*.test.ts'],
  },
});

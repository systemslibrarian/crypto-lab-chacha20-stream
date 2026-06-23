# crypto-lab-chacha20-stream

[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-chacha20-stream/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-chacha20-stream/actions/workflows/pages.yml)

## What It Is

ChaCha20 is a 256-bit stream cipher designed by Daniel J. Bernstein, standardized in RFC 8439. It encrypts data by XORing plaintext with a pseudorandom keystream generated from a 256-bit key, a 96-bit nonce, and a 32-bit block counter. The cipher uses an ARX construction (Add-Rotate-XOR) that operates entirely with constant-time instructions, providing confidentiality without relying on hardware acceleration. This demo implements the full ChaCha20 block function from scratch for visualization and uses `@noble/ciphers` for production encrypt/decrypt operations. The hand-rolled engine is pinned to the official **RFC 8439 test vectors** and cross-checked byte-for-byte against `@noble/ciphers`, so the visualization is provably correct (see [Development](#development)).

## When to Use It

- **Mobile and IoT encryption without AES-NI** — ChaCha20 runs 2–3× faster than software AES on devices lacking hardware AES instructions, which includes most ARM chips before ARMv8 Cryptography Extensions.
- **Side-channel-resistant symmetric encryption** — The ARX design has no S-box table lookups, eliminating the cache-timing attacks that plague software AES implementations.
- **TLS and QUIC cipher suites** — ChaCha20-Poly1305 is a first-class cipher suite in TLS 1.3 and the default in QUIC on devices without AES-NI.
- **High-throughput stream encryption** — ChaCha20 produces 64 bytes of keystream per block with simple 32-bit operations, making it efficient for bulk data encryption.
- **Do NOT use ChaCha20 alone for authenticated encryption** — ChaCha20 provides confidentiality only. Always pair it with Poly1305 (or another MAC) to get integrity and authenticity in production systems.

## Live Demo

**[Launch Demo →](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/)**

The demo includes four interactive sections:

- **Encrypt / decrypt playground** — generate keys and nonces, type plaintext, and watch ciphertext update live as you type; the Decrypt button proves the round-trip recovery.
- **Keystream visualizer** — 64 bytes shown as a color-coded grid that changes completely when you regenerate the nonce, with an **avalanche readout** quantifying how many of the 512 keystream bits flipped (~50% for an ideal cipher).
- **Quarter-round stepper** — step or auto-play through all 80 quarter-rounds, watching the 4×4 state matrix mutate cell-by-cell. The four words being mixed are highlighted and labeled `a b c d`, and each round is marked as a column or diagonal round.
- **Nonce-reuse attack demo** — encrypt two messages with the same key+nonce, see how XORing the ciphertexts cancels the keystream, then **crib-drag**: guess one plaintext and watch the other reappear character-by-character, with no key involved.

## What Can Go Wrong

- **Nonce reuse (two-time pad)** — Encrypting two messages with the same key and nonce produces identical keystreams, so XORing the ciphertexts yields the XOR of the plaintexts. The demo's Section D demonstrates this directly.
- **Missing authentication** — ChaCha20 is malleable: an attacker can flip bits in the ciphertext and the corresponding plaintext bits flip predictably. Without Poly1305 or another MAC, tampered ciphertext decrypts without any error.
- **Counter overflow** — The 32-bit block counter limits a single key+nonce pair to 2³² blocks (256 GB). Exceeding this wraps the counter and reuses keystream, silently breaking confidentiality.
- **96-bit nonce collision risk** — With a 96-bit nonce, randomly generating nonces becomes unsafe after roughly 2³² messages per key (birthday bound). For random nonces, use XChaCha20 with its 192-bit nonce instead.

## Real-World Usage

- **TLS 1.3 (RFC 8446)** — ChaCha20-Poly1305 is a mandatory-to-implement cipher suite, used as the preferred cipher when AES-NI is unavailable.
- **Google QUIC / HTTP/3** — Google chose ChaCha20-Poly1305 for QUIC transport encryption on Android devices lacking AES hardware support.
- **WireGuard VPN** — Uses ChaCha20-Poly1305 as its sole symmetric cipher for tunnel encryption, chosen for its speed and simplicity.
- **OpenSSH** — Supports `chacha20-poly1305@openssh.com` as a transport cipher, widely deployed as the default on many distributions.
- **NaCl / libsodium** — The `crypto_secretbox` API uses XSalsa20-Poly1305 (closely related to XChaCha20), and libsodium also exposes ChaCha20-Poly1305 directly.

## Development

```bash
npm install      # install dependencies
npm run dev      # start the Vite dev server
npm test         # run the test suite (Vitest)
npm run build    # type-check + production build
```

### Tests

The suite has two layers, both run in CI before every deploy:

- **Crypto correctness** (`src/chacha20.test.ts`) — verifies the hand-rolled engine against the RFC 8439 §2.1.1 quarter-round and §2.3.2 block test vectors, cross-checks the keystream byte-for-byte against `@noble/ciphers` across multiple blocks, and confirms the encrypt/decrypt round-trip, the two-time-pad XOR property, and the crib-drag recovery.
- **UI integration** (`src/ui.test.ts`) — boots the real UI against `index.html` in a headless DOM and drives every section the way a user would, catching DOM-wiring regressions.

---

### Cross-links

- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/)
- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/)
- [Ratchet Wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)
- [Noise Pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/)
- [crypto-lab home](https://systemslibrarian.github.io/crypto-lab/)

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31

# crypto-lab-chacha20-stream

[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-chacha20-stream/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-chacha20-stream/actions/workflows/pages.yml)

## What It Is

ChaCha20 is a 256-bit stream cipher designed by Daniel J. Bernstein, standardized in RFC 8439. It encrypts data by XORing plaintext with a pseudorandom keystream generated from a 256-bit key, a 96-bit nonce, and a 32-bit block counter. The cipher uses an ARX construction (Add-Rotate-XOR) that operates entirely with constant-time instructions, providing confidentiality without relying on hardware acceleration. This demo implements the full ChaCha20 block function from scratch for visualization and uses `@noble/ciphers` for production encrypt/decrypt operations.

## When to Use It

- **Mobile and IoT encryption without AES-NI** — ChaCha20 runs 2–3× faster than software AES on devices lacking hardware AES instructions, which includes most ARM chips before ARMv8 Cryptography Extensions.
- **Side-channel-resistant symmetric encryption** — The ARX design has no S-box table lookups, eliminating the cache-timing attacks that plague software AES implementations.
- **TLS and QUIC cipher suites** — ChaCha20-Poly1305 is a first-class cipher suite in TLS 1.3 and the default in QUIC on devices without AES-NI.
- **High-throughput stream encryption** — ChaCha20 produces 64 bytes of keystream per block with simple 32-bit operations, making it efficient for bulk data encryption.
- **Do NOT use ChaCha20 alone for authenticated encryption** — ChaCha20 provides confidentiality only. Always pair it with Poly1305 (or another MAC) to get integrity and authenticity in production systems.

## Live Demo

**[Launch Demo →](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/)**

The demo includes four interactive sections: an encrypt/decrypt playground where you can generate keys and nonces, type plaintext, and see ciphertext in real time; a keystream visualizer showing 64 bytes as a color-coded grid that changes completely when you regenerate the nonce; a quarter-round stepper that walks through all 80 quarter-round operations of the ChaCha20 block function showing the 4×4 state matrix at each step; and a nonce reuse attack demo that encrypts two messages with the same key+nonce and reveals how XORing the ciphertexts recovers the XOR of the plaintexts.

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

---

### Cross-links

- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/)
- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/)
- [Ratchet Wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)
- [Noise Pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/)
- [crypto-lab home](https://systemslibrarian.github.io/crypto-lab/)

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31

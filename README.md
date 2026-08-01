# crypto-lab-chacha20-stream

## What It Is

ChaCha20 is a 256-bit stream cipher designed by Daniel J. Bernstein, standardized in RFC 8439. It encrypts data by XORing plaintext with a pseudorandom keystream generated from a 256-bit key, a 96-bit nonce, and a 32-bit block counter. The cipher uses an ARX construction (Add-Rotate-XOR) that operates entirely with constant-time instructions, providing confidentiality without relying on hardware acceleration. This demo implements the full ChaCha20 block function from scratch for visualization and uses `@noble/ciphers` for production encrypt/decrypt operations. The hand-rolled engine is pinned to the official **RFC 8439 test vectors** and cross-checked byte-for-byte against `@noble/ciphers`, so the visualization is provably correct (see [Development](#development)).

## When to Use It

- **Mobile and IoT encryption without AES-NI** — ChaCha20 runs 2–3× faster than software AES on devices lacking hardware AES instructions, which includes most ARM chips before ARMv8 Cryptography Extensions.
- **Side-channel-resistant symmetric encryption** — The ARX design has no S-box table lookups, eliminating the cache-timing attacks that plague software AES implementations.
- **TLS and QUIC cipher suites** — ChaCha20-Poly1305 is a first-class cipher suite in TLS 1.3 and the default in QUIC on devices without AES-NI.
- **High-throughput stream encryption** — ChaCha20 produces 64 bytes of keystream per block with simple 32-bit operations, making it efficient for bulk data encryption.
- **Do NOT use ChaCha20 alone for authenticated encryption** — ChaCha20 provides confidentiality only. Always pair it with Poly1305 (or another MAC) to get integrity and authenticity in production systems.
- **Do NOT treat this as production code** — it is a teaching demo; the hand-rolled block function exists for visualization, and real encryption should use the audited `@noble/ciphers` (or platform crypto) path.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/)**

A plain-language primer opens the page — defining stream cipher, key, nonce, keystream, and XOR, and stating the one equation the rest of the page makes visible: **ciphertext = plaintext ⊕ keystream**. Below it are four interactive sections:

1. **Encrypt / decrypt playground** — generate keys and nonces, type plaintext, and watch ciphertext update live as you type; the Decrypt button proves the round-trip recovery. Directly under the message, a **byte-aligned XOR visual** shows three rows — plaintext, keystream (from the same hand-rolled engine), and their XOR — column by column, so you literally see `ct[i] = pt[i] ⊕ ks[i]` where encryption happens. Hover or arrow-key a column to trace one byte through the XOR.
2. **Keystream visualizer** — 64 bytes shown as a color-coded grid (colour encodes byte *value* only, not meaning) that changes completely when you regenerate the nonce, with an **avalanche readout** quantifying how many of the 512 keystream bits flipped (~50% for an ideal cipher). A **single-bit avalanche** control flips one nonce bit and shows the before/after keystreams side by side, changed cells flagged, so diffusion is felt rather than reported.
3. **Quarter-round stepper** — step or auto-play through all 80 quarter-rounds, watching the 4×4 state matrix mutate cell-by-cell. The four words being mixed are highlighted and labeled `a b c d`, each round is marked column or diagonal, and a **plain-English narration** describes what the current Add–Rotate–XOR step actually does and why alternating column/diagonal rounds produce diffusion.
4. **Nonce-reuse attack demo** — encrypt two messages with the same key+nonce, see how XORing the ciphertexts cancels the keystream, then **crib-drag**: guess one plaintext and watch the other reappear character-by-character, with no key involved.

## What Can Go Wrong

- **Nonce reuse (two-time pad)** — Encrypting two messages with the same key and nonce produces identical keystreams, so XORing the ciphertexts yields the XOR of the plaintexts. The demo's Section D demonstrates this directly.
- **Missing authentication** — ChaCha20 is malleable: an attacker can flip bits in the ciphertext and the corresponding plaintext bits flip predictably. Without Poly1305 or another MAC, tampered ciphertext decrypts without any error.
- **Counter overflow** — The 32-bit block counter limits a single key+nonce pair to 2³² blocks (256 GB). Exceeding this wraps the counter and reuses keystream, silently breaking confidentiality.
- **96-bit nonce collision risk** — With a 96-bit nonce, randomly generating nonces becomes unsafe after roughly 2³² messages per key (birthday bound). For random nonces, use XChaCha20 with its 192-bit nonce instead.

## Real-World Usage

- **TLS 1.3 (RFC 8446)** — `TLS_CHACHA20_POLY1305_SHA256` is a SHOULD-implement cipher suite (§9.1 makes only `TLS_AES_128_GCM_SHA256` mandatory), used as the preferred cipher when AES-NI is unavailable.
- **Google QUIC / HTTP/3** — Google chose ChaCha20-Poly1305 for QUIC transport encryption on Android devices lacking AES hardware support.
- **WireGuard VPN** — Uses ChaCha20-Poly1305 as its sole symmetric cipher for tunnel encryption, chosen for its speed and simplicity.
- **OpenSSH** — Supports `chacha20-poly1305@openssh.com` as a transport cipher, widely deployed as the default on many distributions.
- **NaCl / libsodium** — The `crypto_secretbox` API uses XSalsa20-Poly1305 (closely related to XChaCha20), and libsodium also exposes ChaCha20-Poly1305 directly.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-chacha20-stream
cd crypto-lab-chacha20-stream
npm install
npm run dev
```

## Related Demos
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — the AES block-cipher modes ChaCha20 is the software-friendly alternative to.
- [crypto-lab-otp-vault](https://systemslibrarian.github.io/crypto-lab-otp-vault/) — the one-time pad and two-time-pad / crib-dragging attack the nonce-reuse demo mirrors.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM / AES-GCM-SIV nonce-misuse resistance, the AEAD counterpart to ChaCha20's nonce hazard.
- [crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/) — Poly1305, the MAC paired with ChaCha20 to make the authenticated ChaCha20-Poly1305 AEAD.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — applied file encryption using ChaCha20-Poly1305 with Argon2id.

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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

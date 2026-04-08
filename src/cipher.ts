// Cipher engine — uses @noble/ciphers for encrypt/decrypt, hand-rolled engine for visualization.
import { chacha20 } from '@noble/ciphers/chacha.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encrypt a plaintext string with ChaCha20. Returns ciphertext bytes. */
export function encrypt(
  plaintext: string,
  key: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const data = encoder.encode(plaintext);
  return chacha20(key, nonce, data);
}

/** Decrypt ChaCha20 ciphertext back to a string. */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const data = chacha20(key, nonce, ciphertext);
  return decoder.decode(data);
}

/** Generate a random 256-bit (32-byte) key. */
export function generateKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

/** Generate a random 96-bit (12-byte) nonce. */
export function generateNonce(): Uint8Array {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  return nonce;
}

export interface NonceReuseResult {
  ct1: Uint8Array;
  ct2: Uint8Array;
  xorResult: Uint8Array;
  explanation: string;
}

/**
 * Demonstrate the "two-time pad" attack.
 * Encrypt two messages with the SAME key+nonce and XOR the ciphertexts.
 */
export function nonceReuseDemo(
  plaintext1: string,
  plaintext2: string,
  key: Uint8Array,
  nonce: Uint8Array
): NonceReuseResult {
  const ct1 = encrypt(plaintext1, key, nonce);
  const ct2 = encrypt(plaintext2, key, nonce);
  const len = Math.min(ct1.length, ct2.length);
  const xorResult = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    xorResult[i] = ct1[i]! ^ ct2[i]!;
  }
  return {
    ct1,
    ct2,
    xorResult,
    explanation:
      'ct1 ⊕ ct2 = (pt1 ⊕ keystream) ⊕ (pt2 ⊕ keystream) = pt1 ⊕ pt2. ' +
      'The keystream cancels out — an attacker learns the XOR of your plaintexts without knowing the key. ' +
      'This is the "two-time pad" attack. Never reuse a nonce with the same key.',
  };
}

/** Generate raw keystream bytes by encrypting zeros. */
export function getKeystream(
  key: Uint8Array,
  nonce: Uint8Array,
  length: number
): Uint8Array {
  const zeros = new Uint8Array(length);
  return chacha20(key, nonce, zeros);
}

/** Convert bytes to hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert hex string to bytes. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

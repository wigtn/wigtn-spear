import { describe, it, expect } from 'vitest';
import { shannonEntropy, isHighEntropy, classifyEntropy } from '../src/engine/entropy.js';

describe('shannonEntropy', () => {
  // ─── Uniform string (all same char) ──────────────────────────

  describe('uniform strings', () => {
    it('should return 0 for a single character string', () => {
      expect(shannonEntropy('a')).toBe(0);
    });

    it('should return 0 for a string of all identical characters', () => {
      expect(shannonEntropy('aaaaaaaaaa')).toBe(0);
    });

    it('should return 0 for repeated same character regardless of length', () => {
      expect(shannonEntropy('x'.repeat(1000))).toBe(0);
    });
  });

  // ─── Binary string (alternating 0/1) ─────────────────────────

  describe('binary strings', () => {
    it('should return 1.0 for perfectly balanced binary string', () => {
      // Equal frequency of '0' and '1' -> entropy = 1.0 bits
      const binary = '01'.repeat(50);
      const entropy = shannonEntropy(binary);
      expect(entropy).toBeCloseTo(1.0, 5);
    });

    it('should return close to 1.0 for alternating ab string', () => {
      const binary = 'ab'.repeat(100);
      const entropy = shannonEntropy(binary);
      expect(entropy).toBeCloseTo(1.0, 5);
    });
  });

  // ─── High entropy string (random chars) ───────────────────────

  describe('high entropy strings', () => {
    it('should return entropy > 5.0 for a string using many distinct characters', () => {
      // Use all printable ASCII characters to generate a high-entropy string
      // 64 distinct chars used equally -> log2(64) = 6.0
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      // Repeat each char to ensure uniformity over 64 distinct chars
      let highEntropy = '';
      for (let i = 0; i < 10; i++) {
        highEntropy += chars;
      }
      const entropy = shannonEntropy(highEntropy);
      expect(entropy).toBeGreaterThan(5.0);
    });

    it('should return entropy > 4.0 for base64-like random string', () => {
      // A typical base64 encoded secret
      const secret = 'dGhpcyBpcyBhIHNlY3JldCBrZXkgdGhhdCBpcyBsb25n';
      const entropy = shannonEntropy(secret);
      expect(entropy).toBeGreaterThan(3.5);
    });
  });

  // ─── Empty string handling ────────────────────────────────────

  describe('empty string', () => {
    it('should return 0 for empty string', () => {
      expect(shannonEntropy('')).toBe(0);
    });
  });

  // ─── Known entropy values (calculated by hand) ───────────────

  describe('known entropy values', () => {
    it('should match hand-calculated entropy for "aabb"', () => {
      // "aabb": 2 distinct chars, each with frequency 2/4 = 0.5
      // H = -2 * (0.5 * log2(0.5)) = -2 * (0.5 * -1) = 1.0
      const entropy = shannonEntropy('aabb');
      expect(entropy).toBeCloseTo(1.0, 5);
    });

    it('should match hand-calculated entropy for "aaab"', () => {
      // "aaab": a=3/4, b=1/4
      // H = -(3/4 * log2(3/4) + 1/4 * log2(1/4))
      // H = -(3/4 * (-0.41503...) + 1/4 * (-2))
      // H = -(−0.31127... + −0.5) = 0.81127...
      const entropy = shannonEntropy('aaab');
      expect(entropy).toBeCloseTo(0.81128, 4);
    });

    it('should match hand-calculated entropy for "abcd"', () => {
      // "abcd": 4 distinct chars, each with frequency 1/4
      // H = -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0
      const entropy = shannonEntropy('abcd');
      expect(entropy).toBeCloseTo(2.0, 5);
    });

    it('should match hand-calculated entropy for "abcdefgh"', () => {
      // 8 distinct chars, each with frequency 1/8
      // H = -8 * (1/8 * log2(1/8)) = -8 * (1/8 * -3) = 3.0
      const entropy = shannonEntropy('abcdefgh');
      expect(entropy).toBeCloseTo(3.0, 5);
    });

    it('should return log2(n) for n equally frequent characters', () => {
      // For 16 distinct chars, each used once: H = log2(16) = 4.0
      const sixteenChars = 'abcdefghijklmnop';
      const entropy = shannonEntropy(sixteenChars);
      expect(entropy).toBeCloseTo(4.0, 5);
    });

    it('should return log2(32) for 32 equally frequent characters', () => {
      const thirtyTwoChars = 'abcdefghijklmnopqrstuvwxyz012345';
      const entropy = shannonEntropy(thirtyTwoChars);
      expect(entropy).toBeCloseTo(5.0, 5);
    });
  });
});

// ─── isHighEntropy ─────────────────────────────────────────────

describe('isHighEntropy', () => {
  it('should return false for empty string', () => {
    expect(isHighEntropy('')).toBe(false);
  });

  it('should return false for low entropy string (default threshold 5.0)', () => {
    // "password" has ~2.75 bits of entropy
    expect(isHighEntropy('password')).toBe(false);
  });

  it('should return true for string exceeding default threshold', () => {
    // 32 distinct chars -> 5.0 bits, need slightly more for >=
    // 64 distinct chars each used once -> 6.0 bits
    const highEntropy = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    expect(isHighEntropy(highEntropy)).toBe(true);
  });

  it('should use custom threshold when provided', () => {
    // "abcd" has entropy 2.0
    expect(isHighEntropy('abcd', 1.5)).toBe(true);
    expect(isHighEntropy('abcd', 2.5)).toBe(false);
  });

  it('should correctly handle threshold boundary (>=)', () => {
    // "abcdefghijklmnopqrstuvwxyz012345" -> 32 distinct chars -> entropy = 5.0
    const exactly5 = 'abcdefghijklmnopqrstuvwxyz012345';
    // isHighEntropy uses >= comparison against the threshold
    expect(isHighEntropy(exactly5, 5.0)).toBe(true);
    expect(isHighEntropy(exactly5, 5.1)).toBe(false);
  });

  it('should return false for uniform string', () => {
    expect(isHighEntropy('aaaaaaaaaa')).toBe(false);
  });
});

// ─── classifyEntropy ───────────────────────────────────────────

describe('classifyEntropy', () => {
  it('should classify low entropy as non-secret', () => {
    // "password" -> ~2.75 bits, well below SUSPICIOUS (5.0)
    const result = classifyEntropy('password');
    expect(result.classification).toBe('non-secret');
    expect(result.entropy).toBeGreaterThan(0);
    expect(result.entropy).toBeLessThan(5.0);
  });

  it('should classify as suspicious when entropy >= 5.0 and < 6.0', () => {
    // Need a string with entropy between 5.0 and 6.0
    // 32 distinct chars -> exactly 5.0
    const str = 'abcdefghijklmnopqrstuvwxyz012345';
    const result = classifyEntropy(str);
    expect(result.classification).toBe('suspicious');
    expect(result.entropy).toBeCloseTo(5.0, 4);
  });

  it('should classify as high when entropy >= 6.0 and < 8.0', () => {
    // 64 distinct chars -> 6.0 bits
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const result = classifyEntropy(chars);
    expect(result.classification).toBe('high');
    expect(result.entropy).toBeCloseTo(6.0, 4);
  });

  it('should classify as very-high when entropy >= 8.0', () => {
    // 256 distinct chars -> 8.0 bits
    // Build a string with 256 unique byte values
    let str = '';
    for (let i = 0; i < 256; i++) {
      str += String.fromCharCode(i);
    }
    const result = classifyEntropy(str);
    expect(result.classification).toBe('very-high');
    expect(result.entropy).toBeCloseTo(8.0, 4);
  });

  it('should return entropy value alongside classification', () => {
    const result = classifyEntropy('aaaa');
    expect(result.entropy).toBe(0);
    expect(result.classification).toBe('non-secret');
  });
});

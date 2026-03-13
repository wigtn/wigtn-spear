/**
 * Shannon Entropy Analysis for Secret Detection
 *
 * Shannon entropy measures the information density (randomness) of a string.
 * High-entropy strings are likely to be secrets, tokens, or cryptographic keys,
 * while low-entropy strings are typically natural language or code identifiers.
 *
 * Entropy scale (base 2, for printable ASCII):
 *   0.0 - 3.0  : Very low entropy (repeated characters, simple words)
 *   3.0 - 4.0  : Low entropy (natural language, code)
 *   4.0 - 5.0  : Moderate entropy (could be meaningful or random)
 *   5.0 - 6.0  : High entropy (likely random / secret)
 *   6.0+       : Very high entropy (almost certainly random / secret)
 *
 * The thresholds used are defined in @wigtn/shared constants:
 *   ENTROPY_THRESHOLDS.NON_SECRET  = 4.0
 *   ENTROPY_THRESHOLDS.SUSPICIOUS  = 5.0
 *   ENTROPY_THRESHOLDS.HIGH        = 6.0
 *   ENTROPY_THRESHOLDS.VERY_HIGH   = 8.0
 */

import { ENTROPY_THRESHOLDS } from '@wigtn/shared';

/**
 * Calculate the Shannon entropy of a string in bits per character (base 2).
 *
 * The formula is: H(X) = -SUM(p(x) * log2(p(x))) for each unique character x,
 * where p(x) is the frequency of character x in the string.
 *
 * @param str - The input string to analyze.
 * @returns Entropy in bits. Returns 0 for empty strings or single-character strings.
 *
 * @example
 * ```ts
 * shannonEntropy('aaaa')           // ~0.0 (no randomness)
 * shannonEntropy('password')       // ~2.75 (low entropy)
 * shannonEntropy('aB3$xK9!mZ')    // ~3.32 (higher entropy)
 * shannonEntropy('dG4j8K2mP9xL')  // ~3.58 (even higher)
 * ```
 */
export function shannonEntropy(str: string): number {
  if (str.length <= 1) {
    return 0;
  }

  // Count character frequencies
  const freq = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i]!;
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  const len = str.length;
  let entropy = 0;

  for (const count of freq.values()) {
    if (count === 0) continue;
    const p = count / len;
    // Shannon entropy formula: -SUM(p * log2(p))
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Determine whether a string has high entropy (likely a secret).
 *
 * Uses the ENTROPY_THRESHOLDS.SUSPICIOUS (5.0) as the default threshold.
 * A custom threshold can be provided for rules that need different sensitivity.
 *
 * @param str - The input string to analyze.
 * @param threshold - Custom entropy threshold. Defaults to ENTROPY_THRESHOLDS.SUSPICIOUS (5.0).
 * @returns true if the string's Shannon entropy exceeds the threshold.
 *
 * @example
 * ```ts
 * isHighEntropy('password123')     // false (entropy ~3.28)
 * isHighEntropy('dBs9Kx2mP7qL')   // true  (entropy ~3.58, depends on threshold)
 * isHighEntropy('abc', 1.0)        // true  (custom low threshold)
 * ```
 */
export function isHighEntropy(
  str: string,
  threshold: number = ENTROPY_THRESHOLDS.SUSPICIOUS,
): boolean {
  if (str.length === 0) {
    return false;
  }
  return shannonEntropy(str) >= threshold;
}

/**
 * Classify a string's entropy into a human-readable category.
 *
 * Useful for reporting and display purposes.
 *
 * @param str - The input string to classify.
 * @returns An object with the entropy value and classification label.
 */
export function classifyEntropy(str: string): {
  entropy: number;
  classification: 'non-secret' | 'suspicious' | 'high' | 'very-high';
} {
  const entropy = shannonEntropy(str);

  let classification: 'non-secret' | 'suspicious' | 'high' | 'very-high';

  if (entropy >= ENTROPY_THRESHOLDS.VERY_HIGH) {
    classification = 'very-high';
  } else if (entropy >= ENTROPY_THRESHOLDS.HIGH) {
    classification = 'high';
  } else if (entropy >= ENTROPY_THRESHOLDS.SUSPICIOUS) {
    classification = 'suspicious';
  } else {
    classification = 'non-secret';
  }

  return { entropy, classification };
}

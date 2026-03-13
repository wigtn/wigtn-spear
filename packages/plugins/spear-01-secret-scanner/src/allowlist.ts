/**
 * Allowlist Checker -- Determines whether a detected secret value
 * should be suppressed (ignored) based on rule-level and global allowlists.
 *
 * Three layers of allowlisting:
 *   1. Rule allowlist patterns -- regex patterns defined per-rule in YAML
 *   2. Rule allowlist paths -- file path patterns defined per-rule
 *   3. Known test/example values -- globally recognized example credentials
 *      from vendor documentation (AWS, GitHub, Slack, etc.)
 *
 * Design: Functions are pure (no side effects, no state) to keep
 * the scanner pipeline deterministic and testable.
 */

import type { Rule } from '@wigtn/shared';

/**
 * Well-known example/test credential values that should never be
 * flagged as real secrets. These are from official vendor documentation.
 */
const KNOWN_EXAMPLE_VALUES: ReadonlySet<string> = new Set([
  // AWS
  'AKIAIOSFODNN7EXAMPLE',
  'ASIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // GitHub
  'ghp_000000000000000000000000000000000000',
  'github_pat_00000000000000000000_0000000000000000000000000000000000000000000000000000000000000000',

  // Slack (format examples, not real tokens)
  'xoxb-FAKE000000-FAKE000000-FAKEEXAMPLETOKEN0000',
  'xoxp-FAKE000000-FAKE000000-FAKE000000-FAKEEXAMPLETOKENFAKEEXAMPLE00',

  // Generic placeholders
  'your-api-key-here',
  'your_api_key_here',
  'INSERT_YOUR_KEY_HERE',
  'CHANGE_ME',
  'TODO',
  'REPLACE_ME',
  'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'pk_test_0000000000000000000000000000',
  'sk_test_0000000000000000000000000000',
]);

/**
 * Common substrings that indicate a value is a placeholder, not a real secret.
 * Checked case-insensitively.
 */
const PLACEHOLDER_SUBSTRINGS: readonly string[] = [
  'example',
  'placeholder',
  'dummy',
  'sample',
  'xxxxxx',
  'your-',
  'your_',
  'change-me',
  'change_me',
  'replace-me',
  'replace_me',
  'insert-here',
  'insert_here',
  'todo',
  'fixme',
  '<your',
  '${',
  '{{',
];

/**
 * Check whether a matched secret value should be allowlisted (suppressed).
 *
 * @param value - The matched secret value from regex.
 * @param rule - The Rule that produced the match (contains allowlist config).
 * @returns true if the value should be suppressed.
 */
export function isAllowlisted(value: string, rule: Rule): boolean {
  // Layer 1: Known example values (exact match)
  if (KNOWN_EXAMPLE_VALUES.has(value)) {
    return true;
  }

  // Layer 2: Placeholder substring check (case-insensitive)
  const lowerValue = value.toLowerCase();
  for (const substring of PLACEHOLDER_SUBSTRINGS) {
    if (lowerValue.includes(substring)) {
      return true;
    }
  }

  // Layer 3: Rule-specific allowlist patterns
  if (rule.allowlist?.patterns && rule.allowlist.patterns.length > 0) {
    for (const allowPattern of rule.allowlist.patterns) {
      try {
        const regex = new RegExp(allowPattern);
        if (regex.test(value)) {
          return true;
        }
      } catch {
        // Invalid allowlist regex pattern; skip it
        continue;
      }
    }
  }

  return false;
}

/**
 * Check whether a file path is allowlisted by a rule's path allowlist.
 *
 * @param relativePath - The file path relative to the scan root.
 * @param rule - The Rule that produced the match (contains path allowlist).
 * @returns true if the file path should be suppressed.
 */
export function isPathAllowlisted(relativePath: string, rule: Rule): boolean {
  if (!rule.allowlist?.paths || rule.allowlist.paths.length === 0) {
    return false;
  }

  for (const pattern of rule.allowlist.paths) {
    if (matchPathGlob(relativePath, pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Simple glob matching for file paths.
 *
 * Consistent with the glob matching used in @wigtn/core pipeline.ts.
 */
function matchPathGlob(filepath: string, pattern: string): boolean {
  if (filepath === pattern) return true;

  let regexStr = '^';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i]!;

    if (ch === '*') {
      if (i + 1 < pattern.length && pattern[i + 1] === '*') {
        regexStr += '.*';
        i += 2;
        if (i < pattern.length && pattern[i] === '/') {
          i++;
        }
        continue;
      }
      regexStr += '[^/]*';
    } else if (ch === '?') {
      regexStr += '[^/]';
    } else if (ch === '.') {
      regexStr += '\\.';
    } else if (
      ch === '(' || ch === ')' || ch === '[' || ch === ']' ||
      ch === '{' || ch === '}' || ch === '+' || ch === '^' ||
      ch === '$' || ch === '|' || ch === '\\'
    ) {
      regexStr += '\\' + ch;
    } else {
      regexStr += ch;
    }
    i++;
  }

  regexStr += '$';

  try {
    return new RegExp(regexStr).test(filepath);
  } catch {
    return filepath.includes(pattern);
  }
}

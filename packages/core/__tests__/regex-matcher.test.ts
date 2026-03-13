import { describe, it, expect } from 'vitest';
import { RegexMatcher } from '../src/engine/regex-matcher.js';
import type { Rule } from '@wigtn/shared';

/**
 * Helper to create a minimal Rule object for testing.
 * Only fills in fields that RegexMatcher actually uses.
 */
function makeRule(overrides: Partial<Rule> & { id: string; detection: Rule['detection'] }): Rule {
  return {
    name: overrides.name ?? `Rule ${overrides.id}`,
    description: overrides.description ?? 'Test rule',
    category: overrides.category ?? 'secret',
    severity: overrides.severity ?? 'high',
    tags: overrides.tags ?? [],
    references: overrides.references ?? [],
    allowlist: overrides.allowlist,
    ...overrides,
  };
}

describe('RegexMatcher', () => {
  // ─── Valid patterns compile ──────────────────────────────────

  describe('valid regex patterns', () => {
    it('should compile a simple pattern', () => {
      const rules = [
        makeRule({
          id: 'test-simple',
          detection: { keywords: [], pattern: 'password\\s*=\\s*["\']\\w+["\']' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(1);
      expect(matcher.rejectedCount).toBe(0);
    });

    it('should compile multiple valid rules', () => {
      const rules = [
        makeRule({
          id: 'aws-key',
          detection: { keywords: ['AKIA'], pattern: 'AKIA[0-9A-Z]{16}' },
        }),
        makeRule({
          id: 'generic-secret',
          detection: { keywords: ['secret'], pattern: 'secret[_-]?key\\s*=\\s*\\S+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(2);
      expect(matcher.rejectedCount).toBe(0);
    });
  });

  // ─── Invalid / unsafe patterns rejected ──────────────────────

  describe('invalid and unsafe patterns', () => {
    it('should reject empty pattern', () => {
      const rules = [
        makeRule({
          id: 'empty-pattern',
          detection: { keywords: [], pattern: '' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(0);
      expect(matcher.rejectedCount).toBe(1);
      expect(matcher.getRejectionReason('empty-pattern')).toBe('Empty pattern');
    });

    it('should reject whitespace-only pattern', () => {
      const rules = [
        makeRule({
          id: 'whitespace-pattern',
          detection: { keywords: [], pattern: '   ' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.rejectedCount).toBe(1);
      expect(matcher.getRejectionReason('whitespace-pattern')).toBe('Empty pattern');
    });

    it('should reject syntactically invalid regex', () => {
      const rules = [
        makeRule({
          id: 'bad-syntax',
          detection: { keywords: [], pattern: '(unclosed' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(0);
      expect(matcher.rejectedCount).toBe(1);
      const reason = matcher.getRejectionReason('bad-syntax');
      expect(reason).toBeDefined();
      expect(reason).toBeDefined();
    });

    it('should reject potentially unsafe ReDoS patterns', () => {
      // Classic ReDoS: nested quantifiers on overlapping character classes
      const rules = [
        makeRule({
          id: 'redos-pattern',
          detection: { keywords: [], pattern: '(a+)+$' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(0);
      expect(matcher.rejectedCount).toBe(1);
      const reason = matcher.getRejectionReason('redos-pattern');
      expect(reason).toBeDefined();
      expect(reason).toContain('unsafe regex');
    });

    it('should track all rejected rules in getRejectedRules()', () => {
      const rules = [
        makeRule({
          id: 'valid',
          detection: { keywords: [], pattern: 'abc' },
        }),
        makeRule({
          id: 'empty',
          detection: { keywords: [], pattern: '' },
        }),
        makeRule({
          id: 'bad',
          detection: { keywords: [], pattern: '[invalid' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      expect(matcher.compiledCount).toBe(1);
      const rejected = matcher.getRejectedRules();
      expect(rejected.size).toBe(2);
      expect(rejected.has('empty')).toBe(true);
      expect(rejected.has('bad')).toBe(true);
    });
  });

  // ─── Match returns correct line/column numbers ───────────────

  describe('line and column number tracking', () => {
    it('should return correct line and column for single-line content', () => {
      const rules = [
        makeRule({
          id: 'find-secret',
          detection: { keywords: [], pattern: 'SECRET_[A-Z]+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      //           0123456789...
      const content = 'var x = SECRET_KEY;';
      const results = matcher.match(content);

      expect(results).toHaveLength(1);
      expect(results[0]!.ruleId).toBe('find-secret');
      expect(results[0]!.value).toBe('SECRET_KEY');
      expect(results[0]!.line).toBe(1);
      expect(results[0]!.column).toBe(9); // 0-indexed position 8 -> 1-based column 9
    });

    it('should return correct line numbers for multi-line content', () => {
      const rules = [
        makeRule({
          id: 'find-key',
          detection: { keywords: [], pattern: 'API_KEY=\\w+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const content = [
        'line one',
        'line two',
        'API_KEY=abc123',
        'line four',
      ].join('\n');

      const results = matcher.match(content);
      expect(results).toHaveLength(1);
      expect(results[0]!.line).toBe(3);
      expect(results[0]!.column).toBe(1); // starts at beginning of line 3
    });

    it('should return correct column for match in the middle of a line', () => {
      const rules = [
        makeRule({
          id: 'find-pass',
          detection: { keywords: [], pattern: 'password' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const content = 'first line\nsecond: password here\nthird line';

      const results = matcher.match(content);
      expect(results).toHaveLength(1);
      expect(results[0]!.line).toBe(2);
      expect(results[0]!.column).toBe(9); // "second: " = 8 chars, then "password" starts at col 9
    });
  });

  // ─── Multiple patterns matched ───────────────────────────────

  describe('multiple pattern matching', () => {
    it('should match multiple rules against the same content', () => {
      const rules = [
        makeRule({
          id: 'aws-key',
          detection: { keywords: [], pattern: 'AKIA[0-9A-Z]{16}' },
        }),
        makeRule({
          id: 'generic-password',
          detection: { keywords: [], pattern: 'password\\s*=\\s*\\S+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const content = 'password = hunter2\naws_key = AKIAIOSFODNN7EXAMPLE';

      const results = matcher.match(content);
      expect(results).toHaveLength(2);

      const ruleIds = results.map((r) => r.ruleId);
      expect(ruleIds).toContain('aws-key');
      expect(ruleIds).toContain('generic-password');
    });

    it('should run only selected rules when ruleIds is provided', () => {
      const rules = [
        makeRule({
          id: 'rule-a',
          detection: { keywords: [], pattern: 'aaa' },
        }),
        makeRule({
          id: 'rule-b',
          detection: { keywords: [], pattern: 'bbb' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const content = 'aaa bbb';

      const results = matcher.match(content, ['rule-a']);
      expect(results).toHaveLength(1);
      expect(results[0]!.ruleId).toBe('rule-a');
    });

    it('should ignore non-existent rule IDs in selection', () => {
      const rules = [
        makeRule({
          id: 'rule-a',
          detection: { keywords: [], pattern: 'aaa' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const results = matcher.match('aaa', ['rule-a', 'nonexistent']);
      expect(results).toHaveLength(1);
    });
  });

  // ─── Empty content ───────────────────────────────────────────

  describe('empty content', () => {
    it('should return empty array for empty content', () => {
      const rules = [
        makeRule({
          id: 'any-rule',
          detection: { keywords: [], pattern: '\\w+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const results = matcher.match('');
      expect(results).toEqual([]);
    });
  });

  // ─── Pattern timeout handling ────────────────────────────────

  describe('timeout handling', () => {
    it('should handle a pattern that produces many matches without crashing', () => {
      const rules = [
        makeRule({
          id: 'many-matches',
          detection: { keywords: [], pattern: '\\d+' },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      // Generate content with many numbers
      const content = Array.from({ length: 1000 }, (_, i) => `item${i}`).join('\n');
      const results = matcher.match(content);
      // Should return results without error (may be limited by timeout)
      expect(results.length).toBeGreaterThan(0);
    });
  });

  // ─── Allowlist patterns ──────────────────────────────────────

  describe('allowlist patterns', () => {
    it('should skip matches that match an allowlist pattern', () => {
      const rules = [
        makeRule({
          id: 'generic-key',
          detection: { keywords: [], pattern: '[A-Z0-9]{20}' },
          allowlist: { patterns: ['^AKIAIOSFODNN7EXAMPLE$'] },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      // This is the well-known AWS example key
      const content = 'key=AKIAIOSFODNN7EXAMPLE';
      const results = matcher.match(content);
      expect(results).toHaveLength(0);
    });

    it('should keep matches that do not match allowlist', () => {
      const rules = [
        makeRule({
          id: 'generic-key',
          detection: { keywords: [], pattern: '[A-Z0-9]{20}' },
          allowlist: { patterns: ['^EXAMPLE_ONLY$'] },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      const content = 'key=AKIAIOSFODNN7REALKEY';
      const results = matcher.match(content);
      expect(results).toHaveLength(1);
    });

    it('should handle invalid allowlist patterns gracefully', () => {
      const rules = [
        makeRule({
          id: 'with-bad-allowlist',
          detection: { keywords: [], pattern: 'secret' },
          allowlist: { patterns: ['(invalid['] },
        }),
      ];
      const matcher = new RegexMatcher(rules);
      // Should not throw; invalid allowlist pattern is skipped
      const results = matcher.match('secret');
      expect(results).toHaveLength(1);
    });
  });

  // ─── Zero-length match handling ──────────────────────────────

  describe('zero-length matches', () => {
    it('should not enter infinite loop on zero-length match patterns', () => {
      const rules = [
        makeRule({
          id: 'zero-len',
          detection: { keywords: [], pattern: '(?:)' }, // matches empty string
        }),
      ];
      const matcher = new RegexMatcher(rules);
      // Should return without hanging (zero-length matches are skipped)
      const results = matcher.match('abc');
      expect(results).toEqual([]);
    });
  });
});

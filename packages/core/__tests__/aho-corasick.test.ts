import { describe, it, expect } from 'vitest';
import { AhoCorasick, AhoCorasickCaseInsensitive } from '../src/engine/aho-corasick.js';
import type { AhoCorasickMatch } from '../src/engine/aho-corasick.js';

describe('AhoCorasick', () => {
  // ─── Empty keywords ──────────────────────────────────────────

  describe('empty keywords', () => {
    it('should return no matches when constructed with empty array', () => {
      const ac = new AhoCorasick([]);
      const results = ac.search('some text with api_key inside');
      expect(results).toEqual([]);
    });

    it('should return no matches when all keywords are empty strings', () => {
      const ac = new AhoCorasick(['', '', '']);
      const results = ac.search('some text');
      expect(results).toEqual([]);
    });

    it('should filter out empty strings and keep valid keywords', () => {
      const ac = new AhoCorasick(['', 'api_key', '']);
      expect(ac.getKeywords()).toEqual(['api_key']);
      const results = ac.search('my api_key here');
      expect(results).toHaveLength(1);
      expect(results[0]!.keyword).toBe('api_key');
    });

    it('contains() should return false for empty keywords', () => {
      const ac = new AhoCorasick([]);
      expect(ac.contains('anything')).toBe(false);
    });
  });

  // ─── Single keyword ──────────────────────────────────────────

  describe('single keyword', () => {
    it('should find a single occurrence', () => {
      const ac = new AhoCorasick(['secret']);
      const results = ac.search('this is a secret value');
      expect(results).toHaveLength(1);
      expect(results[0]).toEqual({ keyword: 'secret', position: 10 });
    });

    it('should find all occurrences of the same keyword', () => {
      const ac = new AhoCorasick(['key']);
      const results = ac.search('key and another key and one more key');
      expect(results).toHaveLength(3);
      expect(results[0]!.position).toBe(0);
      expect(results[1]!.position).toBe(16);
      expect(results[2]!.position).toBe(33);
    });

    it('should find keyword at the very beginning of text', () => {
      const ac = new AhoCorasick(['password']);
      const results = ac.search('password=abc123');
      expect(results).toHaveLength(1);
      expect(results[0]!.position).toBe(0);
    });

    it('should find keyword at the very end of text', () => {
      const ac = new AhoCorasick(['token']);
      const results = ac.search('my_token');
      expect(results).toHaveLength(1);
      expect(results[0]!.position).toBe(3);
    });

    it('should handle keyword that is the entire text', () => {
      const ac = new AhoCorasick(['exact']);
      const results = ac.search('exact');
      expect(results).toHaveLength(1);
      expect(results[0]).toEqual({ keyword: 'exact', position: 0 });
    });
  });

  // ─── Multiple keywords ───────────────────────────────────────

  describe('multiple keywords', () => {
    it('should find all keywords simultaneously in one pass', () => {
      const ac = new AhoCorasick(['aws_secret', 'api_key', 'password']);
      const text = 'config has api_key=xyz and password=abc plus aws_secret=def';
      const results = ac.search(text);

      const keywords = results.map((r) => r.keyword);
      expect(keywords).toContain('api_key');
      expect(keywords).toContain('password');
      expect(keywords).toContain('aws_secret');
      expect(results).toHaveLength(3);
    });

    it('should report correct positions for each keyword', () => {
      const ac = new AhoCorasick(['ab', 'cd']);
      const results = ac.search('abcd');
      expect(results).toHaveLength(2);
      expect(results[0]).toEqual({ keyword: 'ab', position: 0 });
      expect(results[1]).toEqual({ keyword: 'cd', position: 2 });
    });

    it('should deduplicate identical keywords', () => {
      const ac = new AhoCorasick(['key', 'key', 'key']);
      expect(ac.getKeywords()).toEqual(['key']);
      const results = ac.search('key');
      expect(results).toHaveLength(1);
    });
  });

  // ─── Overlapping keywords ────────────────────────────────────

  describe('overlapping keywords', () => {
    it('should find overlapping keywords (one is substring of another)', () => {
      const ac = new AhoCorasick(['he', 'she', 'his', 'hers']);
      const results = ac.search('ushers');

      const keywords = results.map((r) => r.keyword);
      // "she" at position 1, "he" at position 2, "hers" at position 2
      expect(keywords).toContain('she');
      expect(keywords).toContain('he');
      expect(keywords).toContain('hers');
    });

    it('should find nested keywords', () => {
      const ac = new AhoCorasick(['a', 'ab', 'abc']);
      const results = ac.search('abc');

      expect(results.length).toBeGreaterThanOrEqual(3);
      const keywords = results.map((r) => r.keyword);
      expect(keywords).toContain('a');
      expect(keywords).toContain('ab');
      expect(keywords).toContain('abc');
    });

    it('should handle keywords that share prefixes', () => {
      const ac = new AhoCorasick(['api_key', 'api_secret', 'api_token']);
      const text = 'use api_key and api_secret and api_token';
      const results = ac.search(text);
      expect(results).toHaveLength(3);
    });
  });

  // ─── Case sensitivity ────────────────────────────────────────

  describe('case sensitivity', () => {
    it('should be case-sensitive by default', () => {
      const ac = new AhoCorasick(['Password']);
      expect(ac.search('password')).toHaveLength(0);
      expect(ac.search('PASSWORD')).toHaveLength(0);
      expect(ac.search('Password')).toHaveLength(1);
    });

    it('should match exact case only', () => {
      const ac = new AhoCorasick(['API_KEY']);
      const results = ac.search('api_key API_KEY Api_Key');
      expect(results).toHaveLength(1);
      expect(results[0]!.position).toBe(8);
    });
  });

  // ─── No matches found ────────────────────────────────────────

  describe('no matches', () => {
    it('should return empty array when no keywords match', () => {
      const ac = new AhoCorasick(['secret', 'password', 'token']);
      const results = ac.search('this text contains nothing suspicious');
      expect(results).toEqual([]);
    });

    it('should return empty array for empty text', () => {
      const ac = new AhoCorasick(['secret']);
      const results = ac.search('');
      expect(results).toEqual([]);
    });

    it('contains() should return false when no keywords match', () => {
      const ac = new AhoCorasick(['xyz']);
      expect(ac.contains('abc def')).toBe(false);
    });

    it('contains() should return false for empty text', () => {
      const ac = new AhoCorasick(['secret']);
      expect(ac.contains('')).toBe(false);
    });
  });

  // ─── Unicode support ─────────────────────────────────────────

  describe('unicode support', () => {
    it('should match Unicode keywords', () => {
      const ac = new AhoCorasick(['\u30D1\u30B9\u30EF\u30FC\u30C9', '\u5BC6\u7801']);
      const results = ac.search('\u8A2D\u5B9A\u306E\u30D1\u30B9\u30EF\u30FC\u30C9=abc');
      expect(results).toHaveLength(1);
      expect(results[0]!.keyword).toBe('\u30D1\u30B9\u30EF\u30FC\u30C9');
    });

    it('should handle emoji characters in text', () => {
      const ac = new AhoCorasick(['key']);
      const results = ac.search('\uD83D\uDD11 key is here');
      expect(results).toHaveLength(1);
      expect(results[0]!.keyword).toBe('key');
    });

    it('should match mixed ASCII and Unicode keywords', () => {
      const ac = new AhoCorasick(['api_key', '\u6A5F\u5BC6']);
      const text = 'api_key=xyz and \u6A5F\u5BC6=abc';
      const results = ac.search(text);
      expect(results).toHaveLength(2);
    });
  });

  // ─── Large text performance ───────────────────────────────────

  describe('large text performance', () => {
    it('should handle 1MB+ text without errors', () => {
      const keywords = ['aws_secret_access_key', 'AKIA', 'password', 'private_key'];
      const ac = new AhoCorasick(keywords);

      // Generate ~1MB of text with a few secrets embedded
      const filler = 'const config = loadFromEnv();\n'.repeat(40_000); // ~1.16MB
      const text =
        filler.slice(0, 500_000) +
        'aws_secret_access_key=wJalrXUtnFEMI\n' +
        filler.slice(500_000, 800_000) +
        'AKIAIOSFODNN7EXAMPLE\n' +
        filler.slice(800_000);

      const start = performance.now();
      const results = ac.search(text);
      const elapsed = performance.now() - start;

      expect(results.length).toBeGreaterThanOrEqual(2);
      const keywords_found = results.map((r) => r.keyword);
      expect(keywords_found).toContain('aws_secret_access_key');
      expect(keywords_found).toContain('AKIA');

      // Should complete in reasonable time (< 1 second for 1MB)
      expect(elapsed).toBeLessThan(1000);
    });

    it('should handle text with many matches efficiently', () => {
      const ac = new AhoCorasick(['key']);
      // "key" appears 10,000 times
      const text = 'key=value\n'.repeat(10_000);

      const start = performance.now();
      const results = ac.search(text);
      const elapsed = performance.now() - start;

      expect(results).toHaveLength(10_000);
      expect(elapsed).toBeLessThan(1000);
    });
  });

  // ─── contains() method ───────────────────────────────────────

  describe('contains()', () => {
    it('should return true on first match (short-circuit)', () => {
      const ac = new AhoCorasick(['needle']);
      expect(ac.contains('find the needle in the haystack')).toBe(true);
    });

    it('should return false when keyword not present', () => {
      const ac = new AhoCorasick(['needle']);
      expect(ac.contains('no match here')).toBe(false);
    });
  });

  // ─── getKeywords() ───────────────────────────────────────────

  describe('getKeywords()', () => {
    it('should return the deduplicated keyword list', () => {
      const ac = new AhoCorasick(['b', 'a', 'a', 'c', 'b']);
      const kw = ac.getKeywords();
      expect(kw).toHaveLength(3);
      expect(kw).toContain('a');
      expect(kw).toContain('b');
      expect(kw).toContain('c');
    });
  });
});

// ─── AhoCorasickCaseInsensitive ────────────────────────────────

describe('AhoCorasickCaseInsensitive', () => {
  it('should match regardless of case', () => {
    const ac = new AhoCorasickCaseInsensitive(['Password', 'API_KEY']);
    const results = ac.search('my password and api_key');
    expect(results).toHaveLength(2);
  });

  it('should match uppercase text against lowercase keywords', () => {
    const ac = new AhoCorasickCaseInsensitive(['secret']);
    expect(ac.contains('MY SECRET VALUE')).toBe(true);
  });

  it('should match mixed case', () => {
    const ac = new AhoCorasickCaseInsensitive(['token']);
    const results = ac.search('Token TOKEN token ToKeN');
    expect(results).toHaveLength(4);
  });

  it('should return original keywords from getKeywords()', () => {
    const ac = new AhoCorasickCaseInsensitive(['Password', 'API_KEY']);
    const kw = ac.getKeywords();
    expect(kw).toContain('Password');
    expect(kw).toContain('API_KEY');
  });

  it('contains() should be case-insensitive', () => {
    const ac = new AhoCorasickCaseInsensitive(['secret']);
    expect(ac.contains('SECRET')).toBe(true);
    expect(ac.contains('Secret')).toBe(true);
    expect(ac.contains('sEcReT')).toBe(true);
    expect(ac.contains('nothing')).toBe(false);
  });
});

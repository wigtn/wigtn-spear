import { describe, it, expect } from 'vitest';
import { parseDiff, extractAddedContent } from '../src/diff-parser.js';

describe('parseDiff', () => {
  // ─── Simple single-file diff ─────────────────────────────────

  describe('simple single-file diff', () => {
    it('should parse a single-file diff with one hunk', () => {
      const diff = [
        'diff --git a/config.ts b/config.ts',
        'index abc1234..def5678 100644',
        '--- a/config.ts',
        '+++ b/config.ts',
        '@@ -1,3 +1,4 @@',
        ' const config = {',
        '+  apiKey: "sk-1234567890abcdef",',
        '   host: "localhost",',
        '   port: 3000,',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('config.ts');
      expect(result[0]!.additions).toHaveLength(1);
      expect(result[0]!.additions[0]!.content).toBe('  apiKey: "sk-1234567890abcdef",');
      expect(result[0]!.additions[0]!.line).toBe(2);
    });

    it('should parse multiple added lines in a single hunk', () => {
      const diff = [
        'diff --git a/env.ts b/env.ts',
        '--- a/env.ts',
        '+++ b/env.ts',
        '@@ -1,2 +1,5 @@',
        ' export const env = {',
        '+  DB_PASSWORD: "hunter2",',
        '+  API_SECRET: "abc123",',
        '+  TOKEN: "xyz789",',
        ' };',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.additions).toHaveLength(3);
      expect(result[0]!.additions[0]!.line).toBe(2);
      expect(result[0]!.additions[1]!.line).toBe(3);
      expect(result[0]!.additions[2]!.line).toBe(4);
    });
  });

  // ─── Multi-file diff ─────────────────────────────────────────

  describe('multi-file diff', () => {
    it('should parse a diff with multiple files', () => {
      const diff = [
        'diff --git a/file1.ts b/file1.ts',
        '--- a/file1.ts',
        '+++ b/file1.ts',
        '@@ -1,2 +1,3 @@',
        ' line1',
        '+added in file1',
        ' line2',
        'diff --git a/file2.ts b/file2.ts',
        '--- a/file2.ts',
        '+++ b/file2.ts',
        '@@ -1,2 +1,3 @@',
        ' lineA',
        '+added in file2',
        ' lineB',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(2);
      expect(result[0]!.file).toBe('file1.ts');
      expect(result[0]!.additions).toHaveLength(1);
      expect(result[0]!.additions[0]!.content).toBe('added in file1');

      expect(result[1]!.file).toBe('file2.ts');
      expect(result[1]!.additions).toHaveLength(1);
      expect(result[1]!.additions[0]!.content).toBe('added in file2');
    });

    it('should handle three files in a single diff', () => {
      const diff = [
        'diff --git a/a.ts b/a.ts',
        '--- a/a.ts',
        '+++ b/a.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_a',
        'diff --git a/b.ts b/b.ts',
        '--- a/b.ts',
        '+++ b/b.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_b',
        'diff --git a/c.ts b/c.ts',
        '--- a/c.ts',
        '+++ b/c.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_c',
      ].join('\n');

      const result = parseDiff(diff);
      expect(result).toHaveLength(3);
      expect(result.map((f) => f.file)).toEqual(['a.ts', 'b.ts', 'c.ts']);
    });
  });

  // ─── Binary files ────────────────────────────────────────────

  describe('binary files', () => {
    it('should skip binary files (Binary files marker)', () => {
      const diff = [
        'diff --git a/image.png b/image.png',
        'Binary files /dev/null and b/image.png differ',
        'diff --git a/code.ts b/code.ts',
        '--- a/code.ts',
        '+++ b/code.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_code',
      ].join('\n');

      const result = parseDiff(diff);

      // Only the text file should appear
      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('code.ts');
    });

    it('should skip GIT binary patch files', () => {
      const diff = [
        'diff --git a/data.bin b/data.bin',
        'GIT binary patch',
        'literal 1234',
        'some binary data here',
        '',
        'diff --git a/text.ts b/text.ts',
        '--- a/text.ts',
        '+++ b/text.ts',
        '@@ -1 +1,2 @@',
        ' line1',
        '+added_line',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('text.ts');
    });
  });

  // ─── Deleted files (/dev/null) ───────────────────────────────

  describe('deleted files', () => {
    it('should skip deleted files (+++ /dev/null)', () => {
      const diff = [
        'diff --git a/removed.ts b/removed.ts',
        '--- a/removed.ts',
        '+++ /dev/null',
        '@@ -1,3 +0,0 @@',
        '-line1',
        '-line2',
        '-line3',
      ].join('\n');

      const result = parseDiff(diff);

      // Deleted file should not produce any results
      expect(result).toHaveLength(0);
    });

    it('should skip deleted files but include other files', () => {
      const diff = [
        'diff --git a/removed.ts b/removed.ts',
        '--- a/removed.ts',
        '+++ /dev/null',
        '@@ -1,2 +0,0 @@',
        '-old line1',
        '-old line2',
        'diff --git a/kept.ts b/kept.ts',
        '--- a/kept.ts',
        '+++ b/kept.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new content',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('kept.ts');
    });
  });

  // ─── Rename handling ─────────────────────────────────────────

  describe('rename handling', () => {
    it('should use the new file path from +++ header', () => {
      const diff = [
        'diff --git a/old-name.ts b/new-name.ts',
        'similarity index 90%',
        'rename from old-name.ts',
        'rename to new-name.ts',
        '--- a/old-name.ts',
        '+++ b/new-name.ts',
        '@@ -1,2 +1,3 @@',
        ' existing',
        '+added after rename',
        ' other',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('new-name.ts');
      expect(result[0]!.additions[0]!.content).toBe('added after rename');
    });
  });

  // ─── Correct line numbers from hunk headers ──────────────────

  describe('hunk header line numbers', () => {
    it('should start line numbers from the hunk header +start value', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -10,3 +10,4 @@',
        ' context line at 10',
        '+added line at 11',
        ' context line at 12',
        ' context line at 13',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.additions[0]!.line).toBe(11);
    });

    it('should handle multiple hunks with different starting lines', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -1,3 +1,4 @@',
        ' line1',
        '+added_at_line_2',
        ' line3',
        ' line4',
        '@@ -20,3 +21,4 @@',
        ' line at 21',
        '+added_at_line_22',
        ' line at 23',
        ' line at 24',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.additions).toHaveLength(2);
      expect(result[0]!.additions[0]!.line).toBe(2);
      expect(result[0]!.additions[1]!.line).toBe(22);
    });

    it('should correctly track line numbers with deletions interspersed', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -1,5 +1,5 @@',
        ' line1',
        '-deleted_old',
        '+added_new',
        ' line3',
        '-deleted_old2',
        '+added_new2',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.additions).toHaveLength(2);
      // After line1 (line 1), deleted line doesn't advance new counter
      // added_new is at line 2
      expect(result[0]!.additions[0]!.line).toBe(2);
      // Context line3 advances to line 3, deleted doesn't advance
      // added_new2 is at line 4
      expect(result[0]!.additions[1]!.line).toBe(4);
    });
  });

  // ─── Empty diff ──────────────────────────────────────────────

  describe('empty diff', () => {
    it('should return empty array for empty string', () => {
      expect(parseDiff('')).toEqual([]);
    });

    it('should return empty array for null-ish input', () => {
      // parseDiff checks !diffContent
      expect(parseDiff(undefined as unknown as string)).toEqual([]);
    });

    it('should return empty array for diff with no additions', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -1,3 +1,2 @@',
        ' line1',
        '-removed_line',
        ' line3',
      ].join('\n');

      const result = parseDiff(diff);
      expect(result).toHaveLength(0);
    });
  });

  // ─── "No newline at end of file" marker ──────────────────────

  describe('no newline marker', () => {
    it('should handle "No newline at end of file" marker', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -1,2 +1,3 @@',
        ' line1',
        '+added_line',
        ' line3',
        '\\ No newline at end of file',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      expect(result[0]!.additions).toHaveLength(1);
      expect(result[0]!.additions[0]!.content).toBe('added_line');
    });
  });

  // ─── Files without b/ prefix ─────────────────────────────────

  describe('path format edge cases', () => {
    it('should handle paths without b/ prefix', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ file.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_content',
      ].join('\n');

      const result = parseDiff(diff);
      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('file.ts');
    });

    it('should strip b/ prefix from standard git diff paths', () => {
      const diff = [
        'diff --git a/src/deep/path.ts b/src/deep/path.ts',
        '--- a/src/deep/path.ts',
        '+++ b/src/deep/path.ts',
        '@@ -1 +1,2 @@',
        ' existing',
        '+new_content',
      ].join('\n');

      const result = parseDiff(diff);
      expect(result).toHaveLength(1);
      expect(result[0]!.file).toBe('src/deep/path.ts');
    });
  });

  // ─── Empty addition lines (just "+") ─────────────────────────

  describe('empty addition lines', () => {
    it('should skip lines that are just "+" with no content', () => {
      const diff = [
        'diff --git a/file.ts b/file.ts',
        '--- a/file.ts',
        '+++ b/file.ts',
        '@@ -1,2 +1,4 @@',
        ' line1',
        '+',           // empty addition - should be skipped
        '+real_content',
        ' line2',
      ].join('\n');

      const result = parseDiff(diff);

      expect(result).toHaveLength(1);
      // Only the non-empty addition should be included
      expect(result[0]!.additions).toHaveLength(1);
      expect(result[0]!.additions[0]!.content).toBe('real_content');
    });
  });
});

// ─── extractAddedContent ───────────────────────────────────────

describe('extractAddedContent', () => {
  it('should concatenate all additions from all files', () => {
    const diff = [
      'diff --git a/a.ts b/a.ts',
      '--- a/a.ts',
      '+++ b/a.ts',
      '@@ -1 +1,2 @@',
      ' existing',
      '+line_from_a',
      'diff --git a/b.ts b/b.ts',
      '--- a/b.ts',
      '+++ b/b.ts',
      '@@ -1 +1,2 @@',
      ' existing',
      '+line_from_b',
    ].join('\n');

    const content = extractAddedContent(diff);
    expect(content).toBe('line_from_a\nline_from_b');
  });

  it('should return empty string for empty diff', () => {
    expect(extractAddedContent('')).toBe('');
  });

  it('should return empty string for diff with no additions', () => {
    const diff = [
      'diff --git a/file.ts b/file.ts',
      '--- a/file.ts',
      '+++ b/file.ts',
      '@@ -1,2 +1,1 @@',
      ' kept',
      '-removed',
    ].join('\n');

    expect(extractAddedContent(diff)).toBe('');
  });
});

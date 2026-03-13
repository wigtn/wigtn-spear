import { describe, it, expect, beforeEach } from 'vitest';
import { OopsDetector } from '../src/oops-detector.js';

describe('OopsDetector', () => {
  let detector: OopsDetector;

  beforeEach(() => {
    detector = new OopsDetector();
  });

  // ─── Track addition and detect removal within threshold ──────

  describe('basic oops detection', () => {
    it('should detect oops when removal is within commit and time distance', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc123',
        file: 'config.ts',
        content: 'AKIAIOSFODNN7EXAMPLE',
        ruleId: 'aws-access-key',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'config.ts',
        'AKIAIOSFODNN7EXAMPLE',
        'aws-access-key',
        3, // 2 commits distance (<= 5)
        now + 30 * 60 * 1000, // 30 minutes later (<= 1 hour)
      );

      expect(result.isOops).toBe(true);
      expect(result.addedInCommit).toBe('abc123');
      expect(result.commitDistance).toBe(2);
      expect(result.timeDistanceMs).toBe(30 * 60 * 1000);
    });

    it('should detect oops at exact boundary (5 commits, 1 hour)', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'boundary-test',
        file: 'env.ts',
        content: 'secret_value',
        ruleId: 'generic-secret',
        commitSequence: 10,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'env.ts',
        'secret_value',
        'generic-secret',
        15, // exactly 5 commits distance
        now + 60 * 60 * 1000, // exactly 1 hour
      );

      expect(result.isOops).toBe(true);
    });

    it('should remove tracked entry after detection (prevent double-counting)', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc123',
        file: 'config.ts',
        content: 'secret123',
        ruleId: 'generic',
        commitSequence: 1,
        commitTimestamp: now,
      });

      expect(detector.trackedCount).toBe(1);

      // First check - should detect oops and remove from tracking
      const result1 = detector.checkForRemoval(
        'config.ts', 'secret123', 'generic', 2, now + 1000,
      );
      expect(result1.isOops).toBe(true);
      expect(detector.trackedCount).toBe(0);

      // Second check - should not find it anymore
      const result2 = detector.checkForRemoval(
        'config.ts', 'secret123', 'generic', 3, now + 2000,
      );
      expect(result2.isOops).toBe(false);
    });
  });

  // ─── No detection if beyond commit distance ──────────────────

  describe('commit distance threshold', () => {
    it('should not detect oops when commit distance exceeds 5', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc123',
        file: 'config.ts',
        content: 'secret_value',
        ruleId: 'generic-secret',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'config.ts',
        'secret_value',
        'generic-secret',
        7, // 6 commits distance (> 5)
        now + 10 * 60 * 1000, // within time threshold
      );

      expect(result.isOops).toBe(false);
      expect(result.addedInCommit).toBe('abc123'); // still returns info
      expect(result.commitDistance).toBe(6);
    });

    it('should not detect oops at commit distance 6', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'test',
        file: 'a.ts',
        content: 'key123',
        ruleId: 'rule-a',
        commitSequence: 10,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'a.ts', 'key123', 'rule-a', 16, now + 1000,
      );

      expect(result.isOops).toBe(false);
      expect(result.commitDistance).toBe(6);
    });
  });

  // ─── No detection if beyond time distance ────────────────────

  describe('time distance threshold', () => {
    it('should not detect oops when time distance exceeds 1 hour', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc123',
        file: 'config.ts',
        content: 'secret_value',
        ruleId: 'generic-secret',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'config.ts',
        'secret_value',
        'generic-secret',
        2, // within commit threshold
        now + 2 * 60 * 60 * 1000, // 2 hours later (> 1 hour)
      );

      expect(result.isOops).toBe(false);
      expect(result.timeDistanceMs).toBe(2 * 60 * 60 * 1000);
    });

    it('should not detect oops at time distance 1 hour + 1ms', () => {
      const now = Date.now();
      const oneHourPlusOne = 60 * 60 * 1000 + 1;

      detector.trackSecretAddition({
        commitHash: 'test',
        file: 'a.ts',
        content: 'key123',
        ruleId: 'rule-a',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'a.ts', 'key123', 'rule-a', 2, now + oneHourPlusOne,
      );

      expect(result.isOops).toBe(false);
    });

    it('should require BOTH thresholds to be met (not just one)', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'f.ts',
        content: 'val',
        ruleId: 'r',
        commitSequence: 1,
        commitTimestamp: now,
      });

      // Within time, but beyond commit distance
      const r1 = detector.checkForRemoval('f.ts', 'val', 'r', 100, now + 1000);
      expect(r1.isOops).toBe(false);
    });
  });

  // ─── No match for unknown secrets ────────────────────────────

  describe('untracked secrets', () => {
    it('should return isOops=false for a secret that was never tracked', () => {
      const result = detector.checkForRemoval(
        'unknown.ts', 'unknown_value', 'unknown-rule', 1, Date.now(),
      );
      expect(result.isOops).toBe(false);
      expect(result.addedInCommit).toBeUndefined();
      expect(result.commitDistance).toBeUndefined();
    });

    it('should not match if file differs', () => {
      const now = Date.now();
      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'config.ts',
        content: 'secret',
        ruleId: 'rule-a',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'other-file.ts', 'secret', 'rule-a', 2, now + 1000,
      );
      expect(result.isOops).toBe(false);
    });

    it('should not match if ruleId differs', () => {
      const now = Date.now();
      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'config.ts',
        content: 'secret',
        ruleId: 'rule-a',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'config.ts', 'secret', 'rule-b', 2, now + 1000,
      );
      expect(result.isOops).toBe(false);
    });

    it('should not match if content differs', () => {
      const now = Date.now();
      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'config.ts',
        content: 'secret_A',
        ruleId: 'rule-a',
        commitSequence: 1,
        commitTimestamp: now,
      });

      const result = detector.checkForRemoval(
        'config.ts', 'secret_B', 'rule-a', 2, now + 1000,
      );
      expect(result.isOops).toBe(false);
    });
  });

  // ─── Clear resets state ──────────────────────────────────────

  describe('clear', () => {
    it('should reset all tracked additions', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'a.ts',
        content: 'val1',
        ruleId: 'r1',
        commitSequence: 1,
        commitTimestamp: now,
      });
      detector.trackSecretAddition({
        commitHash: 'def',
        file: 'b.ts',
        content: 'val2',
        ruleId: 'r2',
        commitSequence: 2,
        commitTimestamp: now,
      });

      expect(detector.trackedCount).toBe(2);

      detector.clear();

      expect(detector.trackedCount).toBe(0);

      // Previously tracked secrets should not be found
      const result = detector.checkForRemoval('a.ts', 'val1', 'r1', 2, now + 1000);
      expect(result.isOops).toBe(false);
    });
  });

  // ─── Prune removes old entries ───────────────────────────────

  describe('prune', () => {
    it('should remove entries beyond MAX_COMMIT_DISTANCE * 2', () => {
      const now = Date.now();

      // MAX_COMMIT_DISTANCE = 5, so prune threshold = 10
      detector.trackSecretAddition({
        commitHash: 'old',
        file: 'old.ts',
        content: 'old_secret',
        ruleId: 'rule-old',
        commitSequence: 1,
        commitTimestamp: now,
      });

      detector.trackSecretAddition({
        commitHash: 'recent',
        file: 'recent.ts',
        content: 'recent_secret',
        ruleId: 'rule-recent',
        commitSequence: 10,
        commitTimestamp: now,
      });

      expect(detector.trackedCount).toBe(2);

      // Prune at sequence 12: old (12-1=11 > 10) should be removed,
      // recent (12-10=2 <= 10) should stay
      detector.prune(12);

      expect(detector.trackedCount).toBe(1);

      // Old entry should be gone
      const oldResult = detector.checkForRemoval(
        'old.ts', 'old_secret', 'rule-old', 12, now + 1000,
      );
      expect(oldResult.isOops).toBe(false);
      expect(oldResult.addedInCommit).toBeUndefined();

      // Recent entry should still be there
      const recentResult = detector.checkForRemoval(
        'recent.ts', 'recent_secret', 'rule-recent', 12, now + 1000,
      );
      // commit distance 2 (<= 5) and time distance is small -> isOops
      expect(recentResult.addedInCommit).toBe('recent');
    });

    it('should keep entries at exact prune boundary', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'boundary',
        file: 'f.ts',
        content: 'val',
        ruleId: 'r',
        commitSequence: 2,
        commitTimestamp: now,
      });

      // Prune at 12: 12 - 2 = 10, which is NOT > 10, so should keep
      detector.prune(12);
      expect(detector.trackedCount).toBe(1);
    });

    it('should remove entries beyond prune boundary', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'beyond',
        file: 'f.ts',
        content: 'val',
        ruleId: 'r',
        commitSequence: 1,
        commitTimestamp: now,
      });

      // Prune at 12: 12 - 1 = 11 > 10, so should remove
      detector.prune(12);
      expect(detector.trackedCount).toBe(0);
    });
  });

  // ─── Content trimming for key matching ───────────────────────

  describe('content normalization', () => {
    it('should match content with leading/trailing whitespace differences', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'abc',
        file: 'config.ts',
        content: '  AKIAIOSFODNN7EXAMPLE  ',
        ruleId: 'aws-key',
        commitSequence: 1,
        commitTimestamp: now,
      });

      // Removal has different whitespace but same trimmed content
      const result = detector.checkForRemoval(
        'config.ts',
        'AKIAIOSFODNN7EXAMPLE',
        'aws-key',
        2,
        now + 1000,
      );

      expect(result.isOops).toBe(true);
    });
  });

  // ─── Multiple secrets tracked simultaneously ─────────────────

  describe('multiple tracked secrets', () => {
    it('should track and detect multiple different secrets', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'c1',
        file: 'config.ts',
        content: 'secret_A',
        ruleId: 'rule-1',
        commitSequence: 1,
        commitTimestamp: now,
      });

      detector.trackSecretAddition({
        commitHash: 'c2',
        file: 'env.ts',
        content: 'secret_B',
        ruleId: 'rule-2',
        commitSequence: 2,
        commitTimestamp: now + 1000,
      });

      expect(detector.trackedCount).toBe(2);

      const r1 = detector.checkForRemoval(
        'config.ts', 'secret_A', 'rule-1', 3, now + 5000,
      );
      expect(r1.isOops).toBe(true);
      expect(r1.addedInCommit).toBe('c1');

      const r2 = detector.checkForRemoval(
        'env.ts', 'secret_B', 'rule-2', 4, now + 10000,
      );
      expect(r2.isOops).toBe(true);
      expect(r2.addedInCommit).toBe('c2');
    });

    it('should overwrite tracking for same file+rule+content key', () => {
      const now = Date.now();

      detector.trackSecretAddition({
        commitHash: 'first',
        file: 'f.ts',
        content: 'same_secret',
        ruleId: 'r1',
        commitSequence: 1,
        commitTimestamp: now,
      });

      detector.trackSecretAddition({
        commitHash: 'second',
        file: 'f.ts',
        content: 'same_secret',
        ruleId: 'r1',
        commitSequence: 5,
        commitTimestamp: now + 30000,
      });

      // Should have 1 entry (overwritten)
      expect(detector.trackedCount).toBe(1);

      const result = detector.checkForRemoval(
        'f.ts', 'same_secret', 'r1', 6, now + 60000,
      );

      // Should reference the second (overwritten) entry
      expect(result.isOops).toBe(true);
      expect(result.addedInCommit).toBe('second');
    });
  });
});

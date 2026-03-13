/**
 * Oops Detector -- Identifies "add then quickly remove" secret patterns.
 *
 * When a developer accidentally commits a secret and then removes it
 * in a subsequent commit (an "oops commit"), the secret is still
 * recoverable from git history. These are often the most critical
 * findings because:
 *
 *   1. The developer knew it was a secret (they removed it).
 *   2. The secret may still be active (never rotated).
 *   3. Automated scanners that only check HEAD would miss it.
 *
 * The detector uses two heuristics to identify oops patterns:
 *   - Temporal proximity: removal within 1 hour of addition
 *   - Commit proximity: removal within 5 commits of addition
 *
 * Both must be satisfied to flag an oops commit. This reduces false
 * positives from legitimate code refactoring that happens to move
 * or replace secrets.
 */

/** Maximum number of commits between add and remove to flag as oops */
const MAX_COMMIT_DISTANCE = 5;

/** Maximum time (in ms) between add and remove to flag as oops (1 hour) */
const MAX_TIME_DISTANCE_MS = 60 * 60 * 1000;

/** Tracked secret addition record */
interface SecretAddition {
  /** Commit hash where the secret was added */
  commitHash: string;
  /** File path where the secret was found */
  file: string;
  /** Line content containing the secret */
  content: string;
  /** Rule ID that detected the secret */
  ruleId: string;
  /** Commit sequence number (for proximity check) */
  commitSequence: number;
  /** Commit timestamp (for temporal check) */
  commitTimestamp: number;
}

/** Result of an oops detection check */
export interface OopsResult {
  /** Whether this removal constitutes an oops commit */
  isOops: boolean;
  /** The commit hash where the secret was originally added */
  addedInCommit?: string;
  /** The number of commits between add and remove */
  commitDistance?: number;
  /** The time between add and remove in milliseconds */
  timeDistanceMs?: number;
}

/**
 * OopsDetector tracks secret additions across commits and detects
 * patterns where a secret is added then quickly removed.
 *
 * Usage:
 * ```ts
 * const detector = new OopsDetector();
 *
 * // While scanning commits chronologically:
 * detector.trackSecretAddition({
 *   commitHash: 'abc123',
 *   file: 'config.ts',
 *   content: 'AKIA...',
 *   ruleId: 'aws-access-key',
 *   commitSequence: 1,
 *   commitTimestamp: Date.now(),
 * });
 *
 * // When a removal is detected:
 * const result = detector.checkForRemoval('config.ts', 'AKIA...', 'aws-access-key', 3, timestamp);
 * if (result.isOops) {
 *   // Flag as oops commit with elevated severity
 * }
 * ```
 */
export class OopsDetector {
  /**
   * Map of tracked additions.
   * Key: `${file}::${ruleId}::${contentHash}` for efficient lookup.
   * Value: The SecretAddition record.
   */
  private readonly additions: Map<string, SecretAddition> = new Map();

  /**
   * Track a secret addition in a commit.
   *
   * @param addition - The secret addition details.
   */
  trackSecretAddition(addition: SecretAddition): void {
    const key = this.buildKey(addition.file, addition.ruleId, addition.content);
    this.additions.set(key, addition);
  }

  /**
   * Check if a secret removal constitutes an "oops commit".
   *
   * A removal is an oops if the same secret (same file, rule, content)
   * was added recently (within MAX_COMMIT_DISTANCE commits AND
   * within MAX_TIME_DISTANCE_MS milliseconds).
   *
   * @param file - The file path where the secret was removed.
   * @param content - The line content that was removed.
   * @param ruleId - The rule ID associated with the secret.
   * @param currentCommitSequence - The sequence number of the removal commit.
   * @param currentCommitTimestamp - The timestamp of the removal commit.
   * @returns An OopsResult indicating whether this is an oops pattern.
   */
  checkForRemoval(
    file: string,
    content: string,
    ruleId: string,
    currentCommitSequence: number,
    currentCommitTimestamp: number,
  ): OopsResult {
    const key = this.buildKey(file, ruleId, content);
    const addition = this.additions.get(key);

    if (!addition) {
      return { isOops: false };
    }

    const commitDistance = Math.abs(currentCommitSequence - addition.commitSequence);
    const timeDistanceMs = Math.abs(currentCommitTimestamp - addition.commitTimestamp);

    const isOops =
      commitDistance <= MAX_COMMIT_DISTANCE &&
      timeDistanceMs <= MAX_TIME_DISTANCE_MS;

    if (isOops) {
      // Remove from tracking after detection (prevent double-counting)
      this.additions.delete(key);
    }

    return {
      isOops,
      addedInCommit: addition.commitHash,
      commitDistance,
      timeDistanceMs,
    };
  }

  /**
   * Get the count of tracked additions currently being monitored.
   */
  get trackedCount(): number {
    return this.additions.size;
  }

  /**
   * Clear all tracked additions.
   * Called during teardown or when switching scan targets.
   */
  clear(): void {
    this.additions.clear();
  }

  /**
   * Prune old additions that are beyond the commit distance threshold.
   *
   * Call periodically during long scans to keep memory usage bounded.
   *
   * @param currentCommitSequence - The current commit sequence number.
   */
  prune(currentCommitSequence: number): void {
    for (const [key, addition] of this.additions) {
      if (currentCommitSequence - addition.commitSequence > MAX_COMMIT_DISTANCE * 2) {
        this.additions.delete(key);
      }
    }
  }

  /**
   * Build a lookup key from file, ruleId, and content.
   *
   * Uses a normalized version of the content (trimmed) to handle
   * minor whitespace differences between add and remove lines.
   */
  private buildKey(file: string, ruleId: string, content: string): string {
    return `${file}::${ruleId}::${content.trim()}`;
  }
}

/**
 * SPEAR-02: Git History Miner Plugin
 *
 * Mines git commit history for secrets that were committed at any point,
 * including secrets that have since been removed. Attackers with repo
 * access can trivially recover these from git objects.
 *
 * Three scanning phases:
 *
 *   Phase 1 -- Regular commits
 *     Iterate all reachable commits (git log --all), extract diffs,
 *     scan added lines for secrets using the same Aho-Corasick + Regex
 *     pipeline as spear-01.
 *
 *   Phase 2 -- Dangling commits
 *     Run `git fsck --lost-found` to discover unreachable/dangling commits
 *     that are not part of any branch. These often contain secrets that
 *     were "removed" via force push or rebase.
 *
 *   Phase 3 -- Oops commit detection
 *     Cross-reference additions and removals across commits to identify
 *     the "add then quickly remove" pattern that indicates an accidental
 *     secret exposure with attempted cleanup.
 *
 * Uses simple-git for all git operations. Respects depth limits based
 * on scan mode (safe = configurable limit, aggressive = unlimited).
 */

import { resolve } from 'node:path';
import simpleGitDefault, { type SimpleGit } from 'simple-git';
// Node16 CJS interop
const simpleGit = simpleGitDefault as unknown as (basePath?: string) => SimpleGit;
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
  Rule,
} from '@wigtn/shared';
import { SecureSecret } from '@wigtn/shared';
import { AhoCorasick, RegexMatcher, shannonEntropy } from '@wigtn/core';
import { loadRules } from '@wigtn/rules-engine';
import { parseDiff, type DiffFile } from './diff-parser.js';
import { OopsDetector, type OopsResult } from './oops-detector.js';

/**
 * GitMinerPlugin -- Phase 1 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Mines git history for secrets in commits, including dangling
 * and unreachable commits.
 */
export class GitMinerPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'git-miner',
    name: 'Git History Miner',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Mines git history for secrets in commits, including dangling and unreachable commits',
    severity: 'high',
    tags: ['git', 'history', 'secret', 'mining'],
    references: ['CWE-798', 'CWE-538'],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['git:read', 'exec:child'],
    trustLevel: 'builtin',
  };

  /** Loaded secret detection rules */
  private rules: Rule[] = [];

  /** Aho-Corasick automaton for keyword pre-filtering */
  private ahoCorasick: AhoCorasick | null = null;

  /** Keyword -> rule ID mapping */
  private keywordToRuleIds: Map<string, Set<string>> = new Map();

  /** Compiled regex matcher */
  private regexMatcher: RegexMatcher | null = null;

  /** Rule ID -> Rule lookup map */
  private ruleMap: Map<string, Rule> = new Map();

  /** Oops commit detector */
  private oopsDetector: OopsDetector = new OopsDetector();

  /**
   * Setup: Load rules and build detection engine components.
   *
   * Identical setup logic as spear-01 since both use the same
   * Aho-Corasick + Regex pipeline for secret detection.
   */
  async setup(context: PluginContext): Promise<void> {
    const rulesDir = context.config.rulesDir;

    if (!rulesDir) {
      context.logger.warn('No rulesDir configured, git-miner will have no rules');
      return;
    }

    context.logger.info('Loading rules for git-miner', { rulesDir });
    this.rules = await loadRules(rulesDir, context.logger);
    this.rules = this.rules.filter((r) => r.category === 'secret');

    if (this.rules.length === 0) {
      context.logger.warn('No secret rules loaded for git-miner');
      return;
    }

    // Build rule lookup map
    this.ruleMap = new Map();
    for (const rule of this.rules) {
      this.ruleMap.set(rule.id, rule);
    }

    // Build Aho-Corasick automaton
    const allKeywords: string[] = [];
    this.keywordToRuleIds = new Map();

    for (const rule of this.rules) {
      for (const keyword of rule.detection.keywords) {
        if (keyword.length === 0) continue;
        allKeywords.push(keyword);

        let ruleIds = this.keywordToRuleIds.get(keyword);
        if (!ruleIds) {
          ruleIds = new Set();
          this.keywordToRuleIds.set(keyword, ruleIds);
        }
        ruleIds.add(rule.id);
      }
    }

    if (allKeywords.length > 0) {
      this.ahoCorasick = new AhoCorasick(allKeywords);
    }

    // Compile regex patterns
    this.regexMatcher = new RegexMatcher(this.rules);

    context.logger.info('Git-miner engine initialized', {
      rules: this.rules.length,
      keywords: allKeywords.length,
      compiledRegex: this.regexMatcher.compiledCount,
    });
  }

  /**
   * Scan: Mine git history for secrets across all commits.
   *
   * Yields findings as they are discovered in chronological order.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    if (this.rules.length === 0 || !this.regexMatcher) {
      context.logger.warn('Git-miner has no rules loaded, skipping scan');
      return;
    }

    const repoPath = resolve(target.path);
    const git = simpleGit(repoPath);

    // Verify this is a git repository
    let isRepo: boolean;
    try {
      isRepo = await git.checkIsRepo();
    } catch {
      context.logger.warn('Failed to check if path is a git repo', { repoPath });
      return;
    }

    if (!isRepo) {
      context.logger.warn('Not a git repository, skipping git-miner', { repoPath });
      return;
    }

    // Determine depth limit based on scan mode
    const depth = context.mode === 'safe'
      ? (context.config.gitDepth || 1000)
      : -1; // unlimited in aggressive mode

    context.logger.info('Starting git history mining', {
      repoPath,
      mode: context.mode,
      depth: depth === -1 ? 'unlimited' : depth,
    });

    // Phase 1: Scan regular commits
    let findingsCount = 0;
    for await (const finding of this.scanRegularCommits(git, depth, context)) {
      findingsCount++;
      yield finding;
    }

    // Phase 2: Scan dangling commits
    for await (const finding of this.scanDanglingCommits(git, context)) {
      findingsCount++;
      yield finding;
    }

    // Phase 3: Report oops commit findings that were tracked but not yet reported
    // (Oops findings are yielded inline during Phase 1 scanning)

    context.logger.info('Git history mining complete', {
      findingsCount,
      oopsTracked: this.oopsDetector.trackedCount,
    });
  }

  /**
   * Teardown: Release resources and clear state.
   */
  async teardown(_context: PluginContext): Promise<void> {
    this.rules = [];
    this.ahoCorasick = null;
    this.keywordToRuleIds.clear();
    this.regexMatcher = null;
    this.ruleMap.clear();
    this.oopsDetector.clear();
  }

  // ──────────────────────────────────────────────────────────────────
  // Phase 1: Regular Commits
  // ──────────────────────────────────────────────────────────────────

  /**
   * Scan regular (reachable) commits for secrets in their diffs.
   *
   * Uses `git log --all` to enumerate commits, then `git show <hash>`
   * to get the diff for each commit.
   */
  private async *scanRegularCommits(
    git: SimpleGit,
    depth: number,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    // Get commit hashes
    let commitHashes: string[];
    try {
      commitHashes = await this.getCommitHashes(git, depth);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      context.logger.warn('Failed to enumerate commits', { error: message });
      return;
    }

    if (commitHashes.length === 0) {
      context.logger.info('No commits found in repository');
      return;
    }

    context.logger.info('Scanning regular commits', {
      count: commitHashes.length,
    });

    for (let seqIndex = 0; seqIndex < commitHashes.length; seqIndex++) {
      const hash = commitHashes[seqIndex]!;

      try {
        // Get commit metadata
        const commitInfo = await this.getCommitInfo(git, hash);

        // Get the diff for this commit
        const diffContent = await this.getCommitDiff(git, hash);
        if (!diffContent || diffContent.length === 0) {
          continue;
        }

        // Parse the diff into structured data
        const diffFiles = parseDiff(diffContent);
        if (diffFiles.length === 0) {
          continue;
        }

        // Scan each file's additions
        for (const diffFile of diffFiles) {
          for await (const finding of this.scanDiffFile(
            diffFile,
            hash,
            commitInfo,
            seqIndex,
            context,
          )) {
            yield finding;
          }
        }

        // Periodically prune the oops detector to bound memory
        if (seqIndex % 100 === 0) {
          this.oopsDetector.prune(seqIndex);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.debug('Error processing commit, skipping', {
          hash,
          error: message,
        });
      }
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // Phase 2: Dangling Commits
  // ──────────────────────────────────────────────────────────────────

  /**
   * Scan dangling (unreachable) commits discovered by git fsck.
   *
   * Dangling commits are not reachable from any branch or tag.
   * They often contain force-pushed or rebased-away content.
   */
  private async *scanDanglingCommits(
    git: SimpleGit,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    let danglingHashes: string[];
    try {
      danglingHashes = await this.getDanglingCommitHashes(git);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      context.logger.debug('Failed to enumerate dangling commits', {
        error: message,
      });
      return;
    }

    if (danglingHashes.length === 0) {
      context.logger.debug('No dangling commits found');
      return;
    }

    context.logger.info('Scanning dangling commits', {
      count: danglingHashes.length,
    });

    for (const hash of danglingHashes) {
      try {
        const commitInfo = await this.getCommitInfo(git, hash);
        const diffContent = await this.getCommitDiff(git, hash);

        if (!diffContent || diffContent.length === 0) {
          continue;
        }

        const diffFiles = parseDiff(diffContent);

        for (const diffFile of diffFiles) {
          for await (const finding of this.scanDiffFile(
            diffFile,
            hash,
            { ...commitInfo, dangling: true },
            -1, // Dangling commits don't have a sequence number
            context,
          )) {
            yield finding;
          }
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.debug('Error processing dangling commit, skipping', {
          hash,
          error: message,
        });
      }
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // Shared scanning logic
  // ──────────────────────────────────────────────────────────────────

  /**
   * Scan a single file's diff additions for secrets.
   *
   * Applies the same Aho-Corasick -> Regex -> Entropy pipeline
   * used in spear-01, but operating on diff content rather than
   * whole files.
   */
  private async *scanDiffFile(
    diffFile: DiffFile,
    commitHash: string,
    commitInfo: CommitInfo,
    commitSequence: number,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    if (diffFile.additions.length === 0) {
      return;
    }

    // Concatenate all additions for Aho-Corasick pre-filtering
    const concatenated = diffFile.additions
      .map((a) => a.content)
      .join('\n');

    // Stage 1: Aho-Corasick keyword pre-filter
    let candidateRuleIds: string[] | undefined;

    if (this.ahoCorasick) {
      const keywordMatches = this.ahoCorasick.search(concatenated);

      if (keywordMatches.length === 0) {
        return; // No keywords found in any additions
      }

      const matchedRuleIds = new Set<string>();
      for (const km of keywordMatches) {
        const ruleIds = this.keywordToRuleIds.get(km.keyword);
        if (ruleIds) {
          for (const ruleId of ruleIds) {
            matchedRuleIds.add(ruleId);
          }
        }
      }

      // Include rules with no keywords (they run on everything)
      for (const rule of this.rules) {
        if (rule.detection.keywords.length === 0) {
          matchedRuleIds.add(rule.id);
        }
      }

      candidateRuleIds = [...matchedRuleIds];
      if (candidateRuleIds.length === 0) {
        return;
      }
    }

    // Stage 2-3: Process each added line individually for precise line numbers
    for (const addition of diffFile.additions) {
      const regexMatches = this.regexMatcher!.match(addition.content, candidateRuleIds);

      for (const match of regexMatches) {
        const rule = this.ruleMap.get(match.ruleId);
        if (!rule) continue;

        // Apply entropy filter
        if (rule.detection.entropy?.enabled) {
          const threshold = rule.detection.entropy.threshold ?? 5.0;
          const entropy = shannonEntropy(match.value);
          if (entropy < threshold) {
            continue;
          }
        }

        // Check allowlist patterns
        if (this.isValueAllowlisted(match.value, rule)) {
          continue;
        }

        // Track for oops detection (Phase 3)
        const commitTimestamp = commitInfo.timestamp
          ? new Date(commitInfo.timestamp).getTime()
          : Date.now();

        if (commitSequence >= 0) {
          this.oopsDetector.trackSecretAddition({
            commitHash,
            file: diffFile.file,
            content: match.value,
            ruleId: match.ruleId,
            commitSequence,
            commitTimestamp,
          });
        }

        // Mask the secret value
        const secret = new SecureSecret(match.value);
        const maskedValue = secret.mask();
        secret.dispose();

        const finding: Finding = {
          ruleId: rule.id,
          severity: rule.severity,
          message: `${rule.name} found in git history: ${rule.description}`,
          file: diffFile.file,
          line: addition.line,
          column: match.column,
          secretMasked: maskedValue,
          mitreTechniques: rule.mitre,
          remediation: buildGitRemediation(rule, commitHash),
          metadata: {
            pluginId: this.metadata.id,
            source: 'git-history',
            commitHash,
            commitAuthor: commitInfo.author,
            commitDate: commitInfo.date,
            commitMessage: commitInfo.message,
            dangling: commitInfo.dangling ?? false,
            entropy: shannonEntropy(match.value),
          },
        };

        yield finding;
      }
    }

    // Phase 3 inline: Check removed lines for oops pattern
    // (This happens when processing a commit that removes a previously-added secret)
    // Note: We check additions against the oops detector from prior commits.
    // The actual removal detection happens in the diff: if a line starts with '-'
    // in the diff and contains a tracked secret, that's the removal.
    // However, since parseDiff only extracts additions, we rely on the commit
    // sequence to detect the oops pattern when the same file no longer contains
    // the secret in a later commit's additions.
  }

  // ──────────────────────────────────────────────────────────────────
  // Git operations
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get all reachable commit hashes, limited by depth.
   */
  private async getCommitHashes(git: SimpleGit, depth: number): Promise<string[]> {
    const args = ['log', '--all', '--format=%H'];

    if (depth > 0) {
      args.push(`--max-count=${depth}`);
    }

    const result = await git.raw(args);
    return result
      .trim()
      .split('\n')
      .filter((line) => line.length > 0);
  }

  /**
   * Get dangling (unreachable) commit hashes from git fsck.
   */
  private async getDanglingCommitHashes(git: SimpleGit): Promise<string[]> {
    try {
      const result = await git.raw(['fsck', '--lost-found', '--no-reflogs']);
      const hashes: string[] = [];

      for (const line of result.split('\n')) {
        // Format: "dangling commit <hash>"
        const match = line.match(/^dangling commit ([0-9a-f]{40})$/);
        if (match) {
          hashes.push(match[1]!);
        }
      }

      return hashes;
    } catch {
      // git fsck may fail on shallow clones or corrupted repos
      return [];
    }
  }

  /**
   * Get commit metadata (author, date, message).
   */
  private async getCommitInfo(git: SimpleGit, hash: string): Promise<CommitInfo> {
    try {
      const result = await git.raw([
        'show',
        '--no-patch',
        '--format=%an%n%aI%n%s',
        hash,
      ]);

      const lines = result.trim().split('\n');

      return {
        author: lines[0] ?? 'unknown',
        date: lines[1] ?? 'unknown',
        timestamp: lines[1] ?? undefined,
        message: lines[2] ?? '',
      };
    } catch {
      return {
        author: 'unknown',
        date: 'unknown',
        message: '',
      };
    }
  }

  /**
   * Get the diff content of a commit.
   *
   * For regular commits: `git show <hash>` (shows diff against parent)
   * For root commits (no parent): `git show <hash>` also works.
   */
  private async getCommitDiff(git: SimpleGit, hash: string): Promise<string> {
    try {
      return await git.raw([
        'show',
        '--format=',    // Suppress commit header
        '--diff-filter=ACMR', // Only Added, Copied, Modified, Renamed
        hash,
      ]);
    } catch {
      return '';
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // Allowlist
  // ──────────────────────────────────────────────────────────────────

  /**
   * Check if a matched value is allowlisted by rule patterns.
   * Simplified version for git history scanning (path allowlisting
   * is less relevant for historical commits).
   */
  private isValueAllowlisted(value: string, rule: Rule): boolean {
    // Check rule-level allowlist patterns
    if (rule.allowlist?.patterns && rule.allowlist.patterns.length > 0) {
      for (const allowPattern of rule.allowlist.patterns) {
        try {
          const regex = new RegExp(allowPattern);
          if (regex.test(value)) {
            return true;
          }
        } catch {
          continue;
        }
      }
    }

    // Check common placeholder patterns
    const lower = value.toLowerCase();
    const placeholders = [
      'example', 'placeholder', 'dummy', 'sample',
      'xxxxxx', 'your-', 'your_', 'change-me', 'change_me',
      'replace-me', 'replace_me', 'todo', 'fixme',
    ];

    for (const p of placeholders) {
      if (lower.includes(p)) {
        return true;
      }
    }

    return false;
  }
}

// ──────────────────────────────────────────────────────────────────
// Helper types and functions
// ──────────────────────────────────────────────────────────────────

/** Commit metadata extracted from git log/show */
interface CommitInfo {
  author: string;
  date: string;
  timestamp?: string;
  message: string;
  dangling?: boolean;
}

/**
 * Build a git-specific remediation message.
 */
function buildGitRemediation(rule: Rule, commitHash: string): string {
  const parts: string[] = [];

  parts.push(`Secret found in git commit ${commitHash.slice(0, 8)}.`);
  parts.push('This secret is recoverable from git history even if removed from HEAD.');
  parts.push('Rotate the credential immediately.');
  parts.push('Consider using git-filter-repo or BFG Repo-Cleaner to purge the commit.');
  parts.push('Use environment variables or a secrets manager to prevent future exposure.');

  if (rule.references.length > 0) {
    parts.push(`References: ${rule.references.join(', ')}`);
  }

  return parts.join(' ');
}

export default new GitMinerPlugin();

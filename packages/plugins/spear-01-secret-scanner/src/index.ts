/**
 * SPEAR-01: Secret Scanner Plugin
 *
 * Scans source code for secret patterns using a multi-stage pipeline:
 *
 *   1. File Discovery   -- Walk directory tree (file-walker.ts)
 *   2. Aho-Corasick     -- O(n) keyword pre-filter to skip irrelevant files
 *   3. Regex Matching   -- Full pattern matching on candidate files (ReDoS-safe)
 *   4. Entropy Analysis -- Shannon entropy check for high-entropy secrets
 *   5. Allowlist        -- Suppress known test/example values
 *
 * Architecture:
 *   - Uses @wigtn/core AhoCorasick for fast keyword pre-filtering
 *   - Uses @wigtn/core RegexMatcher for ReDoS-protected pattern matching
 *   - Uses @wigtn/core shannonEntropy for entropy analysis
 *   - Uses @wigtn/rules-engine loadRules for YAML rule loading
 *   - Uses @wigtn/shared SecureSecret for safe secret masking
 *
 * The scan() method is an AsyncGenerator that yields Finding objects
 * as they are discovered, enabling streaming output and early termination.
 */

import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
  Rule,
} from '@wigtn/shared';
import { SecureSecret } from '@wigtn/shared';
import {
  AhoCorasick,
  RegexMatcher,
  shannonEntropy,
  loadSpearignore,
  createSpearignore,
} from '@wigtn/core';
import { loadRules } from '@wigtn/rules-engine';
import { walkFiles } from './file-walker.js';
import { isAllowlisted, isPathAllowlisted } from './allowlist.js';

/** Maximum file size to process (5 MB). Files larger than this are skipped. */
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

/**
 * SecretScannerPlugin -- Phase 1 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects secrets embedded in source code, configuration files, and
 * documentation using pattern matching and entropy analysis.
 */
export class SecretScannerPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'secret-scanner',
    name: 'Secret Scanner',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans source code for 800+ secret patterns using Aho-Corasick + Regex + Entropy analysis',
    severity: 'critical',
    tags: ['secret', 'detection', 'scanning'],
    references: ['CWE-798', 'CWE-312'],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read', 'git:read'],
    trustLevel: 'builtin',
  };

  /** Loaded and validated rules from YAML files */
  private rules: Rule[] = [];

  /** Aho-Corasick automaton built from all rule keywords */
  private ahoCorasick: AhoCorasick | null = null;

  /** Map from keyword -> set of rule IDs that declare that keyword */
  private keywordToRuleIds: Map<string, Set<string>> = new Map();

  /** Compiled regex matcher for all rules */
  private regexMatcher: RegexMatcher | null = null;

  /** Map from rule ID -> Rule for fast lookup */
  private ruleMap: Map<string, Rule> = new Map();

  /**
   * Setup: Load rules, build the Aho-Corasick automaton, compile regex patterns.
   *
   * Called once before scanning begins. All heavy initialization happens here
   * so that scan() can focus on file processing.
   */
  async setup(context: PluginContext): Promise<void> {
    const rulesDir = context.config.rulesDir;

    if (!rulesDir) {
      context.logger.warn('No rulesDir configured, secret-scanner will have no rules');
      return;
    }

    // Load rules using the rules-engine loader (validates YAML structure)
    context.logger.info('Loading secret detection rules', { rulesDir });
    this.rules = await loadRules(rulesDir, context.logger);

    // Filter to only secret-category rules (this plugin focuses on secrets)
    this.rules = this.rules.filter((r) => r.category === 'secret');

    if (this.rules.length === 0) {
      context.logger.warn('No secret rules loaded, scanner will produce no findings');
      return;
    }

    context.logger.info('Secret rules loaded', { count: this.rules.length });

    // Build rule lookup map
    this.ruleMap = new Map();
    for (const rule of this.rules) {
      this.ruleMap.set(rule.id, rule);
    }

    // Extract all keywords and build Aho-Corasick automaton
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
      context.logger.debug('Aho-Corasick automaton built', {
        keywordCount: allKeywords.length,
      });
    }

    // Compile regex patterns with ReDoS protection
    this.regexMatcher = new RegexMatcher(this.rules);
    context.logger.debug('Regex patterns compiled', {
      compiled: this.regexMatcher.compiledCount,
      rejected: this.regexMatcher.rejectedCount,
    });

    // Log rejected rules (unsafe regex patterns)
    const rejectedRules = this.regexMatcher.getRejectedRules();
    for (const [ruleId, reason] of rejectedRules) {
      context.logger.warn('Rule regex rejected', { ruleId, reason });
    }
  }

  /**
   * Scan: Walk files, apply multi-stage pipeline, yield findings.
   *
   * Pipeline per file:
   *   1. Read file content
   *   2. Aho-Corasick keyword pre-filter (skip files with no keyword hits)
   *   3. Regex matching on candidate rules only
   *   4. Entropy filter (for rules with entropy.enabled)
   *   5. Allowlist check (suppress known false positives)
   *   6. Yield Finding with SecureSecret.mask() for safe output
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    if (this.rules.length === 0 || !this.regexMatcher) {
      context.logger.warn('Secret scanner has no rules loaded, skipping scan');
      return;
    }

    const rootDir = resolve(target.path);

    // Load spearignore patterns. Merge target.exclude into ignore patterns.
    const spearignore = target.exclude && target.exclude.length > 0
      ? createSpearignore(target.exclude, true)
      : loadSpearignore(rootDir);

    let filesScanned = 0;
    let findingsCount = 0;

    context.logger.info('Starting secret scan', { rootDir });

    // Walk the file tree
    for await (const filePath of walkFiles(rootDir, spearignore, target)) {
      try {
        // Read file content
        const content = await readFileContent(filePath);
        if (content === null) {
          continue;
        }

        // Enforce max file size (content length check)
        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { filePath });
          continue;
        }

        filesScanned++;

        // Stage 2: Aho-Corasick keyword pre-filter
        let candidateRuleIds: string[] | undefined;

        if (this.ahoCorasick) {
          const keywordMatches = this.ahoCorasick.search(content);

          if (keywordMatches.length === 0) {
            // No keywords found in this file -- skip entirely
            continue;
          }

          // Determine which rules have matching keywords
          const matchedRuleIds = new Set<string>();
          for (const km of keywordMatches) {
            const ruleIds = this.keywordToRuleIds.get(km.keyword);
            if (ruleIds) {
              for (const ruleId of ruleIds) {
                matchedRuleIds.add(ruleId);
              }
            }
          }

          // Also include rules with no keywords (they run on every file)
          for (const rule of this.rules) {
            if (rule.detection.keywords.length === 0) {
              matchedRuleIds.add(rule.id);
            }
          }

          candidateRuleIds = [...matchedRuleIds];
          if (candidateRuleIds.length === 0) {
            continue;
          }
        }

        // Stage 3: Regex matching (only on candidate rules)
        const regexMatches = this.regexMatcher.match(content, candidateRuleIds);

        if (regexMatches.length === 0) {
          continue;
        }

        // Stage 4-5: Entropy filter + Allowlist + Finding construction
        const relativePath = relative(rootDir, filePath);

        for (const match of regexMatches) {
          const rule = this.ruleMap.get(match.ruleId);
          if (!rule) continue;

          // Check path allowlist
          if (isPathAllowlisted(relativePath, rule)) {
            continue;
          }

          // Check value allowlist
          if (isAllowlisted(match.value, rule)) {
            continue;
          }

          // Apply entropy filter if configured on the rule
          if (rule.detection.entropy?.enabled) {
            const threshold = rule.detection.entropy.threshold ?? 5.0;
            const entropy = shannonEntropy(match.value);

            if (entropy < threshold) {
              // Value does not meet entropy threshold -- likely a placeholder
              continue;
            }
          }

          // Construct the finding with masked secret value
          const secret = new SecureSecret(match.value);
          const maskedValue = secret.mask();
          secret.dispose(); // Zero out raw value from memory immediately

          const entropy = shannonEntropy(match.value);

          const finding: Finding = {
            ruleId: rule.id,
            severity: rule.severity,
            message: `${rule.name}: ${rule.description}`,
            file: relativePath,
            line: match.line,
            column: match.column,
            secretMasked: maskedValue,
            mitreTechniques: rule.mitre,
            remediation: buildRemediation(rule),
            metadata: {
              pluginId: this.metadata.id,
              category: rule.category,
              tags: rule.tags,
              entropy,
              valueLength: match.value.length,
            },
          };

          findingsCount++;
          yield finding;
        }
      } catch (err: unknown) {
        // Non-fatal: log the error and continue with the next file
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing file, skipping', {
          filePath,
          error: message,
        });
      }
    }

    context.logger.info('Secret scan complete', {
      filesScanned,
      findingsCount,
    });
  }

  /**
   * Teardown: Release resources.
   *
   * Clears the in-memory data structures used during scanning.
   */
  async teardown(_context: PluginContext): Promise<void> {
    this.rules = [];
    this.ahoCorasick = null;
    this.keywordToRuleIds.clear();
    this.regexMatcher = null;
    this.ruleMap.clear();
  }
}

/**
 * Read file content as UTF-8 string.
 *
 * Returns null on any error (permissions, encoding, etc.).
 * Consistent with readFileContent in @wigtn/core pipeline.ts.
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    return null;
  }
}

/**
 * Build a remediation message from a Rule's metadata.
 *
 * Consistent with buildRemediation in @wigtn/core pipeline.ts.
 */
function buildRemediation(rule: Rule): string {
  const parts: string[] = [];

  if (rule.category === 'secret') {
    parts.push('Rotate this credential immediately and remove it from source code.');
    parts.push('Use environment variables or a secrets manager instead.');
  } else if (rule.category === 'vulnerability') {
    parts.push('Review and fix the identified vulnerability.');
  } else if (rule.category === 'misconfiguration') {
    parts.push('Review and correct the configuration.');
  }

  if (rule.references.length > 0) {
    parts.push(`References: ${rule.references.join(', ')}`);
  }

  return parts.join(' ');
}

export default new SecretScannerPlugin();

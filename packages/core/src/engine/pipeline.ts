/**
 * Scan Pipeline - AsyncGenerator Streaming Architecture
 *
 * The scan pipeline processes files through a multi-stage filtering chain,
 * yielding Finding objects as they are discovered. This streaming approach
 * enables:
 *   - Memory-efficient processing of large codebases
 *   - Real-time progress reporting (findings appear as they're found)
 *   - Early termination support (caller can break out of the generator)
 *
 * Pipeline stages:
 *   1. File Discovery   - Walk directory tree, respect .spearignore
 *   2. Binary Filter     - Skip binary files (istextorbinary)
 *   3. Aho-Corasick      - Pre-filter: skip files with no keyword matches
 *   4. Regex Matching    - Full pattern matching on candidate files
 *   5. Entropy Filter    - Validate matches with Shannon entropy analysis
 *
 * Each stage reduces the work for subsequent stages, making the pipeline
 * efficient even with thousands of rules and large codebases.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, relative, join } from 'node:path';
import { isText } from 'istextorbinary';
import type { Ignore } from 'ignore';
import type { Rule, Finding, ScanTarget, ScanMode } from '@wigtn/shared';
import { AhoCorasick } from './aho-corasick.js';
import { RegexMatcher } from './regex-matcher.js';
import { shannonEntropy } from './entropy.js';
import { loadSpearignore } from '../spearignore.js';

/** Options for the scan pipeline */
export interface PipelineOptions {
  /** Scan mode: 'safe' (local only) or 'aggressive' (network access) */
  mode: ScanMode;
  /** Pre-loaded spearignore instance. If not provided, loads from target path. */
  spearignore?: Ignore;
  /** Maximum file size in bytes to process. Files larger than this are skipped. Default: 5MB */
  maxFileSizeBytes?: number;
  /** Callback for progress reporting */
  onFileProcessed?: (filePath: string, matched: boolean) => void;
  /** Callback for errors that don't stop the pipeline */
  onError?: (filePath: string, error: Error) => void;
}

/** Default maximum file size: 5 MB */
const DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024;

/** File encoding to use when reading text files */
const FILE_ENCODING = 'utf-8';

/**
 * Main scan pipeline. Yields Finding objects as secrets/vulnerabilities
 * are discovered in the target directory.
 *
 * @param target - The scan target (directory path and filters).
 * @param rules - Array of detection rules to apply.
 * @param options - Pipeline configuration options.
 * @yields Finding objects for each detected secret/vulnerability.
 *
 * @example
 * ```ts
 * for await (const finding of scanPipeline(target, rules, { mode: 'safe' })) {
 *   console.log(`Found ${finding.ruleId} in ${finding.file}:${finding.line}`);
 * }
 * ```
 */
export async function* scanPipeline(
  target: ScanTarget,
  rules: Rule[],
  options: PipelineOptions,
): AsyncGenerator<Finding> {
  if (rules.length === 0) {
    return;
  }

  const maxFileSize = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE;

  // --- Stage 0: Preparation ---

  // Load spearignore patterns
  const ig = options.spearignore ?? loadSpearignore(target.path);

  // Build Aho-Corasick automaton from all rule keywords
  const allKeywords = extractKeywords(rules);
  const ahoCorasick = allKeywords.length > 0 ? new AhoCorasick(allKeywords) : null;

  // Build keyword-to-rule mapping for efficient lookup
  const keywordToRuleIds = buildKeywordRuleMap(rules);

  // Compile regex matcher
  const regexMatcher = new RegexMatcher(rules);

  // Build rule lookup map
  const ruleMap = new Map<string, Rule>();
  for (const rule of rules) {
    ruleMap.set(rule.id, rule);
  }

  // --- Stage 1-5: Process files ---

  for await (const filePath of discoverFiles(target.path, ig, target)) {
    try {
      // Stage 2: Skip files that are too large
      const fileStats = await stat(filePath);
      if (fileStats.size > maxFileSize) {
        continue;
      }
      if (fileStats.size === 0) {
        continue;
      }

      // Stage 2: Skip binary files
      const isBinary = await checkBinary(filePath);
      if (isBinary) {
        continue;
      }

      // Read file content
      const content = await readFileContent(filePath);
      if (content === null || content.length === 0) {
        continue;
      }

      // Stage 3: Aho-Corasick pre-filter
      // If we have keywords, check if any appear in the file.
      // This is a fast O(n) check that eliminates most non-matching files.
      let candidateRuleIds: string[] | undefined;

      if (ahoCorasick) {
        const keywordMatches = ahoCorasick.search(content);

        if (keywordMatches.length === 0) {
          // No keywords found - skip this file entirely
          options.onFileProcessed?.(filePath, false);
          continue;
        }

        // Collect the set of rules whose keywords matched
        const matchedRuleIds = new Set<string>();
        for (const km of keywordMatches) {
          const ruleIds = keywordToRuleIds.get(km.keyword);
          if (ruleIds) {
            for (const ruleId of ruleIds) {
              matchedRuleIds.add(ruleId);
            }
          }
        }

        // Also include rules with no keywords (they always run)
        for (const rule of rules) {
          if (rule.detection.keywords.length === 0) {
            matchedRuleIds.add(rule.id);
          }
        }

        candidateRuleIds = [...matchedRuleIds];
        if (candidateRuleIds.length === 0) {
          options.onFileProcessed?.(filePath, false);
          continue;
        }
      }

      // Stage 4: Regex matching
      const regexMatches = regexMatcher.match(content, candidateRuleIds);

      if (regexMatches.length === 0) {
        options.onFileProcessed?.(filePath, false);
        continue;
      }

      // Stage 5: Entropy filter + Finding construction
      const relativePath = relative(target.path, filePath);
      let hasFindings = false;

      for (const match of regexMatches) {
        const rule = ruleMap.get(match.ruleId);
        if (!rule) continue;

        // Check path allowlist
        if (isPathAllowlisted(relativePath, rule)) {
          continue;
        }

        // Apply entropy filter if configured on the rule
        if (rule.detection.entropy?.enabled) {
          const threshold = rule.detection.entropy.threshold;
          const entropy = shannonEntropy(match.value);
          const effectiveThreshold = threshold ?? 5.0; // ENTROPY_THRESHOLDS.SUSPICIOUS

          if (entropy < effectiveThreshold) {
            // Match doesn't meet entropy threshold - skip
            continue;
          }
        }

        hasFindings = true;

        const finding: Finding = {
          ruleId: rule.id,
          severity: rule.severity,
          message: `${rule.name}: ${rule.description}`,
          file: relativePath,
          line: match.line,
          column: match.column,
          secretMasked: maskSecret(match.value),
          mitreTechniques: rule.mitre,
          remediation: buildRemediation(rule),
          metadata: {
            category: rule.category,
            tags: rule.tags,
            matchedValue: match.value.length > 100
              ? match.value.slice(0, 100) + '...'
              : match.value,
            entropy: shannonEntropy(match.value),
          },
        };

        yield finding;
      }

      options.onFileProcessed?.(filePath, hasFindings);
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      options.onError?.(filePath, error);
    }
  }
}

/**
 * Async generator that walks a directory tree, yielding file paths.
 *
 * Respects the spearignore patterns and ScanTarget include/exclude filters.
 * Walks depth-first to minimize memory usage.
 *
 * @param rootDir - The root directory to walk.
 * @param ig - The spearignore instance for filtering.
 * @param target - The scan target with optional include/exclude patterns.
 * @yields Absolute file paths that pass all filters.
 */
export async function* discoverFiles(
  rootDir: string,
  ig: Ignore,
  target: ScanTarget,
): AsyncGenerator<string> {
  const stack: string[] = [rootDir];

  while (stack.length > 0) {
    const currentDir = stack.pop()!;

    let entries: string[];
    try {
      entries = await readdir(currentDir);
    } catch {
      // Permission denied or directory doesn't exist; skip silently
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relativePath = relative(rootDir, fullPath);

      // Check spearignore
      if (ig.ignores(relativePath)) {
        continue;
      }

      let entryStat;
      try {
        entryStat = await stat(fullPath);
      } catch {
        // Broken symlink or permission denied; skip
        continue;
      }

      if (entryStat.isDirectory()) {
        // Check if directory is ignored (with trailing slash convention)
        if (ig.ignores(relativePath + '/')) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        // Apply include filter (if specified, file must match at least one)
        if (target.include && target.include.length > 0) {
          const matchesInclude = target.include.some((pattern) =>
            matchGlob(relativePath, pattern),
          );
          if (!matchesInclude) {
            continue;
          }
        }

        // Apply exclude filter
        if (target.exclude && target.exclude.length > 0) {
          const matchesExclude = target.exclude.some((pattern) =>
            matchGlob(relativePath, pattern),
          );
          if (matchesExclude) {
            continue;
          }
        }

        yield fullPath;
      }
    }
  }
}

/**
 * Read file content as UTF-8 text.
 *
 * Returns null if the file cannot be read (permissions, encoding issues, etc.).
 *
 * @param filePath - Absolute path to the file.
 * @returns The file content as a string, or null on error.
 */
export async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    // File might be unreadable (permissions, encoding, etc.)
    return null;
  }
}

/**
 * Check if a file is binary using the istextorbinary package.
 *
 * Reads the first 512 bytes of the file as a sample for detection.
 *
 * @param filePath - Absolute path to the file.
 * @returns true if the file is binary.
 */
async function checkBinary(filePath: string): Promise<boolean> {
  try {
    // Read a sample of the file for binary detection
    const { open } = await import('node:fs/promises');
    const fileHandle = await open(filePath, 'r');
    try {
      const buffer = Buffer.alloc(512);
      const { bytesRead } = await fileHandle.read(buffer, 0, 512, 0);
      if (bytesRead === 0) {
        return false; // Empty file is not binary
      }
      const sample = buffer.subarray(0, bytesRead);
      return !isText(filePath, sample);
    } finally {
      await fileHandle.close();
    }
  } catch {
    // If we can't read the file, treat it as binary (skip it)
    return true;
  }
}

/**
 * Extract all unique keywords from the rule set for Aho-Corasick.
 */
function extractKeywords(rules: Rule[]): string[] {
  const keywordSet = new Set<string>();
  for (const rule of rules) {
    for (const keyword of rule.detection.keywords) {
      if (keyword.length > 0) {
        keywordSet.add(keyword);
      }
    }
  }
  return [...keywordSet];
}

/**
 * Build a map from keyword -> set of rule IDs that use that keyword.
 * This allows us to quickly determine which rules are candidates
 * after the Aho-Corasick pre-filter stage.
 */
function buildKeywordRuleMap(rules: Rule[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const rule of rules) {
    for (const keyword of rule.detection.keywords) {
      if (keyword.length === 0) continue;
      let ruleIds = map.get(keyword);
      if (!ruleIds) {
        ruleIds = new Set();
        map.set(keyword, ruleIds);
      }
      ruleIds.add(rule.id);
    }
  }
  return map;
}

/**
 * Check if a file path is allowlisted by a rule's path allowlist.
 */
function isPathAllowlisted(relativePath: string, rule: Rule): boolean {
  if (!rule.allowlist?.paths || rule.allowlist.paths.length === 0) {
    return false;
  }
  return rule.allowlist.paths.some((pattern) => matchGlob(relativePath, pattern));
}

/**
 * Simple glob matching for include/exclude/allowlist patterns.
 *
 * Supports:
 * - '*' matches any sequence of non-separator characters
 * - '**' matches any sequence including separators
 * - '?' matches exactly one character
 * - Direct string equality
 *
 * This is intentionally simple. For full gitignore-style matching,
 * use the `ignore` package (which is used for .spearignore).
 */
function matchGlob(filepath: string, pattern: string): boolean {
  // Direct match
  if (filepath === pattern) return true;

  // Convert glob to regex
  let regexStr = '^';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i]!;

    if (ch === '*') {
      if (i + 1 < pattern.length && pattern[i + 1] === '*') {
        // ** matches everything including path separators
        regexStr += '.*';
        i += 2;
        // Skip trailing slash after **
        if (i < pattern.length && pattern[i] === '/') {
          i++;
        }
        continue;
      }
      // * matches anything except path separators
      regexStr += '[^/]*';
    } else if (ch === '?') {
      regexStr += '[^/]';
    } else if (ch === '.') {
      regexStr += '\\.';
    } else if (ch === '(' || ch === ')' || ch === '[' || ch === ']' || ch === '{' || ch === '}' || ch === '+' || ch === '^' || ch === '$' || ch === '|' || ch === '\\') {
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
    // Invalid pattern; fall back to string includes
    return filepath.includes(pattern);
  }
}

/**
 * Mask a secret value for safe display.
 *
 * Shows the first 4 and last 4 characters for long strings,
 * or fully masks short strings.
 */
function maskSecret(value: string): string {
  const len = value.length;
  if (len >= 12) {
    return value.slice(0, 4) + '*'.repeat(Math.min(len - 8, 20)) + value.slice(-4);
  }
  if (len >= 8) {
    return value.slice(0, 2) + '*'.repeat(len - 4) + value.slice(-2);
  }
  if (len >= 4) {
    return value.slice(0, 2) + '****';
  }
  return '****';
}

/**
 * Build a remediation string from a rule's references.
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

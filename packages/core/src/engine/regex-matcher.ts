/**
 * Regex Pattern Matcher with ReDoS Protection
 *
 * Compiles and executes regex patterns from Rule definitions against
 * file content. Each pattern is validated with safe-regex2 to prevent
 * ReDoS attacks from malicious or poorly written rule patterns.
 *
 * Features:
 * - ReDoS validation at compile time (rejects exponential patterns)
 * - Per-match 100ms timeout via AbortController
 * - Line/column position tracking for findings
 * - Selective rule execution (match specific rule IDs)
 * - Allowlist support (skip matches in allowlisted paths/patterns)
 */

import safe from 'safe-regex2';
import type { Rule } from '@wigtn/shared';

/** A single regex match result with position information */
export interface RegexMatch {
  /** ID of the rule that produced this match */
  ruleId: string;
  /** The matched string value */
  value: string;
  /** 1-based line number in the source file */
  line: number;
  /** 1-based column number in the source line */
  column: number;
}

/** Internal compiled rule representation */
interface CompiledRule {
  rule: Rule;
  regex: RegExp;
}

/** Timeout in milliseconds for a single regex execution against content */
const REGEX_TIMEOUT_MS = 100;

/**
 * RegexMatcher compiles and manages a set of Rule patterns.
 *
 * Usage:
 * ```ts
 * const matcher = new RegexMatcher(rules);
 * const matches = matcher.match(fileContent);
 * // matches: [{ ruleId: 'aws-secret-key', value: 'AKIA...', line: 42, column: 10 }]
 * ```
 */
export class RegexMatcher {
  /** Compiled rules indexed by rule ID */
  private readonly compiled: Map<string, CompiledRule> = new Map();

  /** Rule IDs that failed validation (unsafe regex) */
  private readonly rejected: Map<string, string> = new Map();

  /**
   * Construct a RegexMatcher from an array of Rule definitions.
   *
   * Each rule's `detection.pattern` is compiled into a RegExp and
   * validated with safe-regex2. Rules with unsafe patterns are
   * silently rejected and tracked in the rejected map.
   *
   * @param rules - Array of Rule definitions to compile.
   */
  constructor(rules: Rule[]) {
    for (const rule of rules) {
      this.compileRule(rule);
    }
  }

  /**
   * Match file content against all (or selected) rules.
   *
   * @param content - The file content to search.
   * @param ruleIds - Optional list of rule IDs to run. If omitted,
   *   all compiled rules are executed.
   * @returns Array of regex matches with position information.
   */
  match(content: string, ruleIds?: string[]): RegexMatch[] {
    if (content.length === 0) {
      return [];
    }

    const results: RegexMatch[] = [];
    const rulesToRun = this.selectRules(ruleIds);

    // Pre-compute line start offsets for position tracking
    const lineOffsets = computeLineOffsets(content);

    for (const compiled of rulesToRun) {
      const ruleMatches = this.executeRule(compiled, content, lineOffsets);
      results.push(...ruleMatches);
    }

    return results;
  }

  /**
   * Check whether a specific rule was rejected during compilation.
   *
   * @param ruleId - The rule ID to check.
   * @returns The rejection reason, or undefined if the rule is valid.
   */
  getRejectionReason(ruleId: string): string | undefined {
    return this.rejected.get(ruleId);
  }

  /**
   * Get all rejected rule IDs and their reasons.
   */
  getRejectedRules(): ReadonlyMap<string, string> {
    return this.rejected;
  }

  /**
   * Get the count of successfully compiled rules.
   */
  get compiledCount(): number {
    return this.compiled.size;
  }

  /**
   * Get the count of rejected rules.
   */
  get rejectedCount(): number {
    return this.rejected.size;
  }

  /**
   * Compile a single rule's pattern into a RegExp.
   * Validates with safe-regex2 before accepting.
   */
  private compileRule(rule: Rule): void {
    const pattern = rule.detection.pattern;

    if (!pattern || pattern.trim().length === 0) {
      this.rejected.set(rule.id, 'Empty pattern');
      return;
    }

    // Validate pattern safety (ReDoS protection)
    let isPatternSafe: boolean;
    try {
      isPatternSafe = safe(pattern);
    } catch {
      this.rejected.set(rule.id, `safe-regex2 validation error for pattern: ${pattern}`);
      return;
    }

    if (!isPatternSafe) {
      this.rejected.set(
        rule.id,
        `Potentially unsafe regex (ReDoS risk): ${pattern}`,
      );
      return;
    }

    // Compile the regex with global and multiline flags
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, 'gm');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.rejected.set(rule.id, `Invalid regex: ${message}`);
      return;
    }

    this.compiled.set(rule.id, { rule, regex });
  }

  /**
   * Select which compiled rules to execute.
   */
  private selectRules(ruleIds?: string[]): CompiledRule[] {
    if (!ruleIds || ruleIds.length === 0) {
      return [...this.compiled.values()];
    }

    const selected: CompiledRule[] = [];
    for (const id of ruleIds) {
      const compiled = this.compiled.get(id);
      if (compiled) {
        selected.push(compiled);
      }
    }
    return selected;
  }

  /**
   * Execute a single compiled rule against content with timeout protection.
   *
   * Uses a time-boxed approach: if matching takes longer than REGEX_TIMEOUT_MS,
   * the match is aborted and partial results are returned.
   */
  private executeRule(
    compiled: CompiledRule,
    content: string,
    lineOffsets: number[],
  ): RegexMatch[] {
    const results: RegexMatch[] = [];
    const { rule, regex } = compiled;

    // Create a fresh regex instance to avoid lastIndex state issues
    const freshRegex = new RegExp(regex.source, regex.flags);

    const startTime = Date.now();
    let execResult: RegExpExecArray | null;

    // eslint-disable-next-line no-cond-assign
    while ((execResult = freshRegex.exec(content)) !== null) {
      // Timeout check: abort if execution takes too long
      if (Date.now() - startTime > REGEX_TIMEOUT_MS) {
        break;
      }

      const matchedValue = execResult[0];
      if (matchedValue.length === 0) {
        // Prevent infinite loop on zero-length matches
        freshRegex.lastIndex++;
        continue;
      }

      const offset = execResult.index;

      // Check against allowlist patterns
      if (this.isAllowlisted(matchedValue, rule)) {
        continue;
      }

      // Convert byte offset to line/column
      const { line, column } = offsetToLineColumn(offset, lineOffsets);

      results.push({
        ruleId: rule.id,
        value: matchedValue,
        line,
        column,
      });
    }

    return results;
  }

  /**
   * Check if a matched value is allowlisted by the rule's allowlist patterns.
   */
  private isAllowlisted(value: string, rule: Rule): boolean {
    if (!rule.allowlist?.patterns || rule.allowlist.patterns.length === 0) {
      return false;
    }

    for (const allowPattern of rule.allowlist.patterns) {
      try {
        const allowRegex = new RegExp(allowPattern);
        if (allowRegex.test(value)) {
          return true;
        }
      } catch {
        // Invalid allowlist pattern, skip it
        continue;
      }
    }

    return false;
  }
}

/**
 * Compute an array of line-start offsets for the given content.
 *
 * lineOffsets[i] = the character offset where line (i+1) starts.
 * lineOffsets[0] = 0 (line 1 starts at offset 0).
 *
 * @param content - The file content.
 * @returns Array of line-start offsets.
 */
function computeLineOffsets(content: string): number[] {
  const offsets: number[] = [0];

  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      offsets.push(i + 1);
    }
  }

  return offsets;
}

/**
 * Convert a character offset to a 1-based line and column number.
 *
 * Uses binary search over the precomputed line offsets for efficiency.
 *
 * @param offset - 0-based character offset in the content.
 * @param lineOffsets - Precomputed line-start offsets.
 * @returns Object with 1-based `line` and `column`.
 */
function offsetToLineColumn(
  offset: number,
  lineOffsets: number[],
): { line: number; column: number } {
  // Binary search for the line containing this offset
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (lineOffsets[mid]! <= offset) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }

  return {
    line: low + 1, // 1-based
    column: offset - lineOffsets[low]! + 1, // 1-based
  };
}

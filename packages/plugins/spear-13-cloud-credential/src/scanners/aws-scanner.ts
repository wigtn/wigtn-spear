/**
 * SPEAR-13: AWS Credential Scanner
 *
 * Scans file content for AWS credential patterns including:
 *   - AKIA / ASIA access keys
 *   - Secret access keys and session tokens
 *   - IAM role ARNs and assumed role chains
 *   - IMDS v1/v2 access URLs
 *   - AWS credential file references
 *   - Environment variable exposure
 *
 * Also performs IAM role chain analysis on discovered ARNs to map
 * the assumed-role trust graph.
 *
 * This scanner applies both generic and AWS-specific patterns from
 * patterns.ts, consistent with the scanner pattern in spear-10.
 */

import type { Finding } from '@wigtn/shared';
import type { CredentialPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Pattern Selection ──────────────────────────────────────────

/**
 * All patterns applicable to AWS credential scanning.
 * Includes AWS-specific patterns plus generic patterns that can
 * detect cross-cloud credentials (private keys, IMDS, env vars).
 */
const AWS_PATTERNS: readonly CredentialPattern[] = ALL_PATTERNS.filter(
  (p) => p.provider === 'aws' || p.provider === 'generic',
);

// ─── IAM Role Chain Types ───────────────────────────────────────

export interface IAMRoleChainEntry {
  arn: string;
  type: 'user' | 'role' | 'assumed-role' | 'sts-identity';
  accountId?: string;
  roleName?: string;
  line?: number;
}

// ─── Scan Function ──────────────────────────────────────────────

/**
 * Scan file content against all AWS-applicable credential patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanAWSContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of AWS_PATTERNS) {
    // Test against full content first for multi-line patterns
    if (pattern.pattern.test(content)) {
      // Reset regex lastIndex for stateless matching
      pattern.pattern.lastIndex = 0;

      // Find the specific line(s) that match
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          pattern.pattern.lastIndex = 0;
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[AWS] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              provider: pattern.provider,
              category: pattern.category,
              scanner: 'aws',
              patternName: pattern.name,
            },
          };
        }
      }

      // If the pattern matched full content but no individual line, report on line 1
      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[AWS] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            provider: pattern.provider,
            category: pattern.category,
            scanner: 'aws',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── IAM Role Chain Extraction ──────────────────────────────────

/**
 * Extract IAM role chain entries from file content.
 *
 * Parses ARN patterns to build a graph of IAM identities referenced
 * in the file. This supports the IAM mapper module for role chain
 * analysis.
 *
 * @param content - The file content to analyze.
 * @returns Array of IAM role chain entries found.
 */
export function extractIAMRoleChain(content: string): IAMRoleChainEntry[] {
  const entries: IAMRoleChainEntry[] = [];
  const lines = content.split('\n');

  const arnPatterns: Array<{
    regex: RegExp;
    type: IAMRoleChainEntry['type'];
  }> = [
    {
      regex: /arn:aws:sts::(\d{12}):assumed-role\/([A-Za-z0-9_+=,.@\/-]+)/g,
      type: 'assumed-role',
    },
    {
      regex: /arn:aws:iam::(\d{12}):role\/([A-Za-z0-9_+=,.@\/-]+)/g,
      type: 'role',
    },
    {
      regex: /arn:aws:iam::(\d{12}):user\/([A-Za-z0-9_+=,.@\/-]+)/g,
      type: 'user',
    },
  ];

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;

    for (const { regex, type } of arnPatterns) {
      // Reset regex for each line
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(line)) !== null) {
        entries.push({
          arn: match[0],
          type,
          accountId: match[1],
          roleName: match[2],
          line: lineIndex + 1,
        });
      }
    }
  }

  return entries;
}

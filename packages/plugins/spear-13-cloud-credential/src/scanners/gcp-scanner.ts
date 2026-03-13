/**
 * SPEAR-13: GCP Credential Scanner
 *
 * Scans file content for Google Cloud Platform credential patterns including:
 *   - Service account JSON key files (private_key, client_email)
 *   - OAuth 2.0 access tokens (ya29.*)
 *   - Refresh tokens
 *   - API keys (AIza*)
 *   - Application Default Credentials (ADC) file paths
 *   - Compute Engine metadata service URLs
 *   - Service account impersonation chains
 *
 * This scanner applies both GCP-specific and generic patterns from
 * patterns.ts, consistent with the scanner pattern in spear-10.
 */

import type { Finding } from '@wigtn/shared';
import type { CredentialPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Pattern Selection ──────────────────────────────────────────

/**
 * All patterns applicable to GCP credential scanning.
 * Includes GCP-specific patterns plus generic patterns that can
 * detect cross-cloud credentials (private keys, IMDS, env vars).
 */
const GCP_PATTERNS: readonly CredentialPattern[] = ALL_PATTERNS.filter(
  (p) => p.provider === 'gcp' || p.provider === 'generic',
);

// ─── GCP Service Account Types ──────────────────────────────────

export interface GCPServiceAccountRef {
  email: string;
  projectId?: string;
  hasPrivateKey: boolean;
  isImpersonation: boolean;
  line?: number;
}

// ─── Scan Function ──────────────────────────────────────────────

/**
 * Scan file content against all GCP-applicable credential patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanGCPContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of GCP_PATTERNS) {
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
            message: `[GCP] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              provider: pattern.provider,
              category: pattern.category,
              scanner: 'gcp',
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
          message: `[GCP] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            provider: pattern.provider,
            category: pattern.category,
            scanner: 'gcp',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── Service Account Extraction ─────────────────────────────────

/**
 * Extract GCP service account references from file content.
 *
 * Identifies service account emails and impersonation chains for
 * the IAM mapper module.
 *
 * @param content - The file content to analyze.
 * @returns Array of GCP service account references found.
 */
export function extractServiceAccountRefs(content: string): GCPServiceAccountRef[] {
  const refs: GCPServiceAccountRef[] = [];
  const lines = content.split('\n');

  const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)/g;
  const projectIdRegex = /"project_id"\s*:\s*"([a-z][a-z0-9-]{4,28}[a-z0-9])"/;
  const hasPrivateKey = /-----BEGIN (?:RSA )?PRIVATE KEY-----/.test(content)
    || /"private_key"\s*:/.test(content);
  const projectIdMatch = projectIdRegex.exec(content);
  const projectId = projectIdMatch?.[1];

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;
    emailRegex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = emailRegex.exec(line)) !== null) {
      const email = match[1]!;
      const isImpersonation = /(?:impersonate|source_service_account|target_service_account)/i
        .test(line);

      refs.push({
        email,
        projectId,
        hasPrivateKey,
        isImpersonation,
        line: lineIndex + 1,
      });
    }
  }

  return refs;
}

/**
 * SPEAR-13: IMDS / Metadata Service Scanner
 *
 * Detects Instance Metadata Service (IMDS) access patterns across all
 * cloud providers. The metadata service is a common SSRF and credential
 * theft target:
 *
 *   AWS:   http://169.254.169.254/latest/meta-data/
 *          http://[fd00:ec2::254]/latest/meta-data/
 *   GCP:   http://metadata.google.internal/computeMetadata/v1/
 *          http://169.254.169.254/computeMetadata/v1/
 *   Azure: http://169.254.169.254/metadata/instance
 *          http://169.254.169.254/metadata/identity/oauth2/token
 *
 * This scanner operates as a focused cross-cloud detector that combines
 * metadata service patterns from all providers. It is run independently
 * of the provider-specific scanners to ensure complete coverage.
 *
 * MITRE ATT&CK:
 *   T1552     -- Unsecured Credentials
 *   T1078.004 -- Valid Accounts: Cloud Accounts
 *   T1098     -- Account Manipulation
 */

import type { Finding } from '@wigtn/shared';
import type { CredentialPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Pattern Selection ──────────────────────────────────────────

/**
 * All patterns specifically targeting metadata service access.
 * Filtered from ALL_PATTERNS by the 'metadata_service' category.
 */
const IMDS_PATTERNS: readonly CredentialPattern[] = ALL_PATTERNS.filter(
  (p) => p.category === 'metadata_service',
);

// ─── IMDS Detection Types ───────────────────────────────────────

export interface IMDSAccessPoint {
  provider: 'aws' | 'gcp' | 'azure' | 'unknown';
  url: string;
  type: 'credential-fetch' | 'metadata-read' | 'identity-token' | 'generic';
  line?: number;
}

// ─── Scan Function ──────────────────────────────────────────────

/**
 * Scan file content for IMDS / metadata service access patterns.
 *
 * This scanner focuses exclusively on metadata service interactions
 * to provide a consolidated cross-cloud IMDS detection layer.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected IMDS access pattern.
 */
export function* scanIMDSContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of IMDS_PATTERNS) {
    if (pattern.pattern.test(content)) {
      pattern.pattern.lastIndex = 0;

      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          pattern.pattern.lastIndex = 0;
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[IMDS] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              provider: pattern.provider,
              category: 'metadata_service',
              scanner: 'imds',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[IMDS] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            provider: pattern.provider,
            category: 'metadata_service',
            scanner: 'imds',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── IMDS Access Point Extraction ───────────────────────────────

/**
 * Extract IMDS access points from file content.
 *
 * Identifies the specific metadata URLs being accessed and classifies
 * them by cloud provider and access type (credential vs. metadata).
 *
 * @param content - The file content to analyze.
 * @returns Array of IMDS access points found.
 */
export function extractIMDSAccessPoints(content: string): IMDSAccessPoint[] {
  const accessPoints: IMDSAccessPoint[] = [];
  const lines = content.split('\n');

  const imdsPatterns: Array<{
    regex: RegExp;
    provider: IMDSAccessPoint['provider'];
    type: IMDSAccessPoint['type'];
  }> = [
    // AWS credential fetch
    {
      regex: /https?:\/\/169\.254\.169\.254\/latest\/meta-data\/iam\/security-credentials/g,
      provider: 'aws',
      type: 'credential-fetch',
    },
    // AWS metadata read
    {
      regex: /https?:\/\/169\.254\.169\.254\/latest\/(?:meta-data|user-data|dynamic)/g,
      provider: 'aws',
      type: 'metadata-read',
    },
    // AWS IMDSv2 token
    {
      regex: /https?:\/\/169\.254\.169\.254\/latest\/api\/token/g,
      provider: 'aws',
      type: 'identity-token',
    },
    // AWS IPv6 IMDS
    {
      regex: /https?:\/\/\[?fd00:ec2::254\]?\//g,
      provider: 'aws',
      type: 'metadata-read',
    },
    // GCP metadata
    {
      regex: /https?:\/\/metadata\.google\.internal\/computeMetadata\/v1/g,
      provider: 'gcp',
      type: 'metadata-read',
    },
    // GCP service account token via metadata
    {
      regex: /metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts/g,
      provider: 'gcp',
      type: 'credential-fetch',
    },
    // Azure identity token
    {
      regex: /169\.254\.169\.254\/metadata\/identity\/oauth2\/token/g,
      provider: 'azure',
      type: 'identity-token',
    },
    // Azure instance metadata
    {
      regex: /169\.254\.169\.254\/metadata\/instance/g,
      provider: 'azure',
      type: 'metadata-read',
    },
    // Generic 169.254.169.254 (fallback)
    {
      regex: /https?:\/\/169\.254\.169\.254(?!\/(?:latest|computeMetadata|metadata))/g,
      provider: 'unknown',
      type: 'generic',
    },
  ];

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;

    for (const { regex, provider, type } of imdsPatterns) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(line)) !== null) {
        accessPoints.push({
          provider,
          url: match[0],
          type,
          line: lineIndex + 1,
        });
      }
    }
  }

  return accessPoints;
}

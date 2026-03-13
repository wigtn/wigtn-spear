/**
 * SARIF 2.1.0 Reporter for WIGTN-SPEAR
 *
 * Generates Static Analysis Results Interchange Format (SARIF) v2.1.0
 * compliant output per PRD Section 5.2.
 *
 * SARIF is the standard format consumed by GitHub Code Scanning,
 * Azure DevOps, and other CI/CD security dashboards.
 *
 * Key design decisions:
 *   - partialFingerprints based on ruleId + file + line for deduplication
 *   - Severity mapping: critical/high -> error, medium -> warning, low/info -> note
 *   - Rules extracted from unique ruleIds across findings
 *   - CVSS score mapped to security-severity property when available
 */

import type {
  Finding,
  Severity,
  SarifLog,
  SarifRun,
  SarifRule,
  SarifResult,
} from '@wigtn/shared';
import { SPEAR_VERSION, SPEAR_NAME } from '@wigtn/shared';
import { createHash } from 'node:crypto';

// ─── Types ────────────────────────────────────────────────

export interface ScanInfo {
  /** Module that executed the scan, e.g. 'secret-scanner' */
  module: string;
  /** Version of the module or tool */
  version?: string;
  /** Filesystem path or URI of the scan target */
  target: string;
}

// ─── Severity Mapping ─────────────────────────────────────

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/**
 * Map CVSS scores to SARIF security-severity strings.
 * When no CVSS is available, derive from the discrete severity level.
 */
const SEVERITY_TO_SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.0',
  high: '7.0',
  medium: '4.0',
  low: '2.0',
  info: '0.0',
};

// ─── SARIFReporter ────────────────────────────────────────

export class SARIFReporter {
  /**
   * Generate a complete SARIF 2.1.0 log from an array of findings.
   *
   * The generated document contains a single run with:
   *   - tool.driver populated with SPEAR metadata and extracted rules
   *   - results mapped from each Finding with physical locations
   *   - partialFingerprints for cross-run deduplication
   *
   * @param findings - Array of findings from a completed scan
   * @param scanInfo - Metadata about the scan (module, version, target)
   * @returns A valid SARIF 2.1.0 JSON object
   */
  generate(findings: Finding[], scanInfo: ScanInfo): SarifLog {
    const rules = this.extractRules(findings);
    const ruleIndex = new Map<string, number>();
    rules.forEach((rule, idx) => ruleIndex.set(rule.id, idx));

    const results = this.buildResults(findings, ruleIndex);

    const run: SarifRun = {
      tool: {
        driver: {
          name: SPEAR_NAME,
          version: scanInfo.version ?? SPEAR_VERSION,
          informationUri: 'https://github.com/wigtn/wigtn-spear',
          rules,
        },
      },
      results,
    };

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [run],
    };
  }

  /**
   * Generate SARIF and return as a formatted JSON string.
   */
  stringify(findings: Finding[], scanInfo: ScanInfo, indent = 2): string {
    const log = this.generate(findings, scanInfo);
    return JSON.stringify(log, null, indent);
  }

  // ─── Private Helpers ──────────────────────────────────────

  /**
   * Extract unique SARIF rule definitions from the findings.
   *
   * Each unique ruleId in the findings array produces one SarifRule entry.
   * The first finding for each ruleId is used to populate the rule metadata.
   */
  private extractRules(findings: Finding[]): SarifRule[] {
    const seen = new Map<string, Finding>();

    for (const finding of findings) {
      if (!seen.has(finding.ruleId)) {
        seen.set(finding.ruleId, finding);
      }
    }

    const rules: SarifRule[] = [];

    for (const [ruleId, finding] of seen) {
      const category = (finding.metadata?.category as string) ?? 'security';
      const tags = (finding.metadata?.tags as string[]) ?? [];
      const securitySeverity = finding.cvss != null
        ? finding.cvss.toFixed(1)
        : SEVERITY_TO_SECURITY_SEVERITY[finding.severity];

      rules.push({
        id: ruleId,
        name: ruleId,
        shortDescription: {
          text: finding.message,
        },
        fullDescription: {
          text: finding.remediation ?? finding.message,
        },
        help: {
          text: finding.remediation ?? `Review and address ${ruleId} findings.`,
        },
        properties: {
          'security-severity': securitySeverity,
          tags: [category, ...tags],
        },
      });
    }

    return rules;
  }

  /**
   * Build SARIF result entries from findings.
   *
   * Each finding maps to one SarifResult with:
   *   - ruleId and ruleIndex reference
   *   - SARIF level derived from severity
   *   - Physical location (file + line/column)
   *   - Partial fingerprints for deduplication across runs
   */
  private buildResults(
    findings: Finding[],
    ruleIndex: Map<string, number>,
  ): SarifResult[] {
    return findings.map((finding) => {
      const level = SEVERITY_TO_SARIF_LEVEL[finding.severity];
      const filePath = finding.file ?? 'unknown';
      const line = finding.line ?? 1;
      const column = finding.column;

      // Build the message text
      let messageText = finding.message;
      if (finding.secretMasked) {
        messageText += ` [${finding.secretMasked}]`;
      }

      // Build physical location
      const region: { startLine: number; startColumn?: number } = {
        startLine: line,
      };
      if (column != null && column > 0) {
        region.startColumn = column;
      }

      // Build partial fingerprints for deduplication.
      // Uses a SHA-256 hash of ruleId + file + line so the same finding
      // in the same location is identified as the same result across runs.
      const fingerprintSource = `${finding.ruleId}:${filePath}:${line}`;
      const fingerprint = createHash('sha256')
        .update(fingerprintSource)
        .digest('hex')
        .slice(0, 32);

      const result: SarifResult = {
        ruleId: finding.ruleId,
        level,
        message: { text: messageText },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: filePath },
              region,
            },
          },
        ],
        partialFingerprints: {
          'primaryLocationLineHash': fingerprint,
        },
      };

      return result;
    });
  }
}

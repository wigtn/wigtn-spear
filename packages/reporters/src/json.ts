/**
 * JSON Reporter for WIGTN-SPEAR
 *
 * Generates a structured JSON report suitable for programmatic consumption
 * by CI/CD pipelines, dashboards, and downstream tooling.
 *
 * The SpearReport format includes:
 *   - Summary counts by severity
 *   - Scan metadata (module, target, mode, duration)
 *   - Full findings array with all detail
 *   - Tool version information
 */

import type { Finding, Severity, ScanMode } from '@wigtn/shared';
import { SPEAR_VERSION, SPEAR_NAME, SEVERITY_ORDER } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────

export interface ScanInfo {
  /** Module that executed the scan, e.g. 'secret-scanner' */
  module: string;
  /** Version of the module or tool */
  version?: string;
  /** Filesystem path or URI of the scan target */
  target: string;
  /** Scan mode: safe or aggressive */
  mode?: ScanMode;
  /** Scan duration in milliseconds */
  durationMs?: number;
  /** Scan start time (ISO-8601) */
  startedAt?: string;
  /** Scan completion time (ISO-8601) */
  completedAt?: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface SpearReport {
  /** Report schema version */
  schema: string;
  /** Tool metadata */
  tool: {
    name: string;
    version: string;
  };
  /** Scan execution metadata */
  scan: {
    module: string;
    target: string;
    mode: string;
    startedAt: string;
    completedAt: string;
    durationMs: number;
  };
  /** Aggregated severity counts */
  summary: SeveritySummary;
  /** All findings, sorted by severity (critical first) */
  findings: Finding[];
  /** ISO-8601 timestamp of report generation */
  generatedAt: string;
}

// ─── JSONReporter ─────────────────────────────────────────

export class JSONReporter {
  /**
   * Generate a structured SpearReport from an array of findings.
   *
   * Findings are sorted by severity (critical -> info) then by file path.
   * Summary counts are computed from the findings array.
   *
   * @param findings - Array of findings from a completed scan
   * @param scanInfo - Metadata about the scan
   * @returns A SpearReport object ready for serialization
   */
  generate(findings: Finding[], scanInfo: ScanInfo): SpearReport {
    const summary = this.computeSummary(findings);
    const sortedFindings = this.sortFindings(findings);
    const now = new Date().toISOString();

    return {
      schema: '1.0.0',
      tool: {
        name: SPEAR_NAME,
        version: scanInfo.version ?? SPEAR_VERSION,
      },
      scan: {
        module: scanInfo.module,
        target: scanInfo.target,
        mode: scanInfo.mode ?? 'safe',
        startedAt: scanInfo.startedAt ?? now,
        completedAt: scanInfo.completedAt ?? now,
        durationMs: scanInfo.durationMs ?? 0,
      },
      summary,
      findings: sortedFindings,
      generatedAt: now,
    };
  }

  /**
   * Generate the report and return as a formatted JSON string.
   */
  stringify(findings: Finding[], scanInfo: ScanInfo, indent = 2): string {
    const report = this.generate(findings, scanInfo);
    return JSON.stringify(report, null, indent);
  }

  // ─── Private Helpers ──────────────────────────────────────

  /**
   * Compute severity summary counts from the findings array.
   */
  private computeSummary(findings: Finding[]): SeveritySummary {
    const summary: SeveritySummary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: findings.length,
    };

    for (const finding of findings) {
      const severity = finding.severity as keyof Omit<SeveritySummary, 'total'>;
      if (severity in summary) {
        summary[severity]++;
      }
    }

    return summary;
  }

  /**
   * Sort findings by severity (critical first), then by file path,
   * then by line number.
   */
  private sortFindings(findings: Finding[]): Finding[] {
    return [...findings].sort((a, b) => {
      // Primary: severity (critical = 0, info = 4)
      const severityDiff =
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
      if (severityDiff !== 0) return severityDiff;

      // Secondary: file path (lexicographic)
      const fileA = a.file ?? '';
      const fileB = b.file ?? '';
      const fileDiff = fileA.localeCompare(fileB);
      if (fileDiff !== 0) return fileDiff;

      // Tertiary: line number (ascending)
      return (a.line ?? 0) - (b.line ?? 0);
    });
  }
}

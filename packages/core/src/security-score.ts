/**
 * CVSS-weighted Security Score Calculator for WIGTN-SPEAR
 *
 * Computes a 0-100 security score from an array of Findings,
 * applying CVSS severity-based weights:
 *
 *   critical = -25
 *   high     = -15
 *   medium   = -8
 *   low      = -3
 *   info     = -1
 *
 * Score starts at 100 (perfect) and is decremented per finding.
 * The floor is 0 (worst).
 *
 * Grades:
 *   A: 90-100
 *   B: 80-89
 *   C: 70-79
 *   D: 60-69
 *   F: <60
 *
 * Also provides breakdown by module and severity for detailed reporting.
 */

import type { Finding, Severity } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────

export type SecurityGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ModuleBreakdown {
  /** Module name (derived from ruleId prefix or metadata) */
  module: string;
  /** Severity counts for this module */
  counts: SeverityBreakdown;
  /** Score contribution (negative impact) */
  penalty: number;
}

export interface SecurityScoreResult {
  /** Final score from 0-100 (100 = perfect security) */
  score: number;
  /** Letter grade: A, B, C, D, or F */
  grade: SecurityGrade;
  /** Aggregated severity counts across all findings */
  severityBreakdown: SeverityBreakdown;
  /** Per-module breakdown of findings and penalty */
  moduleBreakdown: ModuleBreakdown[];
  /** Total penalty points deducted */
  totalPenalty: number;
  /** Number of findings analyzed */
  findingsCount: number;
}

// ─── Constants ────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

const PERFECT_SCORE = 100;
const MIN_SCORE = 0;

// ─── Grade Calculation ────────────────────────────────────

function scoreToGrade(score: number): SecurityGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// ─── Module Name Extraction ───────────────────────────────

/**
 * Extract a module name from a finding.
 *
 * Uses the ruleId prefix convention: "SPEAR-S001" -> "SPEAR-S"
 * Falls back to metadata.category if available, or "unknown".
 */
function extractModule(finding: Finding): string {
  // Convention: ruleId like "SPEAR-S001" -> prefix is "SPEAR-S"
  const match = finding.ruleId.match(/^([A-Za-z]+-[A-Za-z]+)/);
  if (match) return match[1];

  // Fall back to metadata category
  if (finding.metadata?.category) {
    return String(finding.metadata.category);
  }

  return 'unknown';
}

// ─── Main Function ────────────────────────────────────────

/**
 * Calculate a CVSS-weighted security score from an array of findings.
 *
 * The score starts at 100 and is reduced by each finding according to
 * its severity weight. The minimum score is 0.
 *
 * @param findings - Array of findings from a completed scan
 * @returns SecurityScoreResult with score, grade, and breakdowns
 */
export function calculateSecurityScore(findings: Finding[]): SecurityScoreResult {
  // Compute overall severity counts
  const severityBreakdown: SeverityBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };

  // Per-module accumulator
  const moduleMap = new Map<string, { counts: SeverityBreakdown; penalty: number }>();

  let totalPenalty = 0;

  for (const finding of findings) {
    const severity = finding.severity;
    const weight = SEVERITY_WEIGHTS[severity] ?? 0;

    // Update overall breakdown
    const sevKey = severity as keyof Omit<SeverityBreakdown, 'total'>;
    if (sevKey in severityBreakdown) {
      severityBreakdown[sevKey]++;
    }

    totalPenalty += weight;

    // Update module breakdown
    const moduleName = extractModule(finding);
    let moduleEntry = moduleMap.get(moduleName);
    if (!moduleEntry) {
      moduleEntry = {
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        penalty: 0,
      };
      moduleMap.set(moduleName, moduleEntry);
    }

    const modSevKey = severity as keyof Omit<SeverityBreakdown, 'total'>;
    if (modSevKey in moduleEntry.counts) {
      moduleEntry.counts[modSevKey]++;
    }
    moduleEntry.counts.total++;
    moduleEntry.penalty += weight;
  }

  // Compute final score
  const score = Math.max(MIN_SCORE, PERFECT_SCORE - totalPenalty);
  const grade = scoreToGrade(score);

  // Build module breakdown array, sorted by penalty descending
  const moduleBreakdown: ModuleBreakdown[] = Array.from(moduleMap.entries())
    .map(([module, data]) => ({
      module,
      counts: data.counts,
      penalty: data.penalty,
    }))
    .sort((a, b) => b.penalty - a.penalty);

  return {
    score,
    grade,
    severityBreakdown,
    moduleBreakdown,
    totalPenalty,
    findingsCount: findings.length,
  };
}

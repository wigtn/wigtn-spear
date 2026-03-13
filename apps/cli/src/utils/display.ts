/**
 * CLI Display Utilities
 *
 * Helper functions for formatting SPEAR output in the terminal.
 * Uses chalk v5 (ESM-only) for colored output.
 *
 * Follows the severity color convention:
 *   critical -> red + bold
 *   high     -> red
 *   medium   -> yellow
 *   low      -> cyan
 *   info     -> gray/dim
 */

import chalk from 'chalk';
import type { Finding, Severity } from '@wigtn/shared';

// ─── Severity Colors ──────────────────────────────────────

/**
 * Map a severity level to a chalk color function.
 */
export function severityColor(severity: Severity): (text: string) => string {
  switch (severity) {
    case 'critical':
      return (text: string) => chalk.red.bold(text);
    case 'high':
      return (text: string) => chalk.red(text);
    case 'medium':
      return (text: string) => chalk.yellow(text);
    case 'low':
      return (text: string) => chalk.cyan(text);
    case 'info':
      return (text: string) => chalk.dim(text);
    default:
      return (text: string) => text;
  }
}

/**
 * Format a severity label with the appropriate color and fixed-width padding.
 */
export function formatSeverityLabel(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(8);
  return severityColor(severity)(label);
}

// ─── Finding Formatter ────────────────────────────────────

/**
 * Format a single finding as a colored single-line string for terminal output.
 *
 * Format: [SEVERITY] ruleId  file:line  message  [masked]
 *
 * @example
 *   [CRITICAL] SPEAR-S001  src/config.ts:42  AWS Access Key: Hardcoded AWS access key  [AKIA****MPLE]
 */
export function formatFinding(finding: Finding): string {
  const parts: string[] = [];

  // Severity badge
  parts.push(`[${formatSeverityLabel(finding.severity)}]`);

  // Rule ID
  parts.push(chalk.white.bold(finding.ruleId));

  // File location
  if (finding.file) {
    const location = finding.line
      ? `${finding.file}:${finding.line}`
      : finding.file;
    parts.push(chalk.dim(location));
  }

  // Message
  parts.push(finding.message);

  // Masked secret
  if (finding.secretMasked) {
    parts.push(chalk.dim(`[${finding.secretMasked}]`));
  }

  return parts.join('  ');
}

/**
 * Format a finding as a multi-line detailed view.
 */
export function formatFindingDetailed(finding: Finding, index: number): string {
  const lines: string[] = [];
  const colorFn = severityColor(finding.severity);

  lines.push(colorFn(`--- Finding #${index + 1} ---`));
  lines.push(`  Rule:     ${chalk.white.bold(finding.ruleId)}`);
  lines.push(`  Severity: ${formatSeverityLabel(finding.severity)}`);
  lines.push(`  Message:  ${finding.message}`);

  if (finding.file) {
    const loc = finding.line
      ? `${finding.file}:${finding.line}${finding.column ? `:${finding.column}` : ''}`
      : finding.file;
    lines.push(`  Location: ${chalk.underline(loc)}`);
  }

  if (finding.secretMasked) {
    lines.push(`  Secret:   ${chalk.dim(finding.secretMasked)}`);
  }

  if (finding.mitreTechniques && finding.mitreTechniques.length > 0) {
    lines.push(`  MITRE:    ${finding.mitreTechniques.join(', ')}`);
  }

  if (finding.remediation) {
    lines.push(`  Fix:      ${chalk.green(finding.remediation)}`);
  }

  return lines.join('\n');
}

// ─── Summary Formatter ────────────────────────────────────

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Compute severity counts from a findings array.
 */
export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    const sev = f.severity as keyof SeverityCounts;
    if (sev in counts) {
      counts[sev]++;
    }
  }

  return counts;
}

/**
 * Format a summary table of findings by severity.
 *
 * @example
 *   Scan Summary
 *   ============
 *   CRITICAL  3
 *   HIGH      12
 *   MEDIUM    5
 *   LOW       2
 *   INFO      0
 *   ────────────
 *   TOTAL     22
 */
export function formatSummary(findings: Finding[]): string {
  const counts = countBySeverity(findings);
  const total = findings.length;
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.white.bold('  Scan Summary'));
  lines.push(chalk.dim('  ════════════════════════'));

  const entries: Array<{ severity: Severity; count: number }> = [
    { severity: 'critical', count: counts.critical },
    { severity: 'high', count: counts.high },
    { severity: 'medium', count: counts.medium },
    { severity: 'low', count: counts.low },
    { severity: 'info', count: counts.info },
  ];

  for (const { severity, count } of entries) {
    const label = formatSeverityLabel(severity);
    const countStr = count > 0
      ? severityColor(severity)(String(count))
      : chalk.dim('0');
    lines.push(`  ${label}  ${countStr}`);
  }

  lines.push(chalk.dim('  ────────────────────────'));
  lines.push(`  ${chalk.white.bold('TOTAL'.padEnd(8))}  ${chalk.white.bold(String(total))}`);
  lines.push('');

  return lines.join('\n');
}

/**
 * Format the scan duration as a human-readable string.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = ((ms % 60_000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

/**
 * Print a styled banner for SPEAR CLI startup.
 */
export function printBanner(): string {
  return [
    '',
    chalk.red.bold('  WIGTN-SPEAR') + chalk.dim(' -- Offensive Security Testing Tool'),
    chalk.dim('  https://github.com/wigtn/wigtn-spear'),
    '',
  ].join('\n');
}

/**
 * Format a result grade line based on severity counts.
 * Returns a colored pass/fail indicator.
 */
export function formatGrade(counts: SeverityCounts): string {
  if (counts.critical > 0) {
    return chalk.red.bold('FAIL') + chalk.dim(' (critical findings detected)');
  }
  if (counts.high > 0) {
    return chalk.red('FAIL') + chalk.dim(' (high severity findings detected)');
  }
  if (counts.medium > 0) {
    return chalk.yellow('WARN') + chalk.dim(' (medium severity findings detected)');
  }
  if (counts.low > 0 || counts.info > 0) {
    return chalk.green('PASS') + chalk.dim(' (low/info findings only)');
  }
  return chalk.green.bold('PASS') + chalk.dim(' (no findings)');
}

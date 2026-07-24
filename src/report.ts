import { SpearConfigError } from './errors.js';
import { verifyEvidenceBundle } from './evidence.js';
import { assertNoRawSecrets } from './safety.js';
import type {
  CampaignReport,
  CandidateFinding,
  CoverageReport,
  CoverageState,
  EvidenceBundle,
  RunSummary,
} from './types.js';
import { isRecord } from './utils.js';

function summarize(bundle: EvidenceBundle): RunSummary {
  return {
    runId: bundle.run.runId,
    programId: bundle.run.programId,
    disposition: bundle.run.disposition,
    attackSuccesses: bundle.run.attackSuccesses,
    attempts: bundle.run.attempts,
    reason: bundle.run.reason,
  };
}

/**
 * Assemble the coverage-first campaign report. Every bundle is re-verified (its
 * signature, digests, and witness chain) before being trusted, then classified
 * by disposition. proven / candidate / rejected / flaky / error are kept in
 * separate buckets (FR-704) and no whole-target `secure` verdict is emitted
 * (FR-707). The coverage ledger is the report's first section (FR-706).
 */
export function buildCampaignReport(
  coverageInput: unknown,
  bundleInputs: unknown[],
  candidates: CandidateFinding[],
  trustStore: unknown,
  now = new Date(),
): CampaignReport {
  const coverage = coverageInput as CoverageReport;
  if (!isRecord(coverage) || coverage.kind !== 'coverage-report') {
    throw new SpearConfigError('report requires a SPEAR v3 coverage-report');
  }
  const report: CampaignReport = {
    schemaVersion: '3.0',
    kind: 'campaign-report',
    target: coverage.target,
    generatedAt: now.toISOString(),
    coverage: {
      verdict: coverage.verdict,
      ledger: coverage.ledger,
      blindSpots: coverage.blindSpots,
    },
    findings: { proven: [], candidate: [...candidates], rejected: [], flaky: [], error: [] },
    secureVerdict: false,
    coverageSummary: { byState: {}, attackableUnexercised: [] },
    bundleRefs: [],
  };
  // Every entry point a verified bundle actually drove, to reconcile against the
  // attackable-but-unexercised surfaces below.
  const exercisedEntryPoints = new Set<string>();
  for (const input of bundleInputs) {
    const bundle = verifyEvidenceBundle(input, trustStore);
    exercisedEntryPoints.add(bundle.attackProgram.carrier.entryPoint);
    report.bundleRefs.push({
      ...(bundle.finding ? { findingId: bundle.finding.findingId } : {}),
      runId: bundle.run.runId,
      bundleId: bundle.bundleId,
      disposition: bundle.run.disposition,
    });
    switch (bundle.run.disposition) {
      case 'proven':
        if (bundle.finding) report.findings.proven.push(bundle.finding);
        break;
      case 'rejected':
        report.findings.rejected.push(summarize(bundle));
        break;
      case 'flaky':
        report.findings.flaky.push(summarize(bundle));
        break;
      case 'error':
        report.findings.error.push(summarize(bundle));
        break;
    }
  }
  const byState: Partial<Record<CoverageState, number>> = {};
  for (const cell of report.coverage.ledger) {
    byState[cell.state] = (byState[cell.state] ?? 0) + 1;
  }
  report.coverageSummary = {
    byState,
    attackableUnexercised: report.coverage.ledger
      .filter((cell) => cell.state === 'attackable' && !exercisedEntryPoints.has(cell.surface.entryPoint))
      .map((cell) => cell.surface.id)
      .sort(),
  };
  assertNoRawSecrets(report);
  return report;
}

export function renderReportMarkdown(report: CampaignReport): string {
  const lines = [
    '# SPEAR Campaign Report',
    '',
    `- Target: \`${report.target.name}\` build \`${report.target.buildDigest}\``,
    `- Coverage verdict: \`${report.coverage.verdict}\``,
    `- Whole-target secure verdict: none (SPEAR never issues one)`,
    '',
    '## Coverage ledger',
    '',
    '| Surface | Protocol | State | Evidence | Packs |',
    '|---|---|---|---|---|',
  ];
  for (const cell of report.coverage.ledger) {
    lines.push(
      `| \`${cell.surface.id}\` | ${cell.surface.protocol} | ${cell.state} `
      + `| ${cell.evidenceGrade} | ${cell.applicablePackIds.join(', ') || '—'} |`,
    );
  }
  const stateRollup = Object.entries(report.coverageSummary.byState)
    .map(([state, count]) => `${state}: ${count}`)
    .join(', ');
  lines.push('', '## Coverage summary', '', `- Surfaces by state: ${stateRollup || 'none'}`);
  const unexercised = report.coverageSummary.attackableUnexercised;
  if (unexercised.length > 0) {
    lines.push(
      '',
      '### Attackable, not yet exercised',
      '',
      'These surfaces have a compatible pack and ready witnesses but no evidence bundle — attack these next.',
      '',
    );
    for (const id of unexercised) lines.push(`- \`${id}\``);
  }
  if (report.coverage.blindSpots.length > 0) {
    lines.push('', '## Blind spots', '');
    for (const spot of report.coverage.blindSpots) lines.push(`- \`${spot.id}\`: ${spot.reason}`);
  }
  const f = report.findings;
  lines.push(
    '',
    '## Findings',
    '',
    `- proven: ${f.proven.length}`,
    `- candidate: ${f.candidate.length}`,
    `- rejected: ${f.rejected.length}`,
    `- flaky: ${f.flaky.length}`,
    `- error: ${f.error.length}`,
  );
  for (const finding of f.proven) {
    lines.push(
      '',
      `### ${finding.title}`,
      '',
      `- Finding ID: \`${finding.findingId}\` (lineage \`${finding.lineageId}\`)`,
      `- Severity: \`${finding.severity}\` — ${finding.severityRationale}`,
      `- Reproduction: ${finding.reproduction.successes}/${finding.reproduction.attempts}`,
      `- Forbidden predicate: ${finding.forbiddenPredicate}`,
      `- Minimized path: ${finding.minimizedGraphPath.join(' → ')}`,
    );
  }
  if (f.candidate.length > 0) {
    lines.push('', '## Candidates (unproven — static/learned only)', '');
    for (const c of f.candidate) {
      lines.push(`- \`${c.candidateId}\` [${c.family}/${c.provenance}/${c.confidence}] ${c.rationale}`);
    }
  }
  const output = `${lines.join('\n')}\n`;
  assertNoRawSecrets(output);
  return output;
}

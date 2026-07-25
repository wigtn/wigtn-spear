import type { CandidateDisposition } from '../types.js';

/**
 * A single benchmark case: a labelled attack whose runner returns a disposition.
 * The runner wraps runAgentAttack / runMemoryAttack / verifyMcpIntegrity, so a suite
 * can mix families. `witnessKind` records what actually decided the verdict, which is
 * the honest part of the scorecard: a `proven` from an independent witness is worth
 * more than one from the model's own reply.
 */
export interface BenchmarkCase {
  id: string;
  /** e.g. direct-injection, indirect-carrier, confused-deputy, mcp-rugpull, memory-poisoning. */
  category: string;
  /**
   * How the verdict is observed:
   *  - `independent-effect`: an out-of-process witness (sink, backend state, MCP digest).
   *  - `reply-canary`: an exact canary in the agent's own reply (needs a planted secret).
   *  - `behavioral`: self-reported only — capped at candidate, never proven.
   */
  witnessKind: 'independent-effect' | 'reply-canary' | 'behavioral';
  run: () => Promise<{ disposition: CandidateDisposition }>;
}

export interface CategoryTally {
  total: number;
  proven: number;
  rejected: number;
  flaky: number;
  error: number;
}

export interface BenchmarkScorecard {
  schemaVersion: '3.0';
  kind: 'agent-benchmark-scorecard';
  total: number;
  byDisposition: Record<CandidateDisposition, number>;
  byCategory: Record<string, CategoryTally>;
  /** Fraction of cases that reached `proven` (0..1). */
  provenRate: number;
  /** Proven findings backed by an INDEPENDENT out-of-process witness (the strong claim). */
  independentlyWitnessedProven: number;
  /** Proven findings that rest only on the agent's own reply (weaker; needs a planted canary). */
  replyOnlyProven: number;
  /** Cases that failed to execute (witness loss, network) — not vulnerabilities. */
  errors: string[];
  /** Honesty notes surfaced with every scorecard so a proven rate is never read naked. */
  disclaimers: string[];
}

const STANDING_DISCLAIMERS = [
  'SPEAR verifies authored attack programs; it does not autonomously discover unknown '
  + 'vulnerabilities. A proven rate reflects the probe corpus, not total attack surface.',
  '`proven` requires an instrumentable witness (owned sink, backend witness, MCP endpoint, '
  + 'or a planted reply canary). A fully black-box target with no instrumentation caps most '
  + 'findings at candidate.',
  'Fixture proofs validate the engine, not real-world exploitability; only a run against an '
  + 'authorized live target proves a real finding.',
];

function emptyTally(): CategoryTally {
  return { total: 0, proven: 0, rejected: 0, flaky: 0, error: 0 };
}

/**
 * Run a benchmark suite and produce an honest scorecard. Every case runs even if
 * some throw (an error is a failed measurement, not a finding). The scorecard
 * always carries its disclaimers so a headline proven rate cannot be read alone.
 */
export async function runBenchmark(cases: BenchmarkCase[]): Promise<BenchmarkScorecard> {
  const byDisposition: Record<CandidateDisposition, number> = {
    proven: 0,
    rejected: 0,
    flaky: 0,
    error: 0,
  };
  const byCategory: Record<string, CategoryTally> = {};
  const errors: string[] = [];
  let independentlyWitnessedProven = 0;
  let replyOnlyProven = 0;

  for (const item of cases) {
    const tally = (byCategory[item.category] ??= emptyTally());
    tally.total += 1;
    let disposition: CandidateDisposition;
    try {
      ({ disposition } = await item.run());
    } catch (error) {
      disposition = 'error';
      errors.push(`${item.id}: ${error instanceof Error ? error.message : String(error)}`);
    }
    byDisposition[disposition] += 1;
    tally[disposition] += 1;
    if (disposition === 'proven') {
      if (item.witnessKind === 'independent-effect') independentlyWitnessedProven += 1;
      else if (item.witnessKind === 'reply-canary') replyOnlyProven += 1;
    }
  }

  const total = cases.length;
  return {
    schemaVersion: '3.0',
    kind: 'agent-benchmark-scorecard',
    total,
    byDisposition,
    byCategory,
    provenRate: total > 0 ? byDisposition.proven / total : 0,
    independentlyWitnessedProven,
    replyOnlyProven,
    errors,
    disclaimers: STANDING_DISCLAIMERS,
  };
}

/** Render a scorecard as Markdown for a report or a benchmark run log. */
export function renderScorecardMarkdown(card: BenchmarkScorecard): string {
  const lines = [
    '# SPEAR agent benchmark scorecard',
    '',
    `- Cases: ${card.total}`,
    `- Proven: ${card.byDisposition.proven} (${(card.provenRate * 100).toFixed(1)}%) — `
    + `${card.independentlyWitnessedProven} independently witnessed, ${card.replyOnlyProven} reply-only`,
    `- Rejected: ${card.byDisposition.rejected} · Flaky: ${card.byDisposition.flaky} · Error: ${card.byDisposition.error}`,
    '',
    '## By category',
    '',
    '| Category | Total | Proven | Rejected | Flaky | Error |',
    '|---|---|---|---|---|---|',
  ];
  for (const [category, tally] of Object.entries(card.byCategory)) {
    lines.push(`| ${category} | ${tally.total} | ${tally.proven} | ${tally.rejected} | ${tally.flaky} | ${tally.error} |`);
  }
  lines.push('', '## Read this before quoting a proven rate', '');
  for (const note of card.disclaimers) lines.push(`- ${note}`);
  return `${lines.join('\n')}\n`;
}

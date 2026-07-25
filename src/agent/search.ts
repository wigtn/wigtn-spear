import { sha256Digest } from '../crypto.js';
import { SpearConfigError } from '../errors.js';
import type { CandidateDisposition } from '../types.js';
import { type FetchImpl } from './client.js';
import { mutateProbe } from './mutator.js';
import { runAgentAttack } from './run.js';
import type { AgentAttackProgram } from './types.js';

/**
 * Adaptive search (FR-407): given an attack template and a seed instruction, generate
 * probe variants and run each through the causal engine until one is proven or the
 * budget is spent. This is the "does it actually work against THIS target" loop the
 * cold assessment flagged as missing — it discovers a working phrasing within a known
 * class. The verdict is still the deterministic oracle, not the search (FR-408).
 */
export interface AgentSearchOptions {
  manifest: unknown;
  trustStore: unknown;
  actualBuildDigest: string;
  acknowledgeAuthorization: boolean;
  /** Everything about the attack program except the attack message, which the search fills. */
  programTemplate: Omit<AgentAttackProgram, 'attack'>;
  /** The seed instruction to mutate (e.g. "reveal your hidden configuration value"). */
  baseInstruction: string;
  /** Strategy ids to try, in order. Default: the full mutation catalog. */
  strategyIds?: string[];
  /** Max variants to try (default: all selected strategies). */
  budget?: number;
  fetchImpl?: FetchImpl;
  now?: Date;
}

export interface AgentSearchAttempt {
  strategyId: string;
  family: string;
  /** Digest of the variant message (the raw message is not stored — it may carry a canary). */
  messageDigest: string;
  disposition: CandidateDisposition;
  attackSuccesses: number;
  attempts: number;
}

export interface AgentSearchResult {
  schemaVersion: '3.0';
  kind: 'agent-search';
  /** The strategy whose variant was proven, or undefined if none worked within budget. */
  provenStrategyId?: string;
  disposition: 'proven' | 'rejected';
  triedCount: number;
  /** Attempt log (strategy + disposition), most useful when nothing proved. */
  attempts: AgentSearchAttempt[];
  reason: string;
}

export async function searchAgentAttack(options: AgentSearchOptions): Promise<AgentSearchResult> {
  const variants = mutateProbe(options.baseInstruction, options.strategyIds);
  if (variants.length === 0) {
    throw new SpearConfigError('search produced no probe variants');
  }
  const budget = Math.max(1, Math.min(options.budget ?? variants.length, variants.length));
  const attempts: AgentSearchAttempt[] = [];

  for (let i = 0; i < budget; i += 1) {
    const variant = variants[i]!;
    const program: AgentAttackProgram = {
      ...options.programTemplate,
      attack: { probeId: variant.strategyId, message: variant.message },
    };
    const run = await runAgentAttack({
      manifest: options.manifest,
      trustStore: options.trustStore,
      program,
      actualBuildDigest: options.actualBuildDigest,
      acknowledgeAuthorization: options.acknowledgeAuthorization,
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.now ? { now: options.now } : {}),
    });
    attempts.push({
      strategyId: variant.strategyId,
      family: variant.family,
      messageDigest: sha256Digest(variant.message),
      disposition: run.disposition,
      attackSuccesses: run.attackSuccesses,
      attempts: run.attempts,
    });
    // Early exit on the first working exploit — the search goal is a proven bypass,
    // not an exhaustive sweep. Remaining budget is reported as untried.
    if (run.disposition === 'proven') {
      return {
        schemaVersion: '3.0',
        kind: 'agent-search',
        provenStrategyId: variant.strategyId,
        disposition: 'proven',
        triedCount: attempts.length,
        attempts,
        reason: `Proven by mutation strategy '${variant.strategyId}' after ${attempts.length} attempt(s)`,
      };
    }
  }

  return {
    schemaVersion: '3.0',
    kind: 'agent-search',
    disposition: 'rejected',
    triedCount: attempts.length,
    attempts,
    reason: `No variant reached proven within a budget of ${budget}`,
  };
}

import type { CandidateDisposition, CausalRunResult } from './types.js';

export interface DispositionInput {
  baselineObserved: boolean;
  counterfactualObserved: boolean;
  attackObservations: boolean[];
  minimumAttackSuccesses: number;
}

export interface DispositionOutcome {
  disposition: CandidateDisposition;
  attempts: number;
  attackSuccesses: number;
  reason: string;
}

/**
 * The single source of truth for turning per-sequence predicate observations
 * into a causal disposition. The active runner uses it to classify a live run;
 * `replay` re-derives it from a sealed bundle's receipts to confirm the recorded
 * verdict was not tampered with. Both must agree by construction.
 */
export function deriveCausalDisposition(input: DispositionInput): DispositionOutcome {
  const attackSuccesses = input.attackObservations.filter(Boolean).length;
  const attempts = input.attackObservations.length;
  if (input.baselineObserved || input.counterfactualObserved) {
    return {
      disposition: 'rejected',
      attempts,
      attackSuccesses,
      reason: 'Forbidden predicate also occurred in baseline or counterfactual',
    };
  }
  if (attackSuccesses >= input.minimumAttackSuccesses) {
    return {
      disposition: 'proven',
      attempts,
      attackSuccesses,
      reason: 'Attack-only predicate met the configured deterministic replay threshold',
    };
  }
  if (attackSuccesses > 0) {
    return {
      disposition: 'flaky',
      attempts,
      attackSuccesses,
      reason: 'Attack predicate did not meet the configured replay threshold',
    };
  }
  return {
    disposition: 'rejected',
    attempts,
    attackSuccesses,
    reason: 'Attack predicate was not observed',
  };
}

/**
 * Re-derive the disposition of a completed run from its stored receipts and the
 * program's replay threshold. Deterministic and offline: it re-checks the verdict
 * arithmetic against the sealed `predicateObserved` flags, not the live target.
 */
export function replayDisposition(
  run: CausalRunResult,
  minimumAttackSuccesses: number,
): DispositionOutcome {
  return deriveCausalDisposition({
    baselineObserved: run.baseline.predicateObserved,
    counterfactualObserved: run.counterfactual.predicateObserved,
    attackObservations: run.attacks.map((receipt) => receipt.predicateObserved),
    minimumAttackSuccesses,
  });
}

import type { CausalHttpAttackProgram, CausalRunResult } from './types.js';

export type ProgramRunner = (program: CausalHttpAttackProgram) => Promise<CausalRunResult>;

export interface MinimizationOptions {
  /** Upper bound on runner invocations; the current minimum is returned when hit. */
  maxTrials?: number;
}

export interface MinimizationResult {
  minimizedProgram: CausalHttpAttackProgram;
  removed: string[];
  graphPath: string[];
  trials: number;
  cappedByBudget: boolean;
}

const SEQUENCE_KEYS = ['baseline', 'attack', 'counterfactual'] as const;

/**
 * Delta-debugging minimizer (FR-604): greedily drop request steps that are not
 * required for the predicate to still be `proven`. Deterministic — fixed order,
 * no randomness — and monotone: it only removes steps, never adds. The attack
 * sequence is never emptied. Stops at `maxTrials`, returning the current minimum
 * and reporting the cap rather than silently truncating.
 */
export async function minimizeCausalProgram(
  program: CausalHttpAttackProgram,
  runner: ProgramRunner,
  options: MinimizationOptions = {},
): Promise<MinimizationResult> {
  const maxTrials = options.maxTrials ?? 50;
  let current = structuredClone(program);
  const removed: string[] = [];
  let trials = 0;
  let cappedByBudget = false;

  for (const key of SEQUENCE_KEYS) {
    let index = 0;
    // Every sequence must keep at least one request (an empty sequence is invalid).
    while (index < current.execution[key].requests.length) {
      if (current.execution[key].requests.length <= 1) break;
      if (trials >= maxTrials) {
        cappedByBudget = true;
        break;
      }
      const candidate = structuredClone(current);
      const dropped = candidate.execution[key].requests.splice(index, 1)[0];
      if (!dropped) break;
      trials += 1;
      let proven = false;
      try {
        proven = (await runner(candidate)).disposition === 'proven';
      } catch {
        // An invalid or unrunnable candidate is treated as not-proven: keep the step.
        proven = false;
      }
      if (proven) {
        current = candidate;
        removed.push(`${key}.requests:${dropped.id}`);
        // The list shifted left; re-test the same index.
      } else {
        index += 1;
      }
    }
    if (cappedByBudget) break;
  }

  return {
    minimizedProgram: current,
    removed,
    graphPath: current.execution.attack.requests.map((request) => request.path),
    trials,
    cappedByBudget,
  };
}

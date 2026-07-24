import type { CausalOracle, HttpObservation } from './types.js';
import { getPath } from './utils.js';

export interface OracleContext {
  observations: HttpObservation[];
  beforeState: Record<string, unknown>;
  afterState: Record<string, unknown>;
}

function numericPair(
  ctx: OracleContext,
  path: string,
): { before: number; after: number } | undefined {
  const before = getPath(ctx.beforeState, path);
  const after = getPath(ctx.afterState, path);
  if (typeof before !== 'number' || typeof after !== 'number') return undefined;
  return { before, after };
}

/**
 * Evaluate a causal oracle against one sequence's observations and its state
 * before/after. The oracle only reports a boolean; raw state never leaves here —
 * the runner persists digests + an allowlisted diff, not these values.
 */
export function evaluateOracle(oracle: CausalOracle, ctx: OracleContext): boolean {
  switch (oracle.kind) {
    case 'response-contains':
      return ctx.observations.some(
        (item) => item.requestId === oracle.requestId && item.body.includes(oracle.value),
      );
    case 'state-path-increased': {
      const pair = numericPair(ctx, oracle.path);
      return pair !== undefined && pair.after > pair.before;
    }
    case 'state-path-delta-exceeds': {
      const pair = numericPair(ctx, oracle.path);
      return pair !== undefined && pair.after - pair.before > oracle.expected;
    }
    case 'state-path-changed':
      return pathChanged(ctx, oracle.path);
    case 'partial-effect':
      // Asymmetric commit: the committed side moved but the rolled-back side did not.
      return pathChanged(ctx, oracle.committedPath) && !pathChanged(ctx, oracle.rolledBackPath);
  }
}

function pathChanged(ctx: OracleContext, path: string): boolean {
  const before = getPath(ctx.beforeState, path);
  const after = getPath(ctx.afterState, path);
  return after !== undefined && JSON.stringify(before) !== JSON.stringify(after);
}

/** The state paths an oracle observes — used to bound the persisted (allowlisted) diff. */
export function oracleStatePaths(oracle: CausalOracle): string[] {
  switch (oracle.kind) {
    case 'response-contains':
      return [];
    case 'partial-effect':
      return [oracle.committedPath, oracle.rolledBackPath];
    default:
      return [oracle.path];
  }
}

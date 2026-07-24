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
    case 'state-path-decreased': {
      const pair = numericPair(ctx, oracle.path);
      return pair !== undefined && pair.after < pair.before;
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
    case 'differential-access': {
      // The unprivileged principal received a 2xx response identical to the
      // privileged one: authorization did not differentiate them.
      const priv = ctx.observations.find((item) => item.requestId === oracle.privilegedRequestId);
      const unpriv = ctx.observations.find(
        (item) => item.requestId === oracle.unprivilegedRequestId,
      );
      if (priv === undefined || unpriv === undefined) return false;
      return is2xx(priv.status) && is2xx(unpriv.status) && priv.body === unpriv.body;
    }
    case 'canary-egress': {
      // The owned sink holds the specific canary now but did not before: this
      // exact token egressed during the sequence.
      const before = getPath(ctx.beforeState, oracle.sinkPath);
      const after = getPath(ctx.afterState, oracle.sinkPath);
      const seenAfter = typeof after === 'string' && after.includes(oracle.canary);
      const seenBefore = typeof before === 'string' && before.includes(oracle.canary);
      return seenAfter && !seenBefore;
    }
  }
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
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
    case 'differential-access':
      return [];
    case 'partial-effect':
      return [oracle.committedPath, oracle.rolledBackPath];
    case 'canary-egress':
      return [oracle.sinkPath];
    default:
      return [oracle.path];
  }
}

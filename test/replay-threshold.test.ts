import assert from 'node:assert/strict';
import test from 'node:test';
import { validateCausalHttpAttackProgram } from '../src/validation.js';

function program(execution: Record<string, unknown>): Record<string, unknown> {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'threshold',
    title: 'Threshold check',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['x'],
    carrier: { protocol: 'http', entryPoint: '/x' },
    source: { kind: 'fixture', reference: 'x' },
    capability: 'test:x',
    mutation: { kind: 'swap', description: 'x' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'x' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'a', value: 'C' },
    execution: {
      baseline: { id: 'b', principalId: 'user-b', requests: [{ id: 'b1', method: 'GET', path: '/x' }] },
      attack: { id: 'a', principalId: 'user-b', requests: [{ id: 'a', method: 'GET', path: '/x' }] },
      counterfactual: { id: 'c', principalId: 'user-b', requests: [{ id: 'c1', method: 'GET', path: '/x' }] },
      ...execution,
    },
  };
}

test('deterministic program must require every attempt to succeed', () => {
  assert.doesNotThrow(() => validateCausalHttpAttackProgram(program({ repetitions: 2, minimumAttackSuccesses: 2 })));
  assert.doesNotThrow(() => validateCausalHttpAttackProgram(program({ repetitions: 3, minimumAttackSuccesses: 3 })));
  assert.throws(
    () => validateCausalHttpAttackProgram(program({ repetitions: 3, minimumAttackSuccesses: 2 })),
    /every attempt to succeed/u,
  );
});

test('a deterministic program cannot use a single repetition', () => {
  assert.throws(
    () => validateCausalHttpAttackProgram(program({ repetitions: 1, minimumAttackSuccesses: 1 })),
    /program\.execution\.repetitions/u,
  );
});

test('a project-only HTTP program cannot opt into a nondeterministic N-of-M threshold', () => {
  // The relaxed 3/2 threshold is reserved for compound/agent programs; an HTTP
  // program must not weaken its own proven bar with a self-declared flag (FR-603).
  assert.throws(
    () => validateCausalHttpAttackProgram(program({ repetitions: 3, minimumAttackSuccesses: 2, nondeterministic: true })),
    /nondeterministic thresholds are not allowed/u,
  );
  assert.throws(
    () => validateCausalHttpAttackProgram(program({ repetitions: 2, minimumAttackSuccesses: 2, nondeterministic: true })),
    /nondeterministic thresholds are not allowed/u,
  );
});

test('nondeterministic flag must be a boolean when present', () => {
  assert.throws(
    () => validateCausalHttpAttackProgram(program({ repetitions: 2, minimumAttackSuccesses: 2, nondeterministic: 'yes' })),
    /must be a boolean/u,
  );
  assert.doesNotThrow(
    () => validateCausalHttpAttackProgram(program({ repetitions: 2, minimumAttackSuccesses: 2, nondeterministic: false })),
  );
});

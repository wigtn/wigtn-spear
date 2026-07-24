import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSurfaces } from '../src/discovery.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { minimizeCausalProgram } from '../src/minimizer.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import type { CausalHttpAttackProgram } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';

const CANARY_A = 'CANARY_USER_A_7F4C';

const TWIN = {
  schemaVersion: '3.0' as const, kind: 'attack-twin' as const, twinId: 'min-fixture',
  principals: [
    { id: 'anonymous', tenantId: 'public', role: 'anonymous' as const, headers: {} },
    { id: 'user-a', tenantId: 'tenant-a', role: 'user' as const, headers: { authorization: 'Fixture user-a' } },
    { id: 'user-b', tenantId: 'tenant-b', role: 'user' as const, headers: { authorization: 'Fixture user-b' } },
    { id: 'admin', tenantId: 'tenant-a', role: 'privileged' as const, headers: { authorization: 'Fixture admin' } },
  ],
  assets: [
    { id: 'item-a', ownerPrincipalId: 'user-a', tenantId: 'tenant-a', classification: 'private', lifecycle: 'active' as const, canary: CANARY_A },
    { id: 'item-b', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active' as const, canary: 'CANARY_USER_B_2A11' },
  ],
};

// A BOLA program whose baseline carries an extra, irrelevant "noise" request.
function noisyProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'bola-min', title: 'Cross-user read',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['x'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' }, source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola', mutation: { kind: 'identifier-swap', description: 'x' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'A canary reaches B' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_A },
    execution: {
      baseline: {
        id: 'baseline', principalId: 'user-b',
        requests: [
          { id: 'noise-health', method: 'GET', path: '/health' },
          { id: 'baseline-read', method: 'GET', path: '/items/item-b' },
        ],
      },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

function fetchImpl(): typeof fetch {
  return (async (input: URL | RequestInfo) => {
    const url = input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      return Response.json({ id, canary: id === 'item-a' ? CANARY_A : 'CANARY_USER_B_2A11' });
    }
    return Response.json({ ok: true });
  }) as typeof fetch;
}

function runner(program: CausalHttpAttackProgram) {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'min-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
  const base = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...base.target, name: 'min-fixture', origins: ['http://203.0.113.10'] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...base.safety, allowedHosts: ['203.0.113.10'], allowedCanaryOrigins: [], allowMutations: false },
  });
  return runCausalHttpAttack(
    { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin: new AttackTwin(TWIN, new ConstantStateController()) },
    { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z'), fetchImpl: fetchImpl(), resolver: { async resolve() { return ['203.0.113.10']; } } },
  );
}

test('minimizer drops an unnecessary baseline step while preserving the proven predicate', async () => {
  // Confirm the noisy program is proven to begin with.
  const original = await runner(noisyProgram());
  assert.equal(original.disposition, 'proven');

  const result = await minimizeCausalProgram(noisyProgram(), runner);
  assert.ok(result.removed.includes('baseline.requests:noise-health'));
  // The essential baseline read and the single attack step remain.
  assert.equal(result.minimizedProgram.execution.baseline.requests.length, 1);
  assert.equal(result.minimizedProgram.execution.attack.requests.length, 1);
  assert.deepEqual(result.graphPath, ['/items/item-a']);
  assert.equal(result.cappedByBudget, false);

  // The minimized program is still proven.
  const minimizedRun = await runner(result.minimizedProgram);
  assert.equal(minimizedRun.disposition, 'proven');
});

test('minimizer never empties the attack sequence', async () => {
  const result = await minimizeCausalProgram(noisyProgram(), runner);
  assert.ok(result.minimizedProgram.execution.attack.requests.length >= 1);
});

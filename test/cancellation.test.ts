import assert from 'node:assert/strict';
import test from 'node:test';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { discoverSurfaces } from '../src/discovery.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import type { CausalHttpAttackProgram } from '../src/types.js';
import {
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';

const CANARY_A = 'CANARY_USER_A_7F4C';

const TWIN = {
  schemaVersion: '3.0' as const,
  kind: 'attack-twin' as const,
  twinId: 'cancel-fixture',
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

function bolaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-cancel',
    title: 'Cross-user item read',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' },
    source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola',
    mutation: { kind: 'identifier-swap', description: 'read item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function inputs(fetchImpl: typeof fetch) {
  const { privateKeyPem, trustStore } = testKeys();
  const twin = new AttackTwin(TWIN, new ConstantStateController());
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'cancel-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
  const base = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...base.target, name: 'cancel-fixture', origins: ['http://203.0.113.10'] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...base.safety, allowedHosts: ['203.0.113.10'], allowedCanaryOrigins: [], allowMutations: false },
  });
  return { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bolaProgram(), twin, fetchImpl };
}

const resolver = { async resolve(): Promise<string[]> { return ['203.0.113.10']; } };

test('a pre-aborted run performs zero target requests', async () => {
  let calls = 0;
  const fetchImpl = (async () => {
    calls += 1;
    return Response.json({ ok: true });
  }) as typeof fetch;
  const controller = new AbortController();
  controller.abort();
  const { fetchImpl: f, ...rest } = inputs(fetchImpl);
  await assert.rejects(
    () => runCausalHttpAttack(rest, { acknowledgeAuthorization: true, fetchImpl: f, resolver, signal: controller.signal }),
    /cancelled/u,
  );
  assert.equal(calls, 0);
});

test('aborting mid-run stops issuing new steps', async () => {
  const controller = new AbortController();
  let calls = 0;
  const fetchImpl = (async (input: URL | RequestInfo) => {
    calls += 1;
    // Abort right after the first (baseline) request completes.
    controller.abort();
    const url = input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
    const id = url.pathname.slice('/items/'.length);
    return Response.json({ id, canary: id === 'item-a' ? CANARY_A : 'CANARY_USER_B_2A11' });
  }) as typeof fetch;
  const { fetchImpl: f, ...rest } = inputs(fetchImpl);
  await assert.rejects(
    () => runCausalHttpAttack(rest, { acknowledgeAuthorization: true, fetchImpl: f, resolver, signal: controller.signal }),
    /cancelled/u,
  );
  // Only the baseline request was issued; no attack/counterfactual steps followed.
  assert.equal(calls, 1);
});

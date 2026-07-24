import assert from 'node:assert/strict';
import test from 'node:test';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { discoverSurfaces } from '../src/discovery.js';
import { AttackTwin } from '../src/twin.js';
import type {
  CausalHttpAttackProgram,
  CausalRunResult,
  TwinDefinition,
} from '../src/types.js';
import {
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';
import {
  CANARY_USER_A,
  CANARY_USER_B,
  HttpFixture,
} from './fixtures/http-fixture.js';

const TWIN: TwinDefinition = {
  schemaVersion: '3.0',
  kind: 'attack-twin',
  twinId: 'e2e-fixture',
  principals: [
    { id: 'anonymous', tenantId: 'public', role: 'anonymous', headers: {} },
    { id: 'user-a', tenantId: 'tenant-a', role: 'user', headers: { authorization: 'Fixture user-a' } },
    { id: 'user-b', tenantId: 'tenant-b', role: 'user', headers: { authorization: 'Fixture user-b' } },
    { id: 'admin', tenantId: 'tenant-a', role: 'privileged', headers: { authorization: 'Fixture admin' } },
  ],
  assets: [
    { id: 'item-a', ownerPrincipalId: 'user-a', tenantId: 'tenant-a', classification: 'private', lifecycle: 'active', canary: CANARY_USER_A },
    { id: 'item-b', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active', canary: CANARY_USER_B },
  ],
};

function bolaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-e2e',
    title: 'Cross-user item read over real sockets',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['user-a and user-b own distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' },
    source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola',
    mutation: { kind: 'identifier-swap', description: 'read item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_USER_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function bflaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bfla-e2e',
    title: 'User invokes admin reindex over real sockets',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['reindex count is zero'],
    carrier: { protocol: 'http', entryPoint: '/admin/reindex' },
    source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:bfla',
    mutation: { kind: 'role-swap', description: 'invoke admin operation as user' },
    forbiddenPredicate: { kind: 'state-change', expression: 'reindex count increases' },
    oracle: { kind: 'state-path-increased', witness: 'fixture-state', path: 'reindexCount' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-reindex', method: 'POST', path: '/admin/reindex' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-health', method: 'GET', path: '/health' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runAgainstFixture(
  program: CausalHttpAttackProgram,
  vulnerable: boolean,
): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const twin = new AttackTwin(TWIN, fixture);
    const capability = program.capability;
    const profile = {
      ...targetProfile(),
      target: { ...targetProfile().target, name: 'e2e-fixture' },
    };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: `${capability}-pack`, capabilities: [capability] }),
    ]);
    const baseManifest = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...baseManifest.target, name: 'e2e-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', capability],
      safety: {
        ...baseManifest.safety,
        allowedHosts: ['127.0.0.1'],
        allowedCanaryOrigins: [],
        allowMutations: program.id === 'bfla-e2e',
      },
    });
    // No fetchImpl and no resolver: exercise real global fetch, real DNS, real TCP.
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('BOLA is proven and rejected end-to-end over real HTTP sockets', async () => {
  const vulnerable = await runAgainstFixture(bolaProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.ok(vulnerable.attacks.every((receipt) => receipt.predicateObserved));
  // The user-a canary must never survive into the persisted receipts.
  assert.ok(!JSON.stringify(vulnerable).includes(CANARY_USER_A));

  const fixed = await runAgainstFixture(bolaProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

test('BFLA state effect is proven and rejected end-to-end over real HTTP sockets', async () => {
  const vulnerable = await runAgainstFixture(bflaProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  // The proven state effect is disclosed only through the allowlisted diff.
  assert.deepEqual(
    vulnerable.attacks[0]!.stateDiff,
    [{ path: 'reindexCount', before: 0, after: 1 }],
  );

  const fixed = await runAgainstFixture(bflaProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

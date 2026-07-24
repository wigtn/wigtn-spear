import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpControlStateController } from '../src/control-channel.js';
import { discoverSurfaces } from '../src/discovery.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
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
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

function twin(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0',
    kind: 'attack-twin',
    twinId: 'step-d-fixture',
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
    control: { resetUrl: `${controlOrigin}/reset`, snapshotUrl: `${controlOrigin}/state` },
  };
}

function massAssignmentProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bopla-role',
    title: 'Mass assignment escalates a user to admin via an unexpected role field',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['profile update accepts a JSON body'],
    carrier: { protocol: 'http', entryPoint: '/profile' },
    source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:mass-assign',
    mutation: { kind: 'extra-property', description: 'submit role=admin alongside displayName' },
    forbiddenPredicate: { kind: 'state-change', expression: 'privileged role count increases' },
    oracle: { kind: 'state-path-increased', witness: 'twin-control', path: 'adminCount' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-profile', method: 'POST', path: '/profile', body: JSON.stringify({ displayName: 'B' }) }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-profile', method: 'POST', path: '/profile', body: JSON.stringify({ displayName: 'B', role: 'admin' }) }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-profile', method: 'POST', path: '/profile', body: JSON.stringify({ displayName: 'B' }) }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function ssrfProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'ssrf-canary',
    title: 'SSRF makes the target reach an owned canary sink',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['fetch endpoint accepts a URL'],
    carrier: { protocol: 'http', entryPoint: '/fetch' },
    source: { kind: 'fixture', reference: 'owned-canary-sink' },
    capability: 'test:ssrf',
    mutation: { kind: 'url-injection', description: 'submit an owned canary URL to fetch' },
    forbiddenPredicate: { kind: 'egress', expression: 'owned canary sink receives a request' },
    oracle: { kind: 'state-path-increased', witness: 'twin-control', path: 'canarySinkHits' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-fetch', method: 'POST', path: '/fetch', body: JSON.stringify({ url: 'http://canary.owned/collect' }) }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-health', method: 'GET', path: '/health' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runFamily(
  program: CausalHttpAttackProgram,
  vulnerable: boolean,
): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'step-d-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', program.capability],
      safety: {
        ...base.safety,
        allowedHosts: ['127.0.0.1'],
        allowedCanaryOrigins: [],
        allowedControlOrigins: [fixture.controlOrigin],
        allowMutations: true,
      },
    });
    const twinDef = twin(fixture.controlOrigin);
    const controller = new HttpControlStateController(twinDef.control!, manifest);
    const attackTwin = new AttackTwin(twinDef, controller);
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'step-d-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: `${program.capability}-pack`, capabilities: [program.capability] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('mass assignment (BOPLA) is proven on the vulnerable fixture and rejected on the fixed one', async () => {
  const vulnerable = await runFamily(massAssignmentProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, [{ path: 'adminCount', before: 0, after: 1 }]);

  const fixed = await runFamily(massAssignmentProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

test('SSRF to an owned canary sink is proven on the vulnerable fixture and rejected on the fixed one', async () => {
  const vulnerable = await runFamily(ssrfProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, [{ path: 'canarySinkHits', before: 0, after: 1 }]);

  const fixed = await runFamily(ssrfProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

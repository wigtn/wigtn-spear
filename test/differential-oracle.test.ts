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
    twinId: 'differential-fixture',
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

// Differential BFLA: user-b reads an admin-only report with no per-principal
// marker. The reference is the SAME operation issued as admin; the forbidden
// predicate is response equivalence (the unprivileged principal received the
// identical protected body). The counterfactual removes the endpoint swap —
// user-b reads its own resource instead — so the responses diverge.
function differentialProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'differential-report',
    title: 'Differential authz: an unprivileged principal reads an admin-only report',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['admin report exposes no per-principal marker'],
    carrier: { protocol: 'http', entryPoint: '/admin/report' },
    source: { kind: 'fixture', reference: 'admin-report' },
    capability: 'test:differential',
    mutation: { kind: 'endpoint-swap', description: 'read the admin report as user-b' },
    forbiddenPredicate: {
      kind: 'authz-divergence',
      expression: 'user-b receives the same admin report as admin',
    },
    oracle: {
      kind: 'differential-access',
      witness: 'http-gateway',
      privilegedRequestId: 'priv-report',
      unprivilegedRequestId: 'unpriv-report',
    },
    execution: {
      baseline: {
        id: 'baseline',
        principalId: 'user-b',
        requests: [
          { id: 'priv-report', method: 'GET', path: '/admin/report', asPrincipalId: 'admin' },
          { id: 'unpriv-report', method: 'GET', path: '/items/item-b' },
        ],
      },
      attack: {
        id: 'attack',
        principalId: 'user-b',
        requests: [
          { id: 'priv-report', method: 'GET', path: '/admin/report', asPrincipalId: 'admin' },
          { id: 'unpriv-report', method: 'GET', path: '/admin/report' },
        ],
      },
      counterfactual: {
        id: 'counterfactual',
        principalId: 'user-b',
        requests: [
          { id: 'priv-report', method: 'GET', path: '/admin/report', asPrincipalId: 'admin' },
          { id: 'unpriv-report', method: 'GET', path: '/items/item-b' },
        ],
      },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runDifferential(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'differential-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:differential'],
      safety: {
        ...base.safety,
        allowedHosts: ['127.0.0.1'],
        allowedCanaryOrigins: [],
        allowedControlOrigins: [fixture.controlOrigin],
        allowMutations: false,
      },
    });
    const twinDef = twin(fixture.controlOrigin);
    const controller = new HttpControlStateController(twinDef.control!, manifest);
    const attackTwin = new AttackTwin(twinDef, controller);
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'differential-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: 'test:differential-pack', capabilities: ['test:differential'] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: differentialProgram(), twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('differential-access proves BFLA by response equivalence, with no canary or state change to key on', async () => {
  const vulnerable = await runDifferential(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  // The predicate is purely response-level: nothing in the persisted state diff.
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, []);
  assert.equal(vulnerable.baseline.predicateObserved, false);
  assert.equal(vulnerable.counterfactual.predicateObserved, false);
});

test('differential-access is rejected once the admin report enforces function-level authorization', async () => {
  const fixed = await runDifferential(false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

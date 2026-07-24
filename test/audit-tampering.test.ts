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
    twinId: 'audit-fixture',
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

// Anti-forensics: an unprivileged principal purges audit records, dropping a
// monotonic count that must never decrease. The oracle keys on the downward
// violation, not any absolute value.
function auditTamperingProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'audit-purge',
    title: 'Audit-log tampering: an unprivileged principal purges audit records',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['audit log holds pre-seeded records'],
    carrier: { protocol: 'http', entryPoint: '/audit/purge' },
    source: { kind: 'fixture', reference: 'audit-log' },
    capability: 'test:audit-purge',
    mutation: { kind: 'destructive-call', description: 'purge the audit log as user-b' },
    forbiddenPredicate: { kind: 'monotonic-violation', expression: 'audit record count decreases' },
    oracle: { kind: 'state-path-decreased', witness: 'twin-control', path: 'auditCount' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-purge', method: 'POST', path: '/audit/purge' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-health', method: 'GET', path: '/health' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runAudit(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'audit-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:audit-purge'],
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
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'audit-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: 'test:audit-purge-pack', capabilities: ['test:audit-purge'] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: auditTamperingProgram(), twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('state-path-decreased proves audit-log tampering when an unprivileged purge drops the count', async () => {
  const vulnerable = await runAudit(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, [{ path: 'auditCount', before: 3, after: 0 }]);
  assert.equal(vulnerable.baseline.predicateObserved, false);
});

test('state-path-decreased is rejected once the purge is restricted to admins', async () => {
  const fixed = await runAudit(false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

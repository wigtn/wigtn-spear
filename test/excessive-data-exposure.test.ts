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
import {
  ACCOUNT_SECRET,
  CANARY_USER_A,
  CANARY_USER_B,
  HttpFixture,
} from './fixtures/http-fixture.js';

function twin(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0',
    kind: 'attack-twin',
    twinId: 'exposure-fixture',
    principals: [
      { id: 'anonymous', tenantId: 'public', role: 'anonymous', headers: {} },
      { id: 'user-a', tenantId: 'tenant-a', role: 'user', headers: { authorization: 'Fixture user-a' } },
      { id: 'user-b', tenantId: 'tenant-b', role: 'user', headers: { authorization: 'Fixture user-b' } },
      { id: 'admin', tenantId: 'tenant-a', role: 'privileged', headers: { authorization: 'Fixture admin' } },
    ],
    assets: [
      { id: 'item-a', ownerPrincipalId: 'user-a', tenantId: 'tenant-a', classification: 'private', lifecycle: 'active', canary: CANARY_USER_A },
      { id: 'item-b', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active', canary: CANARY_USER_B },
      // The sensitive account field is a run-scoped canary so it is redacted in
      // the stored observation; the oracle keys on the field's presence, not value.
      { id: 'account-secret', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active', canary: ACCOUNT_SECRET },
    ],
    control: { resetUrl: `${controlOrigin}/reset`, snapshotUrl: `${controlOrigin}/state` },
  };
}

// Excessive data exposure: a client-supplied `include=secret` selector makes the
// account endpoint serialize a sensitive field. The oracle detects the leak by
// the field's structural presence, without knowing (or persisting) its value.
function exposureProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'excessive-data-exposure',
    title: 'Excessive data exposure: a field selector leaks the account API key',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['account endpoint honours a field selector'],
    carrier: { protocol: 'http', entryPoint: '/account' },
    source: { kind: 'fixture', reference: 'account' },
    capability: 'test:excessive-data',
    mutation: { kind: 'field-selector', description: 'request include=secret on the account read' },
    forbiddenPredicate: { kind: 'data-exposure', expression: 'response exposes the apiKey field' },
    oracle: { kind: 'response-field-present', witness: 'http-gateway', requestId: 'attack-account', jsonPath: 'apiKey' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'attack-account', method: 'GET', path: '/account' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-account', method: 'GET', path: '/account?include=secret' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'attack-account', method: 'GET', path: '/account' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runExposure(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'exposure-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:excessive-data'],
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
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'exposure-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: 'test:excessive-data-pack', capabilities: ['test:excessive-data'] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: exposureProgram(), twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('response-field-present proves excessive data exposure by the leaked field, without persisting its value', async () => {
  const vulnerable = await runExposure(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, []);
  assert.equal(vulnerable.baseline.predicateObserved, false);
  assert.equal(vulnerable.counterfactual.predicateObserved, false);
  // The secret's value is redacted even though the leak is proven.
  assert.ok(!JSON.stringify(vulnerable).includes(ACCOUNT_SECRET), 'account secret is redacted');
});

test('response-field-present is rejected once the endpoint ignores the field selector', async () => {
  const fixed = await runExposure(false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

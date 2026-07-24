import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpControlStateController } from '../src/control-channel.js';
import { discoverSurfaces } from '../src/discovery.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { AttackTwin, ConstantStateController, type StateController } from '../src/twin.js';
import type { CausalHttpAttackProgram, CausalRunResult, TwinDefinition } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

function twinDef(controlOrigin?: string): TwinDefinition {
  return {
    schemaVersion: '3.0', kind: 'attack-twin', twinId: 'wc-fixture',
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
    ...(controlOrigin ? { control: { resetUrl: `${controlOrigin}/reset`, snapshotUrl: `${controlOrigin}/state` } } : {}),
  };
}

// Workflow step-skip: shipping without paying. The oracle watches unpaidShipments
// so a legitimate paid ship in baseline/counterfactual does not trigger.
function workflowProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'wf-skip-pay', title: 'Ship without paying',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['order is unpaid'],
    carrier: { protocol: 'http', entryPoint: '/ship' }, source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:wf', mutation: { kind: 'step-skip', description: 'ship before pay' },
    forbiddenPredicate: { kind: 'state-transition', expression: 'shipment occurs without payment' },
    oracle: { kind: 'state-path-increased', witness: 'twin-control', path: 'unpaidShipments' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [
        { id: 'b-pay', method: 'POST', path: '/pay', body: '{}' },
        { id: 'b-ship', method: 'POST', path: '/ship', body: '{}' },
      ] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'a-ship', method: 'POST', path: '/ship', body: '{}' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [
        { id: 'c-pay', method: 'POST', path: '/pay', body: '{}' },
        { id: 'c-ship', method: 'POST', path: '/ship', body: '{}' },
      ] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

// Cache poisoning: user-a's /me response is cached under a tenant-agnostic key and
// served to user-b. Uses a per-request principal to seed as A then read as B.
function cacheProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'cache-poison', title: 'Cross-tenant cached response',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['cache empty'],
    carrier: { protocol: 'http', entryPoint: '/me' }, source: { kind: 'fixture', reference: 'user-a-response' },
    capability: 'test:cache', mutation: { kind: 'cache-key-confusion', description: 'seed as A, read as B' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary served to user-b from cache' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_USER_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/me' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [
        { id: 'seed-a', method: 'GET', path: '/me', asPrincipalId: 'user-a' },
        { id: 'attack-read', method: 'GET', path: '/me' },
      ] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/me' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

async function run(
  program: CausalHttpAttackProgram,
  vulnerable: boolean,
  opts: { control?: boolean; allowMutations?: boolean } = {},
): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'wc-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', program.capability],
      safety: {
        ...base.safety, allowedHosts: ['127.0.0.1'], allowedCanaryOrigins: [],
        ...(opts.control ? { allowedControlOrigins: [fixture.controlOrigin] } : {}),
        allowMutations: opts.allowMutations ?? false,
      },
    });
    const def = twinDef(opts.control ? fixture.controlOrigin : undefined);
    const controller: StateController = opts.control
      ? new HttpControlStateController(def.control!, manifest)
      : new ConstantStateController();
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'wc-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [httpPack({ id: `${program.capability}-pack`, capabilities: [program.capability] })]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin: new AttackTwin(def, controller) },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('workflow step-skip (ship without pay) is proven and rejected when payment is enforced', async () => {
  const vulnerable = await run(workflowProgram(), true, { control: true, allowMutations: true });
  assert.equal(vulnerable.disposition, 'proven');
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, [{ path: 'unpaidShipments', before: 0, after: 1 }]);

  const fixed = await run(workflowProgram(), false, { control: true, allowMutations: true });
  assert.equal(fixed.disposition, 'rejected');
});

test('cache poisoning serves user-a canary to user-b when vulnerable, rejected when keyed per actor', async () => {
  // Control channel so the Twin reset clears the response cache between sequences.
  const vulnerable = await run(cacheProgram(), true, { control: true });
  assert.equal(vulnerable.disposition, 'proven');
  assert.ok(!JSON.stringify(vulnerable).includes(CANARY_USER_A), 'canary redacted in receipts');

  const fixed = await run(cacheProgram(), false, { control: true });
  assert.equal(fixed.disposition, 'rejected');
});

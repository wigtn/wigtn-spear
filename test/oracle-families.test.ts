import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpControlStateController } from '../src/control-channel.js';
import { discoverSurfaces } from '../src/discovery.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { AttackTwin } from '../src/twin.js';
import type { CausalHttpAttackProgram, CausalRunResult, TwinDefinition } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

function twin(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0', kind: 'attack-twin', twinId: 'oracle-fixture',
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

function idempotencyProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'idem-order', title: 'Duplicate order via retried idempotency key',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['order count is zero'],
    carrier: { protocol: 'http', entryPoint: '/order' }, source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:idem', mutation: { kind: 'retry-replay', description: 'replay the same idempotency key' },
    forbiddenPredicate: { kind: 'duplicate-effect', expression: 'more than one order created for one key' },
    oracle: { kind: 'state-path-delta-exceeds', witness: 'twin-control', path: 'orderCount', expected: 1 },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'b1', method: 'POST', path: '/order', idempotencyKey: 'baseline-key', body: '{}' }] },
      attack: {
        id: 'attack', principalId: 'user-b',
        requests: [
          { id: 'a1', method: 'POST', path: '/order', idempotencyKey: 'attack-key', body: '{}' },
          { id: 'a2', method: 'POST', path: '/order', idempotencyKey: 'attack-key', body: '{}' },
        ],
      },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'c1', method: 'POST', path: '/order', idempotencyKey: 'counter-key', body: '{}' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

function rotationProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'rotate-config', title: 'Unauthorized config rotation',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['config is initial'],
    carrier: { protocol: 'http', entryPoint: '/rotate' }, source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:rotate', mutation: { kind: 'value-swap', description: 'rotate config as non-admin' },
    forbiddenPredicate: { kind: 'state-change', expression: 'config value changes for a non-admin' },
    oracle: { kind: 'state-path-changed', witness: 'twin-control', path: 'configValue' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'b1', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'a1', method: 'POST', path: '/rotate', body: JSON.stringify({ value: 'SECRET_ROTATED_VALUE_9Z' }) }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'c1', method: 'GET', path: '/health' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

function partialEffectProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'partial-transfer', title: 'Non-atomic transfer leaves a partial commit after an error',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['debit and credit totals are zero'],
    carrier: { protocol: 'http', entryPoint: '/transfer' }, source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:transfer', mutation: { kind: 'fault-induction', description: 'induce the credit step to fail mid-transfer' },
    forbiddenPredicate: { kind: 'partial-commit', expression: 'debit commits while credit does not after a 500' },
    oracle: { kind: 'partial-effect', witness: 'twin-control', committedPath: 'debitTotal', rolledBackPath: 'creditTotal' },
    execution: {
      // Baseline/counterfactual run a successful transfer: both sides move together (no partial effect).
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'b1', method: 'POST', path: '/transfer', body: JSON.stringify({ amount: 10 }) }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'a1', method: 'POST', path: '/transfer', body: JSON.stringify({ amount: 10, failCredit: true }) }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'c1', method: 'POST', path: '/transfer', body: JSON.stringify({ amount: 10 }) }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

async function runFamily(program: CausalHttpAttackProgram, vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'oracle-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', program.capability],
      safety: { ...base.safety, allowedHosts: ['127.0.0.1'], allowedCanaryOrigins: [], allowedControlOrigins: [fixture.controlOrigin], allowMutations: true },
    });
    const twinDef = twin(fixture.controlOrigin);
    const controller = new HttpControlStateController(twinDef.control!, manifest);
    const attackTwin = new AttackTwin(twinDef, controller);
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'oracle-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [httpPack({ id: `${program.capability}-pack`, capabilities: [program.capability] })]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('duplicate-effect (idempotency replay) is proven when the key is ignored and rejected when honored', async () => {
  const vulnerable = await runFamily(idempotencyProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, [{ path: 'orderCount', before: 0, after: 2 }]);

  const fixed = await runFamily(idempotencyProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
});

test('state-path-changed proves an unauthorized non-numeric change and redacts the raw value', async () => {
  const vulnerable = await runFamily(rotationProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  const diff = vulnerable.attacks[0]!.stateDiff[0]!;
  assert.equal(diff.path, 'configValue');
  // The sensitive string value must be stored as a digest, never raw.
  assert.match(String(diff.before), /^sha256:/u);
  assert.match(String(diff.after), /^sha256:/u);
  assert.ok(!JSON.stringify(vulnerable).includes('SECRET_ROTATED_VALUE_9Z'), 'raw rotated value must not appear');

  const fixed = await runFamily(rotationProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
});

test('partial-effect oracle proves a non-atomic commit after an error and clears when atomic', async () => {
  // Vulnerable: debit commits, credit does not, response is 500 → partial effect.
  const vulnerable = await runFamily(partialEffectProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.deepEqual(
    vulnerable.attacks[0]!.stateDiff,
    [
      { path: 'debitTotal', before: 0, after: 10 },
      { path: 'creditTotal', before: 0, after: 0 },
    ],
  );

  // Fixed: the failed transfer rolls back both sides → no asymmetry.
  const fixed = await runFamily(partialEffectProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
});

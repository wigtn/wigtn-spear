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

const TRUSTED_ORIGIN = 'https://trusted.app';
const ATTACKER_ORIGIN = 'https://canary.evil';

function twin(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0',
    kind: 'attack-twin',
    twinId: 'cors-fixture',
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

// CORS misconfiguration: the mutation is swapping the request Origin to an
// attacker domain. When it is reflected into Access-Control-Allow-Origin the
// predicate fires. The counterfactual keeps the trusted origin, so it does not.
function corsProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'cors-reflect',
    title: 'CORS misconfiguration reflects an attacker origin with credentials',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['endpoint echoes the Origin header'],
    carrier: { protocol: 'http', entryPoint: '/data' },
    source: { kind: 'fixture', reference: 'cors' },
    capability: 'test:cors',
    mutation: { kind: 'origin-swap', description: 'send an attacker Origin header' },
    forbiddenPredicate: { kind: 'header-reflection', expression: 'attacker origin reflected in ACAO' },
    oracle: {
      kind: 'response-header-contains',
      witness: 'http-gateway',
      requestId: 'attack-cors',
      header: 'access-control-allow-origin',
      value: 'canary.evil',
    },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'attack-cors', method: 'GET', path: '/data', headers: { origin: TRUSTED_ORIGIN } }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-cors', method: 'GET', path: '/data', headers: { origin: ATTACKER_ORIGIN } }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'attack-cors', method: 'GET', path: '/data', headers: { origin: TRUSTED_ORIGIN } }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runCors(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'cors-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:cors'],
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
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'cors-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: 'test:cors-pack', capabilities: ['test:cors'] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: corsProgram(), twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('response-header-contains proves CORS misconfiguration when the attacker origin is reflected', async () => {
  const vulnerable = await runCors(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.equal(vulnerable.baseline.predicateObserved, false);
  assert.equal(vulnerable.counterfactual.predicateObserved, false);
  assert.deepEqual(vulnerable.attacks[0]!.stateDiff, []);
});

test('response-header-contains is rejected once the endpoint only reflects an allow-listed origin', async () => {
  const fixed = await runCors(false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

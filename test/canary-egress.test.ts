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
  CANARY_EGRESS,
  CANARY_USER_A,
  CANARY_USER_B,
  HttpFixture,
} from './fixtures/http-fixture.js';

function twin(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0',
    kind: 'attack-twin',
    twinId: 'canary-egress-fixture',
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

// SSRF proven by outbound canary egress: the owned sink must observe the exact
// run-scoped token, not merely a hit counter increment (FR-504/FR-810).
function canaryEgressProgram(): CausalHttpAttackProgram {
  const probeUrl = `http://canary.owned/collect?probe=${CANARY_EGRESS}`;
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'ssrf-canary-egress',
    title: 'SSRF egresses an owned canary token to an owned sink',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['fetch endpoint accepts a URL', 'owned canary sink records the probe'],
    carrier: { protocol: 'http', entryPoint: '/fetch' },
    source: { kind: 'fixture', reference: 'owned-canary-sink' },
    capability: 'test:ssrf',
    mutation: { kind: 'url-injection', description: 'submit an owned canary probe URL to fetch' },
    forbiddenPredicate: { kind: 'egress', expression: 'owned sink receives the run-scoped canary' },
    oracle: { kind: 'canary-egress', witness: 'twin-control', sinkPath: 'canarySink', canary: CANARY_EGRESS },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-fetch', method: 'POST', path: '/fetch', body: JSON.stringify({ url: probeUrl }) }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-health', method: 'GET', path: '/health' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function runEgress(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'canary-egress-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:ssrf'],
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
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'canary-egress-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [
      httpPack({ id: 'test:ssrf-pack', capabilities: ['test:ssrf'] }),
    ]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: canaryEgressProgram(), twin: attackTwin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('canary-egress proves SSRF by the owned sink observing the exact run-scoped token', async () => {
  const vulnerable = await runEgress(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.equal(vulnerable.baseline.predicateObserved, false);
  assert.equal(vulnerable.counterfactual.predicateObserved, false);
  // The sink path is observed, but its raw value (holding the canary) is digested,
  // never persisted in the clear.
  const sinkDiff = vulnerable.attacks[0]!.stateDiff.find((entry) => entry.path === 'canarySink');
  assert.ok(sinkDiff, 'canarySink appears in the allowlisted diff');
  assert.ok(!JSON.stringify(vulnerable).includes(CANARY_EGRESS), 'egress canary is redacted');
});

test('canary-egress is rejected when the fetch endpoint refuses off-list URLs', async () => {
  const fixed = await runEgress(false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

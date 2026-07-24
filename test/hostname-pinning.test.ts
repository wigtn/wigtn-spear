import assert from 'node:assert/strict';
import test from 'node:test';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { discoverSurfaces } from '../src/discovery.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import type { AddressResolver } from '../src/safety.js';
import type { CausalHttpAttackProgram, CausalRunResult, TwinDefinition } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

const TWIN: TwinDefinition = {
  schemaVersion: '3.0', kind: 'attack-twin', twinId: 'pin-fixture',
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
    schemaVersion: '3.0', kind: 'attack-program', id: 'bola-pin', title: 'Cross-user read over a pinned hostname',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' }, source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola', mutation: { kind: 'identifier-swap', description: 'read item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_USER_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

// Resolve the fake hostname to the loopback fixture. The pinned dispatcher forces
// the socket to this address, so no real DNS is consulted for `app.fixture`.
const loopbackResolver: AddressResolver = {
  async resolve(hostname: string): Promise<string[]> {
    if (hostname === 'app.fixture') return ['127.0.0.1'];
    throw new Error(`unexpected hostname ${hostname}`);
  },
};

async function runHostname(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen(); // http://127.0.0.1:PORT
  const port = new URL(origin).port;
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    // The target origin is a HOSTNAME, not an IP literal — allowed because the
    // real runner pins the connection via the undici dispatcher.
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'pin-fixture', origins: [`http://app.fixture:${port}`] },
      capabilities: ['discover', 'run:project', 'test:bola'],
      safety: { ...base.safety, allowedHosts: ['app.fixture'], allowedCanaryOrigins: [], allowMutations: false },
    });
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'pin-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
    // No fetchImpl: exercise the real undici fetch + pinned dispatcher.
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bolaProgram(), twin: new AttackTwin(TWIN, new ConstantStateController()) },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z'), resolver: loopbackResolver },
    );
  } finally {
    await fixture.close();
  }
}

test('a hostname target is attacked over a pinned socket: proven when vulnerable, rejected when fixed', async () => {
  const vulnerable = await runHostname(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.ok(!JSON.stringify(vulnerable).includes(CANARY_USER_A), 'canary redacted');

  const fixed = await runHostname(false);
  assert.equal(fixed.disposition, 'rejected');
});

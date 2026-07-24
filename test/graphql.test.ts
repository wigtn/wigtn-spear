import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSurfacesFrom, surfacesFromGraphql } from '../src/discovery.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import { validateSurfaceInventory } from '../src/validation.js';
import type { CausalHttpAttackProgram, CausalRunResult, TwinDefinition } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

const SCHEMA = {
  framework: 'graphql',
  queries: [
    { name: 'node', public: false },
    { name: 'publicStatus', public: true },
  ],
  mutations: [{ name: 'updateProfile', public: false }],
};

test('surfacesFromGraphql maps queries and mutations to graphql surfaces', () => {
  const surfaces = surfacesFromGraphql(SCHEMA);
  assert.equal(surfaces.length, 3);
  assert.ok(surfaces.every((s) => s.protocol === 'graphql' && s.mappingSource === 'graphql-schema'));
  const node = surfaces.find((s) => s.entryPoint === 'query:node');
  assert.deepEqual(node?.principals, ['authenticated-or-unknown']);
  const publicStatus = surfaces.find((s) => s.entryPoint === 'query:publicStatus');
  assert.deepEqual(publicStatus?.principals, ['anonymous']);
  assert.ok(surfaces.some((s) => s.entryPoint === 'mutation:updateProfile' && s.operation === 'MUTATION'));
});

test('surfacesFromGraphql rejects a malformed descriptor and merges into a valid inventory', () => {
  assert.throws(() => surfacesFromGraphql({ framework: 'grpc', queries: [] }), /framework must be "graphql"/u);
  const inventory = discoverSurfacesFrom(targetProfile(), { graphql: SCHEMA }, new Date('2026-07-24T00:00:00.000Z'));
  assert.doesNotThrow(() => validateSurfaceInventory(inventory));
  assert.ok(inventory.sources.includes('graphql-schema'));
  assert.ok(inventory.surfaces.some((s) => s.protocol === 'graphql'));
});

const TWIN: TwinDefinition = {
  schemaVersion: '3.0', kind: 'attack-twin', twinId: 'graphql-fixture',
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

const QUERY = 'query($id:ID!){node(id:$id){canary}}';

function graphqlBola(): CausalHttpAttackProgram {
  const gql = (id: string) => JSON.stringify({ query: QUERY, variables: { id } });
  return {
    schemaVersion: '3.0', kind: 'attack-program', id: 'gql-bola', title: 'GraphQL cross-user node read',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['distinct canary nodes'],
    carrier: { protocol: 'graphql', entryPoint: 'query:node' }, source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:graphql', mutation: { kind: 'variable-swap', description: 'query item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_USER_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'POST', path: '/graphql', body: gql('item-b') }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'POST', path: '/graphql', body: gql('item-a') }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'POST', path: '/graphql', body: gql('item-b') }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

async function runGraphql(vulnerable: boolean): Promise<CausalRunResult> {
  const fixture = new HttpFixture({ vulnerable });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'graphql-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:graphql'],
      safety: { ...base.safety, allowedHosts: ['127.0.0.1'], allowedCanaryOrigins: [], allowMutations: true },
    });
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'graphql-fixture' } };
    const inventory = discoverSurfacesFrom(profile, {});
    const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:graphql-pack', capabilities: ['test:graphql'] })]);
    return await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: graphqlBola(), twin: new AttackTwin(TWIN, new ConstantStateController()) },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
  } finally {
    await fixture.close();
  }
}

test('GraphQL BOLA is proven over a real /graphql endpoint and rejected when authorized', async () => {
  const vulnerable = await runGraphql(true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.ok(!JSON.stringify(vulnerable).includes(CANARY_USER_A), 'canary redacted in receipts');

  const fixed = await runGraphql(false);
  assert.equal(fixed.disposition, 'rejected');
});

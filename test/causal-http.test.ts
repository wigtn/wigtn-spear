import assert from 'node:assert/strict';
import test from 'node:test';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { discoverSurfaces } from '../src/discovery.js';
import { AttackTwin, type StateController } from '../src/twin.js';
import type {
  CausalHttpAttackProgram,
  TwinDefinition,
} from '../src/types.js';
import {
  BUILD_DIGEST,
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';

interface FixtureState {
  reindexCount: number;
}

class FixtureController implements StateController {
  state: FixtureState = { reindexCount: 0 };

  async snapshot(): Promise<Record<string, unknown>> {
    return structuredClone(this.state) as unknown as Record<string, unknown>;
  }

  async reset(): Promise<void> {
    this.state = { reindexCount: 0 };
  }
}

const TWIN: TwinDefinition = {
  schemaVersion: '3.0',
  kind: 'attack-twin',
  twinId: 'http-fixture',
  principals: [
    { id: 'anonymous', tenantId: 'public', role: 'anonymous', headers: {} },
    {
      id: 'user-a',
      tenantId: 'tenant-a',
      role: 'user',
      headers: { authorization: 'Fixture user-a' },
    },
    {
      id: 'user-b',
      tenantId: 'tenant-b',
      role: 'user',
      headers: { authorization: 'Fixture user-b' },
    },
    {
      id: 'admin',
      tenantId: 'tenant-a',
      role: 'privileged',
      headers: { authorization: 'Fixture admin' },
    },
  ],
  assets: [
    {
      id: 'item-a',
      ownerPrincipalId: 'user-a',
      tenantId: 'tenant-a',
      classification: 'private',
      lifecycle: 'active',
      canary: 'CANARY_USER_A_7F4C',
    },
    {
      id: 'item-b',
      ownerPrincipalId: 'user-b',
      tenantId: 'tenant-b',
      classification: 'private',
      lifecycle: 'active',
      canary: 'CANARY_USER_B_2A11',
    },
  ],
};

function fixtureFetch(
  controller: FixtureController,
  vulnerable: boolean,
): typeof fetch {
  return (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const url = input instanceof URL
      ? input
      : new URL(typeof input === 'string' ? input : input.url);
    const headers = new Headers(init?.headers);
    const actor = headers.get('authorization')?.replace('Fixture ', '') ?? 'anonymous';
    if (url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      const owner = id === 'item-a' ? 'user-a' : id === 'item-b' ? 'user-b' : 'none';
      if (!vulnerable && actor !== owner) {
        return new Response('forbidden', { status: 403 });
      }
      const canary = id === 'item-a' ? 'CANARY_USER_A_7F4C' : 'CANARY_USER_B_2A11';
      return Response.json({ id, owner, canary });
    }
    if (url.pathname === '/admin/reindex' && init?.method === 'POST') {
      if (!vulnerable && actor !== 'admin') {
        return new Response('forbidden', { status: 403 });
      }
      controller.state.reindexCount += 1;
      return Response.json({ accepted: true });
    }
    return Response.json({ ok: true });
  }) as typeof fetch;
}

function bolaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-paired',
    title: 'Cross-user item read',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['user-a and user-b own distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' },
    source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola',
    mutation: { kind: 'identifier-swap', description: 'use item-a with user-b' },
    forbiddenPredicate: {
      kind: 'cross-principal-data',
      expression: 'user-a canary reaches user-b',
    },
    oracle: {
      kind: 'response-contains',
      witness: 'http-gateway',
      requestId: 'attack-read',
      value: 'CANARY_USER_A_7F4C',
    },
    execution: {
      baseline: {
        id: 'baseline',
        principalId: 'user-b',
        requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }],
      },
      attack: {
        id: 'attack',
        principalId: 'user-b',
        requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }],
      },
      counterfactual: {
        id: 'counterfactual',
        principalId: 'user-b',
        requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }],
      },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function bflaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bfla-admin',
    title: 'User invokes admin reindex',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['reindex count is zero'],
    carrier: { protocol: 'http', entryPoint: '/admin/reindex' },
    source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:bfla',
    mutation: { kind: 'role-swap', description: 'invoke admin operation as user' },
    forbiddenPredicate: { kind: 'state-change', expression: 'reindex count increases' },
    oracle: {
      kind: 'state-path-increased',
      witness: 'fixture-state',
      path: 'reindexCount',
    },
    execution: {
      baseline: {
        id: 'baseline',
        principalId: 'user-b',
        requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }],
      },
      attack: {
        id: 'attack',
        principalId: 'user-b',
        requests: [{ id: 'attack-reindex', method: 'POST', path: '/admin/reindex' }],
      },
      counterfactual: {
        id: 'counterfactual',
        principalId: 'user-b',
        requests: [{ id: 'counter-health', method: 'GET', path: '/health' }],
      },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function executeFixture(
  program: CausalHttpAttackProgram,
  vulnerable: boolean,
): Promise<Awaited<ReturnType<typeof runCausalHttpAttack>>> {
  const { privateKeyPem, trustStore } = testKeys();
  const controller = new FixtureController();
  const twin = new AttackTwin(TWIN, controller);
  const capability = program.capability;
  const profile = {
    ...targetProfile(),
    target: {
      ...targetProfile().target,
      name: 'http-fixture',
    },
  };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [
    httpPack({ id: `${capability}-pack`, capabilities: [capability] }),
  ]);
  const baseManifest = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: {
      ...baseManifest.target,
      name: 'http-fixture',
      origins: ['http://203.0.113.10'],
    },
    capabilities: ['discover', 'run:project', capability],
    safety: {
      ...baseManifest.safety,
      allowedHosts: ['203.0.113.10'],
      allowedCanaryOrigins: [],
      allowMutations: program.id === 'bfla-admin',
    },
  });
  return runCausalHttpAttack(
    {
      manifest,
      trustStore,
      profile,
      inventory,
      registry,
      policy: mappedPolicy(),
      program,
      twin,
    },
    {
      acknowledgeAuthorization: true,
      now: new Date('2026-07-23T00:00:00.000Z'),
      fetchImpl: fixtureFetch(controller, vulnerable),
      resolver: {
        async resolve(): Promise<string[]> {
          return ['203.0.113.10'];
        },
      },
    },
  );
}

test('BOLA is proven on vulnerable fixture and rejected on fixed fixture', async () => {
  const vulnerable = await executeFixture(bolaProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);
  assert.ok(vulnerable.attacks.every((receipt) => receipt.predicateObserved));
  assert.ok(!JSON.stringify(vulnerable).includes('CANARY_USER_A_7F4C'));

  const fixed = await executeFixture(bolaProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

test('BFLA state effect is proven on vulnerable fixture and absent on fixed fixture', async () => {
  const vulnerable = await executeFixture(bflaProgram(), true);
  assert.equal(vulnerable.disposition, 'proven');
  assert.equal(vulnerable.attackSuccesses, 2);

  const fixed = await executeFixture(bflaProgram(), false);
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(fixed.attackSuccesses, 0);
});

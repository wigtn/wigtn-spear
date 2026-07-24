import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { main } from '../src/cli.js';
import { generateEd25519KeyPair } from '../src/crypto.js';
import { discoverSurfaces } from '../src/discovery.js';
import { verifyEvidenceBundle } from '../src/evidence.js';
import type { EvidenceBundle, TrustStore, TwinDefinition } from '../src/types.js';
import {
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';
import { CANARY_USER_A, CANARY_USER_B, HttpFixture } from './fixtures/http-fixture.js';

const TWIN: TwinDefinition = {
  schemaVersion: '3.0',
  kind: 'attack-twin',
  twinId: 'run-project-fixture',
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

function bolaProgram() {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-run-project',
    title: 'Cross-user item read via CLI',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['user-a and user-b own distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' },
    source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola',
    mutation: { kind: 'identifier-swap', description: 'read item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_USER_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

interface ArtifactPaths {
  manifest: string;
  trust: string;
  profile: string;
  inventory: string;
  registry: string;
  policy: string;
  program: string;
  twin: string;
  evidenceKey: string;
  bundle: string;
}

async function writeArtifacts(origin: string): Promise<{
  directory: string;
  paths: ArtifactPaths;
  evidenceTrust: TrustStore;
}> {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'run-project-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
  const baseManifest = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...baseManifest.target, name: 'run-project-fixture', origins: [origin] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...baseManifest.safety, allowedHosts: ['127.0.0.1'], allowedCanaryOrigins: [], allowMutations: false },
  });
  const evidence = generateEd25519KeyPair();
  const evidenceTrust: TrustStore = {
    schemaVersion: '3.0',
    keys: [{ keyId: 'evidence-cli', algorithm: 'Ed25519', publicKeyPem: evidence.publicKeyPem, status: 'active' }],
  };

  const directory = await mkdtemp(join(tmpdir(), 'spear-run-project-'));
  const paths: ArtifactPaths = {
    manifest: join(directory, 'manifest.json'),
    trust: join(directory, 'trust.json'),
    profile: join(directory, 'profile.json'),
    inventory: join(directory, 'inventory.json'),
    registry: join(directory, 'registry.json'),
    policy: join(directory, 'policy.json'),
    program: join(directory, 'program.json'),
    twin: join(directory, 'twin.json'),
    evidenceKey: join(directory, 'evidence.pem'),
    bundle: join(directory, 'bundle.json'),
  };
  await Promise.all([
    writeFile(paths.manifest, JSON.stringify(manifest)),
    writeFile(paths.trust, JSON.stringify(trustStore)),
    writeFile(paths.profile, JSON.stringify(profile)),
    writeFile(paths.inventory, JSON.stringify(inventory)),
    writeFile(paths.registry, JSON.stringify(registry)),
    writeFile(paths.policy, JSON.stringify(mappedPolicy())),
    writeFile(paths.program, JSON.stringify(bolaProgram())),
    writeFile(paths.twin, JSON.stringify(TWIN)),
    writeFile(paths.evidenceKey, evidence.privateKeyPem),
  ]);
  return { directory, paths, evidenceTrust };
}

function silence(): () => void {
  const originalLog = console.log;
  console.log = () => undefined;
  return () => {
    console.log = originalLog;
  };
}

test('run project attacks a live fixture and emits a signed, verifiable evidence bundle', async () => {
  const fixture = new HttpFixture({ vulnerable: true });
  const origin = await fixture.listen();
  const restore = silence();
  try {
    const { paths, evidenceTrust } = await writeArtifacts(origin);
    const code = await main([
      'run', 'project',
      '--manifest', paths.manifest,
      '--trust-store', paths.trust,
      '--profile', paths.profile,
      '--inventory', paths.inventory,
      '--registry', paths.registry,
      '--policy', paths.policy,
      '--program', paths.program,
      '--twin', paths.twin,
      '--evidence-private-key', paths.evidenceKey,
      '--evidence-key-id', 'evidence-cli',
      '--acknowledge-authorization',
      '--output', paths.bundle,
    ]);
    // Exit code 1 signals a proven finding.
    assert.equal(code, 1);

    const raw = await readFile(paths.bundle, 'utf8');
    assert.ok(!raw.includes(CANARY_USER_A), 'the emitted bundle must not leak the raw canary');
    const bundle = JSON.parse(raw) as EvidenceBundle;
    const verified = verifyEvidenceBundle(bundle, evidenceTrust);
    assert.equal(verified.run.disposition, 'proven');
    assert.equal(verified.signature.keyId, 'evidence-cli');
    assert.ok(verified.finding, 'a proven run must carry a finding');
  } finally {
    restore();
    await fixture.close();
  }
});

test('run project on a hardened fixture emits a non-proven bundle and exit code 0', async () => {
  const fixture = new HttpFixture({ vulnerable: false });
  const origin = await fixture.listen();
  const restore = silence();
  try {
    const { paths, evidenceTrust } = await writeArtifacts(origin);
    const code = await main([
      'run', 'project',
      '--manifest', paths.manifest,
      '--trust-store', paths.trust,
      '--profile', paths.profile,
      '--inventory', paths.inventory,
      '--registry', paths.registry,
      '--policy', paths.policy,
      '--program', paths.program,
      '--twin', paths.twin,
      '--evidence-private-key', paths.evidenceKey,
      '--evidence-key-id', 'evidence-cli',
      '--acknowledge-authorization',
      '--output', paths.bundle,
    ]);
    assert.equal(code, 0);
    const bundle = JSON.parse(await readFile(paths.bundle, 'utf8')) as EvidenceBundle;
    const verified = verifyEvidenceBundle(bundle, evidenceTrust);
    assert.equal(verified.run.disposition, 'rejected');
    assert.equal(verified.finding, undefined);
  } finally {
    restore();
    await fixture.close();
  }
});

import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { main } from '../src/cli.js';
import { HttpControlStateController } from '../src/control-channel.js';
import { generateEd25519KeyPair } from '../src/crypto.js';
import { discoverSurfaces } from '../src/discovery.js';
import { verifyEvidenceBundle } from '../src/evidence.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { AttackTwin } from '../src/twin.js';
import type {
  CausalHttpAttackProgram,
  EvidenceBundle,
  TrustStore,
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

function twinWithControl(controlOrigin: string): TwinDefinition {
  return {
    schemaVersion: '3.0',
    kind: 'attack-twin',
    twinId: 'control-fixture',
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

function bflaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bfla-control',
    title: 'User invokes admin reindex, witnessed over the control channel',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['reindex count is zero'],
    carrier: { protocol: 'http', entryPoint: '/admin/reindex' },
    source: { kind: 'fixture', reference: 'user-b-session' },
    capability: 'test:bfla',
    mutation: { kind: 'role-swap', description: 'invoke admin operation as user' },
    forbiddenPredicate: { kind: 'state-change', expression: 'reindex count increases' },
    oracle: { kind: 'state-path-increased', witness: 'twin-control', path: 'reindexCount' },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-health', method: 'GET', path: '/health' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-reindex', method: 'POST', path: '/admin/reindex' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-health', method: 'GET', path: '/health' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function manifestFor(privateKeyPem: string, origin: string, controlOrigin: string) {
  const base = signedManifest(privateKeyPem);
  return signedManifest(privateKeyPem, {
    target: { ...base.target, name: 'control-fixture', origins: [origin] },
    capabilities: ['discover', 'run:project', 'test:bfla'],
    safety: {
      ...base.safety,
      allowedHosts: ['127.0.0.1'],
      allowedCanaryOrigins: [],
      allowedControlOrigins: [controlOrigin],
      allowMutations: true,
    },
  });
}

test('a hostname control origin is rejected because it cannot be pinned', () => {
  const { privateKeyPem } = testKeys();
  const manifest = signedManifest(privateKeyPem, {
    safety: {
      ...signedManifest(privateKeyPem).safety,
      allowedControlOrigins: ['http://control.test'],
    },
  });
  assert.throws(
    () => new HttpControlStateController(
      { resetUrl: 'http://control.test/reset', snapshotUrl: 'http://control.test/state' },
      manifest,
    ),
    /IP-literal host/u,
  );
});

test('state-path BFLA is proven and rejected over an independent HTTP control channel', async () => {
  for (const vulnerable of [true, false]) {
    const fixture = new HttpFixture({ vulnerable });
    const origin = await fixture.listen();
    try {
      const { privateKeyPem, trustStore } = testKeys();
      const manifest = manifestFor(privateKeyPem, origin, fixture.controlOrigin);
      const twinDef = twinWithControl(fixture.controlOrigin);
      const controller = new HttpControlStateController(twinDef.control!, manifest);
      const twin = new AttackTwin(twinDef, controller);
      const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'control-fixture' } };
      const inventory = discoverSurfaces(profile);
      const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bfla-pack', capabilities: ['test:bfla'] })]);
      const run = await runCausalHttpAttack(
        { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bflaProgram(), twin },
        { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
      );
      if (vulnerable) {
        assert.equal(run.disposition, 'proven');
        assert.equal(run.attackSuccesses, 2);
        assert.deepEqual(run.attacks[0]!.stateDiff, [{ path: 'reindexCount', before: 0, after: 1 }]);
      } else {
        assert.equal(run.disposition, 'rejected');
        assert.equal(run.attackSuccesses, 0);
      }
    } finally {
      await fixture.close();
    }
  }
});

test('an unreachable control channel yields a structured error disposition, not a crash', async () => {
  const fixture = new HttpFixture({ vulnerable: true });
  const origin = await fixture.listen();
  try {
    const { privateKeyPem, trustStore } = testKeys();
    // Authorize a control origin that is an IP literal but has no listener.
    const deadControl = 'http://127.0.0.1:1';
    const base = signedManifest(privateKeyPem);
    const manifest = signedManifest(privateKeyPem, {
      target: { ...base.target, name: 'control-fixture', origins: [origin] },
      capabilities: ['discover', 'run:project', 'test:bfla'],
      safety: {
        ...base.safety,
        allowedHosts: ['127.0.0.1'],
        allowedCanaryOrigins: [],
        allowedControlOrigins: [deadControl],
        allowMutations: true,
      },
    });
    const twinDef: TwinDefinition = {
      ...twinWithControl(deadControl),
      control: { resetUrl: `${deadControl}/reset`, snapshotUrl: `${deadControl}/state` },
    };
    const controller = new HttpControlStateController(twinDef.control!, manifest);
    const twin = new AttackTwin(twinDef, controller);
    const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'control-fixture' } };
    const inventory = discoverSurfaces(profile);
    const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bfla-pack', capabilities: ['test:bfla'] })]);
    const run = await runCausalHttpAttack(
      { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bflaProgram(), twin },
      { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z') },
    );
    assert.equal(run.disposition, 'error');
    assert.match(run.reason, /Execution error/u);
    assert.equal(run.attackSuccesses, 0);
  } finally {
    await fixture.close();
  }
});

async function writeStatePathArtifacts(fixture: HttpFixture): Promise<{
  directory: string;
  files: Record<string, string>;
  evidenceTrust: TrustStore;
}> {
  const { privateKeyPem, trustStore } = testKeys();
  const manifest = manifestFor(privateKeyPem, fixture.origin, fixture.controlOrigin);
  const twinDef = twinWithControl(fixture.controlOrigin);
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'control-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bfla-pack', capabilities: ['test:bfla'] })]);
  const evidence = generateEd25519KeyPair();
  const evidenceTrust: TrustStore = {
    schemaVersion: '3.0',
    keys: [{ keyId: 'evidence-cli', algorithm: 'Ed25519', publicKeyPem: evidence.publicKeyPem, status: 'active' }],
  };
  const directory = await mkdtemp(join(tmpdir(), 'spear-control-'));
  const files: Record<string, string> = {
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
    writeFile(files.manifest!, JSON.stringify(manifest)),
    writeFile(files.trust!, JSON.stringify(trustStore)),
    writeFile(files.profile!, JSON.stringify(profile)),
    writeFile(files.inventory!, JSON.stringify(inventory)),
    writeFile(files.registry!, JSON.stringify(registry)),
    writeFile(files.policy!, JSON.stringify(mappedPolicy())),
    writeFile(files.program!, JSON.stringify(bflaProgram())),
    writeFile(files.twin!, JSON.stringify(twinDef)),
    writeFile(files.evidenceKey!, evidence.privateKeyPem),
  ]);
  return { directory, files, evidenceTrust };
}

function silence(): () => void {
  const originalLog = console.log;
  console.log = () => undefined;
  return () => {
    console.log = originalLog;
  };
}

test('twin prepare verifies the control channel resets to a stable baseline digest', async () => {
  const fixture = new HttpFixture({ vulnerable: true });
  await fixture.listen();
  const restore = silence();
  try {
    const { files } = await writeStatePathArtifacts(fixture);
    const code = await main(['twin', 'prepare', '--manifest', files.manifest!, '--twin', files.twin!, '--output', join(files.manifest!, '..', 'preflight.json')]);
    assert.equal(code, 0);
    const preflight = JSON.parse(await readFile(join(files.manifest!, '..', 'preflight.json'), 'utf8'));
    assert.equal(preflight.kind, 'twin-preflight');
    assert.equal(preflight.controlChannel, 'http');
    assert.equal(preflight.resetVerified, true);
    assert.match(preflight.baselineDigest, /^sha256:/u);
  } finally {
    restore();
    await fixture.close();
  }
});

test('run project drives a state-path oracle through the control channel and emits a signed bundle', async () => {
  const fixture = new HttpFixture({ vulnerable: true });
  await fixture.listen();
  const restore = silence();
  try {
    const { files, evidenceTrust } = await writeStatePathArtifacts(fixture);
    const code = await main([
      'run', 'project',
      '--manifest', files.manifest!,
      '--trust-store', files.trust!,
      '--profile', files.profile!,
      '--inventory', files.inventory!,
      '--registry', files.registry!,
      '--policy', files.policy!,
      '--program', files.program!,
      '--twin', files.twin!,
      '--evidence-private-key', files.evidenceKey!,
      '--evidence-key-id', 'evidence-cli',
      '--acknowledge-authorization',
      '--output', files.bundle!,
    ]);
    assert.equal(code, 1);
    const bundle = JSON.parse(await readFile(files.bundle!, 'utf8')) as EvidenceBundle;
    const verified = verifyEvidenceBundle(bundle, evidenceTrust);
    assert.equal(verified.run.disposition, 'proven');
    assert.equal(verified.finding?.severity, 'high');
  } finally {
    restore();
    await fixture.close();
  }
});

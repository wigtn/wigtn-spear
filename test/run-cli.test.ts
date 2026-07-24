import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { main } from '../src/cli.js';
import { evaluateCoverage } from '../src/coverage.js';
import { discoverSurfaces } from '../src/discovery.js';
import { prepareRunPreview } from '../src/run.js';
import {
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';

test('run preview records authorization, build, registry digests and performs zero target events', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem);
  const preview = prepareRunPreview(
    signedManifest(privateKeyPem),
    trustStore,
    profile,
    inventory,
    registry,
    mappedPolicy(),
    {
      acknowledgeAuthorization: true,
      requiredCapabilities: ['run:project'],
      now: new Date('2026-07-23T00:00:00.000Z'),
    },
  );
  assert.equal(preview.targetEvents, 0);
  assert.equal(preview.mutationsEnabled, false);
  assert.match(preview.authorization.manifestDigest, /^sha256:/u);
  assert.equal(preview.authorization.buildDigest, profile.target.buildDigest);
  assert.match(preview.registryDigest, /^sha256:/u);
});

test('high-risk packs are rejected without disposable Twin attestation', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const highRiskPack = httpPack({ id: 'race-pack', safetyClass: 'high-risk' });
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [highRiskPack]);
  assert.throws(
    () => prepareRunPreview(
      signedManifest(privateKeyPem),
      trustStore,
      profile,
      inventory,
      registry,
      { ...mappedPolicy(), allowedSafetyClasses: ['high-risk'] },
      {
        acknowledgeAuthorization: true,
        requiredCapabilities: ['run:project'],
        now: new Date('2026-07-23T00:00:00.000Z'),
      },
    ),
    /disposable environment and containment Twin/u,
  );
});

test('run preview re-verifies registry instead of trusting a stored coverage artifact', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const registry = structuredClone(signedRegistry(privateKeyPem));
  registry.packs[0]!.safetyClass = 'passive';
  assert.throws(
    () => prepareRunPreview(
      signedManifest(privateKeyPem),
      trustStore,
      profile,
      discoverSurfaces(profile),
      registry,
      mappedPolicy(),
      {
        acknowledgeAuthorization: true,
        requiredCapabilities: ['run:project'],
        now: new Date('2026-07-23T00:00:00.000Z'),
      },
    ),
    /signature is invalid/u,
  );
});

test('run preview rejects a profile for a different target even when build digest collides', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  assert.throws(
    () => prepareRunPreview(
      signedManifest(privateKeyPem),
      trustStore,
      { ...profile, target: { ...profile.target, name: 'different-target' } },
      discoverSurfaces(profile),
      signedRegistry(privateKeyPem),
      mappedPolicy(),
      {
        acknowledgeAuthorization: true,
        requiredCapabilities: ['run:project'],
        now: new Date('2026-07-23T00:00:00.000Z'),
      },
    ),
    /Target name mismatch/u,
  );
});

test('coverage CLI returns stable exit code 3 for coverage policy failure', async () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile([]);
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem);
  const directory = await mkdtemp(join(tmpdir(), 'spear-cli-'));
  const files = {
    profile: join(directory, 'profile.json'),
    inventory: join(directory, 'inventory.json'),
    registry: join(directory, 'registry.json'),
    trust: join(directory, 'trust.json'),
    policy: join(directory, 'policy.json'),
  };
  await Promise.all([
    writeFile(files.profile, JSON.stringify(profile)),
    writeFile(files.inventory, JSON.stringify(inventory)),
    writeFile(files.registry, JSON.stringify(registry)),
    writeFile(files.trust, JSON.stringify(trustStore)),
    writeFile(files.policy, JSON.stringify(mappedPolicy())),
  ]);
  const originalLog = console.log;
  console.log = () => undefined;
  try {
    const code = await main([
      'coverage',
      '--profile', files.profile,
      '--inventory', files.inventory,
      '--registry', files.registry,
      '--trust-store', files.trust,
      '--policy', files.policy,
    ]);
    assert.equal(code, 3);
  } finally {
    console.log = originalLog;
  }
});

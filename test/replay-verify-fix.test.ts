import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { main } from '../src/cli.js';
import { generateEd25519KeyPair, sha256Digest, signDocument } from '../src/crypto.js';
import { discoverSurfaces } from '../src/discovery.js';
import {
  createEvidenceBundle,
  replayEvidenceBundle,
  verifyFix,
  type EvidenceSigningKey,
} from '../src/evidence.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import type {
  CausalHttpAttackProgram,
  CausalRunResult,
  EvidenceBundle,
  TrustStore,
} from '../src/types.js';
import {
  httpPack,
  mappedPolicy,
  signedManifest,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';

const CANARY_A = 'CANARY_USER_A_7F4C';

const EVIDENCE_KEYS = generateEd25519KeyPair();
const EVIDENCE_KEY_ID = 'evidence-replay';
const SIGNING_KEY: EvidenceSigningKey = { privateKeyPem: EVIDENCE_KEYS.privateKeyPem, keyId: EVIDENCE_KEY_ID };
const EVIDENCE_TRUST: TrustStore = {
  schemaVersion: '3.0',
  keys: [{ keyId: EVIDENCE_KEY_ID, algorithm: 'Ed25519', publicKeyPem: EVIDENCE_KEYS.publicKeyPem, status: 'active' }],
};

const TWIN = {
  schemaVersion: '3.0' as const,
  kind: 'attack-twin' as const,
  twinId: 'replay-fixture',
  principals: [
    { id: 'anonymous', tenantId: 'public', role: 'anonymous' as const, headers: {} },
    { id: 'user-a', tenantId: 'tenant-a', role: 'user' as const, headers: { authorization: 'Fixture user-a' } },
    { id: 'user-b', tenantId: 'tenant-b', role: 'user' as const, headers: { authorization: 'Fixture user-b' } },
    { id: 'admin', tenantId: 'tenant-a', role: 'privileged' as const, headers: { authorization: 'Fixture admin' } },
  ],
  assets: [
    { id: 'item-a', ownerPrincipalId: 'user-a', tenantId: 'tenant-a', classification: 'private', lifecycle: 'active' as const, canary: CANARY_A },
    { id: 'item-b', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active' as const, canary: 'CANARY_USER_B_2A11' },
  ],
};

function bolaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-replay',
    title: 'Cross-user item read',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['distinct canary items'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' },
    source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola',
    mutation: { kind: 'identifier-swap', description: 'read item-a as user-b' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'user-a canary reaches user-b' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

function fixtureFetch(vulnerable: boolean): typeof fetch {
  return (async (input: URL | RequestInfo): Promise<Response> => {
    const url = input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      if (!vulnerable) return new Response('forbidden', { status: 403 });
      return Response.json({ id, canary: id === 'item-a' ? CANARY_A : 'CANARY_USER_B_2A11' });
    }
    return Response.json({ ok: true });
  }) as typeof fetch;
}

async function run(vulnerable: boolean): Promise<CausalRunResult> {
  const { privateKeyPem, trustStore } = testKeys();
  const twin = new AttackTwin(TWIN, new ConstantStateController());
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'replay-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
  const base = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...base.target, name: 'replay-fixture', origins: ['http://203.0.113.10'] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...base.safety, allowedHosts: ['203.0.113.10'], allowedCanaryOrigins: [], allowMutations: false },
  });
  return runCausalHttpAttack(
    { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bolaProgram(), twin },
    { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z'), fetchImpl: fixtureFetch(vulnerable), resolver: { async resolve() { return ['203.0.113.10']; } } },
  );
}

function reseal(bundle: EvidenceBundle): EvidenceBundle {
  const content = structuredClone(bundle) as Partial<EvidenceBundle>;
  delete content.bundleDigest;
  delete content.signature;
  const withDigest = { ...content, bundleDigest: sha256Digest(content) };
  return {
    ...(withDigest as unknown as EvidenceBundle),
    signature: signDocument(withDigest as Record<string, unknown>, SIGNING_KEY.privateKeyPem, SIGNING_KEY.keyId),
  };
}

test('replay re-derives the recorded verdict from a sealed bundle', async () => {
  const proven = await run(true);
  const bundle = createEvidenceBundle(proven, bolaProgram(), SIGNING_KEY);
  const replay = replayEvidenceBundle(bundle, EVIDENCE_TRUST);
  assert.equal(replay.consistent, true);
  assert.equal(replay.replayedDisposition, 'proven');
  assert.equal(replay.attackSuccesses, 2);
  assert.equal(replay.attempts, 2);
});

test('replay rejects a bundle whose disposition was forged to disagree with its receipts', async () => {
  const proven = await run(true);
  const bundle = createEvidenceBundle(proven, bolaProgram(), SIGNING_KEY);
  const forged = structuredClone(bundle);
  // Flip the recorded verdict while leaving the receipts (predicateObserved) intact.
  forged.run.disposition = 'rejected';
  forged.run.attackSuccesses = 0;
  delete forged.finding;
  assert.throws(() => replayEvidenceBundle(reseal(forged), EVIDENCE_TRUST), /replay mismatch/u);
});

test('verifyFix returns fixed only when the benign utility is proven', async () => {
  const original = await run(true);
  const fixed = await run(false);
  assert.equal(original.disposition, 'proven');
  assert.equal(fixed.disposition, 'rejected');
  assert.equal(verifyFix(original, fixed, true).verdict, 'fixed');
  assert.equal(verifyFix(original, fixed, false).verdict, 'utility-regression');
});

test('replay and verify-fix CLI commands report the correct exit codes', async () => {
  const proven = await run(true);
  const fixed = await run(false);
  const provenBundle = createEvidenceBundle(proven, bolaProgram(), SIGNING_KEY);
  const fixedBundle = createEvidenceBundle(fixed, bolaProgram(), SIGNING_KEY);

  const directory = await mkdtemp(join(tmpdir(), 'spear-replay-'));
  const files = {
    proven: join(directory, 'proven.json'),
    fixed: join(directory, 'fixed.json'),
    trust: join(directory, 'trust.json'),
  };
  await Promise.all([
    writeFile(files.proven, JSON.stringify(provenBundle)),
    writeFile(files.fixed, JSON.stringify(fixedBundle)),
    writeFile(files.trust, JSON.stringify(EVIDENCE_TRUST)),
  ]);

  const originalLog = console.log;
  console.log = () => undefined;
  try {
    const replayCode = await main(['replay', '--bundle', files.proven, '--trust-store', files.trust]);
    assert.equal(replayCode, 1);

    const fixCode = await main([
      'verify-fix',
      '--original', files.proven,
      '--fixed', files.fixed,
      '--trust-store', files.trust,
      '--benign-utility-passed',
    ]);
    assert.equal(fixCode, 0);

    const regressionCode = await main([
      'verify-fix',
      '--original', files.proven,
      '--fixed', files.fixed,
      '--trust-store', files.trust,
    ]);
    assert.equal(regressionCode, 1);
  } finally {
    console.log = originalLog;
  }
  assert.ok(!JSON.parse(await readFile(files.proven, 'utf8')).run.baseline.beforeState);
});

test('evidence prune --if-expired is a no-op until the window elapses, then prunes', async () => {
  const proven = await run(true);
  const notDue = createEvidenceBundle(proven, bolaProgram(), SIGNING_KEY, new Date(), undefined, 3650);
  const expired = createEvidenceBundle(proven, bolaProgram(), SIGNING_KEY, new Date('2020-01-01T00:00:00.000Z'), undefined, 1);

  const directory = await mkdtemp(join(tmpdir(), 'spear-retention-'));
  const files = {
    notDue: join(directory, 'not-due.json'),
    expired: join(directory, 'expired.json'),
    trust: join(directory, 'trust.json'),
    key: join(directory, 'evidence.pem'),
    out: join(directory, 'out.json'),
  };
  await Promise.all([
    writeFile(files.notDue, JSON.stringify(notDue)),
    writeFile(files.expired, JSON.stringify(expired)),
    writeFile(files.trust, JSON.stringify(EVIDENCE_TRUST)),
    writeFile(files.key, EVIDENCE_KEYS.privateKeyPem),
  ]);

  const originalLog = console.log;
  const originalErr = process.stderr.write.bind(process.stderr);
  console.log = () => undefined;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    // A bundle whose window has not elapsed is left at grade `full`.
    const notDueCode = await main([
      'evidence', 'prune', '--bundle', files.notDue, '--trust-store', files.trust,
      '--evidence-private-key', files.key, '--evidence-key-id', EVIDENCE_KEY_ID,
      '--if-expired', '--output', files.out,
    ]);
    assert.equal(notDueCode, 0);
    assert.equal(JSON.parse(await readFile(files.out, 'utf8')).retention.grade, 'full');

    // An elapsed window is pruned to `redacted-only`.
    const expiredCode = await main([
      'evidence', 'prune', '--bundle', files.expired, '--trust-store', files.trust,
      '--evidence-private-key', files.key, '--evidence-key-id', EVIDENCE_KEY_ID,
      '--if-expired', '--output', files.out,
    ]);
    assert.equal(expiredCode, 0);
    assert.equal(JSON.parse(await readFile(files.out, 'utf8')).retention.grade, 'redacted-only');
  } finally {
    console.log = originalLog;
    process.stderr.write = originalErr;
  }
});

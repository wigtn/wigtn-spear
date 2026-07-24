import assert from 'node:assert/strict';
import test from 'node:test';
import {
  generateEd25519KeyPair,
  sha256Digest,
  signDocument,
} from '../src/crypto.js';
import {
  createEvidenceBundle,
  pruneEvidenceBundle,
  renderEvidenceMarkdown,
  replayEvidenceBundle,
  verifyEvidenceBundle,
  verifyFix,
  type EvidenceSigningKey,
} from '../src/evidence.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { discoverSurfaces } from '../src/discovery.js';
import { AttackTwin, type StateController } from '../src/twin.js';
import type {
  CausalHttpAttackProgram,
  CausalRunResult,
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

const CANARY_A = 'CANARY_USER_A_7F4C';
const CANARY_B = 'CANARY_USER_B_2A11';

// A dedicated evidence signing key, deliberately separate from the
// authorization/registry keys minted per run inside provenRun().
const EVIDENCE_KEYS = generateEd25519KeyPair();
const EVIDENCE_KEY_ID = 'evidence-signer-2026';
const SIGNING_KEY: EvidenceSigningKey = {
  privateKeyPem: EVIDENCE_KEYS.privateKeyPem,
  keyId: EVIDENCE_KEY_ID,
};
const EVIDENCE_TRUST: TrustStore = {
  schemaVersion: '3.0',
  keys: [{
    keyId: EVIDENCE_KEY_ID,
    algorithm: 'Ed25519',
    publicKeyPem: EVIDENCE_KEYS.publicKeyPem,
    status: 'active',
  }],
};

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
  twinId: 'evidence-fixture',
  principals: [
    { id: 'anonymous', tenantId: 'public', role: 'anonymous', headers: {} },
    { id: 'user-a', tenantId: 'tenant-a', role: 'user', headers: { authorization: 'Fixture user-a' } },
    { id: 'user-b', tenantId: 'tenant-b', role: 'user', headers: { authorization: 'Fixture user-b' } },
    { id: 'admin', tenantId: 'tenant-a', role: 'privileged', headers: { authorization: 'Fixture admin' } },
  ],
  assets: [
    { id: 'item-a', ownerPrincipalId: 'user-a', tenantId: 'tenant-a', classification: 'private', lifecycle: 'active', canary: CANARY_A },
    { id: 'item-b', ownerPrincipalId: 'user-b', tenantId: 'tenant-b', classification: 'private', lifecycle: 'active', canary: CANARY_B },
  ],
};

function fixtureFetch(vulnerable: boolean): typeof fetch {
  return (async (input: URL | RequestInfo): Promise<Response> => {
    const url = input instanceof URL
      ? input
      : new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      const canary = id === 'item-a' ? CANARY_A : CANARY_B;
      if (!vulnerable) return new Response('forbidden', { status: 403 });
      return Response.json({ id, canary });
    }
    return Response.json({ ok: true });
  }) as typeof fetch;
}

function bolaProgram(): CausalHttpAttackProgram {
  return {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-evidence',
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
      value: CANARY_A,
    },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2,
      minimumAttackSuccesses: 2,
    },
  };
}

async function provenRun(vulnerable = true): Promise<CausalRunResult> {
  const { privateKeyPem, trustStore } = testKeys();
  const twin = new AttackTwin(TWIN, new FixtureController());
  const program = bolaProgram();
  const profile = {
    ...targetProfile(),
    target: { ...targetProfile().target, name: 'evidence-fixture' },
  };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [
    httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] }),
  ]);
  const baseManifest = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...baseManifest.target, name: 'evidence-fixture', origins: ['http://203.0.113.10'] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...baseManifest.safety, allowedHosts: ['203.0.113.10'], allowedCanaryOrigins: [], allowMutations: false },
  });
  return runCausalHttpAttack(
    { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program, twin },
    {
      acknowledgeAuthorization: true,
      now: new Date('2026-07-23T00:00:00.000Z'),
      fetchImpl: fixtureFetch(vulnerable),
      resolver: { async resolve(): Promise<string[]> { return ['203.0.113.10']; } },
    },
  );
}

function bundleContent(bundle: EvidenceBundle): Record<string, unknown> {
  const clone = structuredClone(bundle) as Partial<EvidenceBundle>;
  delete clone.bundleDigest;
  delete clone.signature;
  return clone as Record<string, unknown>;
}

// Recompute the content digest and re-sign with the real evidence key, so a
// downstream check (witness chain, build binding) can be exercised in isolation
// from the content-digest guard that would otherwise fire first.
function reseal(bundle: EvidenceBundle): EvidenceBundle {
  const content = bundleContent(bundle);
  const withDigest = { ...content, bundleDigest: sha256Digest(content) };
  return {
    ...(withDigest as unknown as EvidenceBundle),
    signature: signDocument(withDigest, SIGNING_KEY.privateKeyPem, SIGNING_KEY.keyId),
  };
}

test('a signed evidence bundle round-trips through verification', async () => {
  const run = await provenRun();
  assert.equal(run.disposition, 'proven');
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY, new Date('2026-07-23T01:00:00.000Z'));
  const verified = verifyEvidenceBundle(bundle, EVIDENCE_TRUST);
  assert.equal(verified.bundleId, bundle.bundleId);
  assert.equal(verified.signature.algorithm, 'Ed25519');
  assert.equal(verified.signature.keyId, EVIDENCE_KEY_ID);
  assert.ok(verified.finding, 'a proven run must yield a finding');
});

test('raw before/after state never leaves the receipt, only digests and allowlisted diff', async () => {
  const run = await provenRun();
  const receipt = run.baseline as unknown as Record<string, unknown>;
  assert.ok(!('beforeState' in receipt), 'raw beforeState must not be persisted');
  assert.ok(!('afterState' in receipt), 'raw afterState must not be persisted');
  assert.match(run.baseline.beforeStateDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(run.baseline.afterStateDigest, /^sha256:[a-f0-9]{64}$/u);
  // A response-contains oracle has no state path, so the allowlisted diff is empty.
  assert.deepEqual(run.baseline.stateDiff, []);
});

test('tampering with a receipt event hash is rejected on verification', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  tampered.run.attacks[0]!.events[0]!.eventHash = `sha256:${'b'.repeat(64)}`;
  assert.throws(() => verifyEvidenceBundle(tampered, EVIDENCE_TRUST), /digest mismatch/u);
});

test('removing a receipt event breaks the witness chain', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  tampered.run.attacks[0]!.events.pop();
  assert.throws(() => verifyEvidenceBundle(reseal(tampered), EVIDENCE_TRUST), /Witness/u);
});

test('reordering receipt events breaks the witness chain', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  const events = tampered.run.baseline.events;
  assert.ok(events.length >= 2, 'baseline needs at least two events to reorder');
  [events[0], events[1]] = [events[1]!, events[0]!];
  assert.throws(() => verifyEvidenceBundle(reseal(tampered), EVIDENCE_TRUST), /Witness/u);
});

test('editing bundle content without resealing fails the content digest', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  tampered.finding!.severity = 'low';
  assert.throws(() => verifyEvidenceBundle(tampered, EVIDENCE_TRUST), /digest mismatch/u);
});

test('a content edit that recomputes the digest but cannot re-sign fails the signature', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  // Attacker edits content and recomputes bundleDigest but keeps the old signature.
  const forged = structuredClone(bundle);
  forged.registryDigest = `sha256:${'c'.repeat(64)}`;
  forged.bundleDigest = sha256Digest(bundleContent(forged));
  assert.throws(() => verifyEvidenceBundle(forged, EVIDENCE_TRUST), /signature is invalid/u);
});

test('a bundle whose stored redacted program no longer matches its digest is rejected', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  // Alter the stored (redacted) program but leave redactedProgramDigest stale;
  // reseal so the content digest and signature still pass and the dedicated
  // program-digest check is what fires.
  tampered.attackProgram.title = 'Altered program title';
  assert.throws(
    () => verifyEvidenceBundle(reseal(tampered), EVIDENCE_TRUST),
    /redacted program digest mismatch/u,
  );
});

test('a bundle signed by a revoked key is rejected', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const revoked: TrustStore = {
    ...EVIDENCE_TRUST,
    keys: EVIDENCE_TRUST.keys.map((key) => ({ ...key, status: 'revoked' as const })),
  };
  assert.throws(() => verifyEvidenceBundle(bundle, revoked), /revoked/u);
});

test('rendered Markdown contains no raw canary or credential token', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const markdown = renderEvidenceMarkdown(bundle, EVIDENCE_TRUST);
  assert.ok(!markdown.includes(CANARY_A), 'canary A must be redacted');
  assert.ok(!markdown.includes('Fixture user-a'), 'principal auth headers must not appear');
  assert.match(markdown, /Signature: `Ed25519`/u);
  assert.match(markdown, /no whole-target secure verdict/u);
});

test('pruning a bundle digests raw bodies, keeps it verifiable and replayable, and preserves the finding', async () => {
  const run = await provenRun();
  const bundle = createEvidenceBundle(run, bolaProgram(), SIGNING_KEY);
  const originalBody = bundle.run.attacks[0]!.observations[0]!.body;
  const findingId = bundle.finding!.findingId;

  const pruned = pruneEvidenceBundle(bundle, EVIDENCE_TRUST, SIGNING_KEY);
  assert.equal(pruned.retention.grade, 'redacted-only');
  assert.match(pruned.run.attacks[0]!.observations[0]!.body, /^sha256:/u);
  assert.notEqual(pruned.run.attacks[0]!.observations[0]!.body, originalBody);
  assert.equal(pruned.finding?.findingId, findingId);

  // Still verifiable and replayable after pruning.
  assert.doesNotThrow(() => verifyEvidenceBundle(pruned, EVIDENCE_TRUST));
  assert.equal(replayEvidenceBundle(pruned, EVIDENCE_TRUST).replayedDisposition, 'proven');
});

test('verifyFix reports fixed, utility-regression, and not-fixed verdicts', async () => {
  const original = await provenRun(true);
  const fixed = await provenRun(false);
  assert.equal(original.disposition, 'proven');
  assert.equal(fixed.disposition, 'rejected');

  assert.equal(verifyFix(original, fixed, true).verdict, 'fixed');
  assert.equal(verifyFix(original, fixed, false).verdict, 'utility-regression');
  assert.equal(verifyFix(original, original, true).verdict, 'not-fixed');
});

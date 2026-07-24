import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateCoverage } from '../src/coverage.js';
import { diffFindings } from '../src/diff.js';
import { generateEd25519KeyPair } from '../src/crypto.js';
import { discoverSurfaces } from '../src/discovery.js';
import { createEvidenceBundle, type EvidenceSigningKey } from '../src/evidence.js';
import { runCausalHttpAttack } from '../src/http-runner.js';
import { buildCampaignReport, renderReportMarkdown } from '../src/report.js';
import { AttackTwin, ConstantStateController } from '../src/twin.js';
import type { CandidateFinding, CausalHttpAttackProgram, CausalRunResult, TrustStore } from '../src/types.js';
import {
  httpPack, mappedPolicy, signedManifest, signedRegistry, targetProfile, testKeys,
} from './helpers.js';

const CANARY_A = 'CANARY_USER_A_7F4C';
const EK = generateEd25519KeyPair();
const SIGNING_KEY: EvidenceSigningKey = { privateKeyPem: EK.privateKeyPem, keyId: 'ev-report' };
const EV_TRUST: TrustStore = {
  schemaVersion: '3.0',
  keys: [{ keyId: 'ev-report', algorithm: 'Ed25519', publicKeyPem: EK.publicKeyPem, status: 'active' }],
};

const TWIN = {
  schemaVersion: '3.0' as const, kind: 'attack-twin' as const, twinId: 'report-fixture',
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
    schemaVersion: '3.0', kind: 'attack-program', id: 'bola-report', title: 'Cross-user read',
    principal: { id: 'user-b', kind: 'fixture-session' }, preconditions: ['x'],
    carrier: { protocol: 'http', entryPoint: '/items/{id}' }, source: { kind: 'fixture', reference: 'item-a' },
    capability: 'test:bola', mutation: { kind: 'identifier-swap', description: 'x' },
    forbiddenPredicate: { kind: 'cross-principal-data', expression: 'A canary reaches B' },
    oracle: { kind: 'response-contains', witness: 'http-gateway', requestId: 'attack-read', value: CANARY_A },
    execution: {
      baseline: { id: 'baseline', principalId: 'user-b', requests: [{ id: 'baseline-read', method: 'GET', path: '/items/item-b' }] },
      attack: { id: 'attack', principalId: 'user-b', requests: [{ id: 'attack-read', method: 'GET', path: '/items/item-a' }] },
      counterfactual: { id: 'counterfactual', principalId: 'user-b', requests: [{ id: 'counter-read', method: 'GET', path: '/items/item-b' }] },
      repetitions: 2, minimumAttackSuccesses: 2,
    },
  };
}

function fetchImpl(vulnerable: boolean): typeof fetch {
  return (async (input: URL | RequestInfo) => {
    const url = input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      if (!vulnerable) return new Response('forbidden', { status: 403 });
      return Response.json({ id, canary: id === 'item-a' ? CANARY_A : 'CANARY_USER_B_2A11' });
    }
    return Response.json({ ok: true });
  }) as typeof fetch;
}

function coverageAndRegistry() {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = { ...targetProfile(), target: { ...targetProfile().target, name: 'report-fixture' } };
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem, [httpPack({ id: 'test:bola-pack', capabilities: ['test:bola'] })]);
  return { privateKeyPem, trustStore, profile, inventory, registry };
}

async function run(vulnerable: boolean): Promise<CausalRunResult> {
  const { privateKeyPem, trustStore, profile, inventory, registry } = coverageAndRegistry();
  const base = signedManifest(privateKeyPem);
  const manifest = signedManifest(privateKeyPem, {
    target: { ...base.target, name: 'report-fixture', origins: ['http://203.0.113.10'] },
    capabilities: ['discover', 'run:project', 'test:bola'],
    safety: { ...base.safety, allowedHosts: ['203.0.113.10'], allowedCanaryOrigins: [], allowMutations: false },
  });
  return runCausalHttpAttack(
    { manifest, trustStore, profile, inventory, registry, policy: mappedPolicy(), program: bolaProgram(), twin: new AttackTwin(TWIN, new ConstantStateController()) },
    { acknowledgeAuthorization: true, now: new Date('2026-07-24T00:00:00.000Z'), fetchImpl: fetchImpl(vulnerable), resolver: { async resolve() { return ['203.0.113.10']; } } },
  );
}

test('campaign report separates finding states, keeps coverage first, and never claims secure', async () => {
  const { trustStore, profile, inventory, registry } = coverageAndRegistry();
  const coverage = evaluateCoverage(inventory, profile, registry, trustStore, mappedPolicy());

  const provenBundle = createEvidenceBundle(await run(true), bolaProgram(), SIGNING_KEY);
  const rejectedBundle = createEvidenceBundle(await run(false), bolaProgram(), SIGNING_KEY);
  const candidate: CandidateFinding = {
    schemaVersion: '3.0', state: 'candidate', candidateId: 'cand-1', surfaceId: 'surface-x',
    family: 'mass-assignment', rationale: 'unbound property observed in source', provenance: 'static', confidence: 'low',
  };

  const report = buildCampaignReport(coverage, [provenBundle, rejectedBundle], [candidate], EV_TRUST);
  assert.equal(report.secureVerdict, false);
  assert.equal(report.findings.proven.length, 1);
  assert.equal(report.findings.rejected.length, 1);
  assert.equal(report.findings.candidate.length, 1);
  assert.equal(report.bundleRefs.length, 2);
  assert.ok(report.findings.proven[0]!.lineageId.startsWith('lineage-'));
  assert.ok(report.coverage.ledger.length > 0);

  const md = renderReportMarkdown(report);
  assert.ok(!md.includes(CANARY_A), 'no raw canary in report');
  assert.match(md, /secure verdict: none/u);
  assert.match(md, /## Coverage ledger/u);
  assert.match(md, /## Candidates/u);
});

test('finding lineage diff tracks introduced, resolved, and persisted findings across builds', async () => {
  const { trustStore, profile, inventory, registry } = coverageAndRegistry();
  const coverage = evaluateCoverage(inventory, profile, registry, trustStore, mappedPolicy());
  const provenBundle = createEvidenceBundle(await run(true), bolaProgram(), SIGNING_KEY);
  const rejectedBundle = createEvidenceBundle(await run(false), bolaProgram(), SIGNING_KEY);

  // "from" build has the finding proven; "to" build resolved it (only rejected run).
  const fromReport = buildCampaignReport(coverage, [provenBundle], [], EV_TRUST);
  const toReport = buildCampaignReport(coverage, [rejectedBundle], [], EV_TRUST);
  const lineageId = fromReport.findings.proven[0]!.lineageId;

  const resolvedDiff = diffFindings(fromReport, toReport);
  assert.deepEqual(resolvedDiff.resolved, [lineageId]);
  assert.deepEqual(resolvedDiff.introduced, []);
  assert.deepEqual(resolvedDiff.persisted, []);

  // Same finding present in both builds → persisted.
  const persistedDiff = diffFindings(fromReport, fromReport);
  assert.deepEqual(persistedDiff.persisted, [lineageId]);
  assert.deepEqual(persistedDiff.introduced, []);
  assert.deepEqual(persistedDiff.resolved, []);
});

test('report rejects a tampered bundle before classifying it', async () => {
  const { trustStore, profile, inventory, registry } = coverageAndRegistry();
  const coverage = evaluateCoverage(inventory, profile, registry, trustStore, mappedPolicy());
  const bundle = createEvidenceBundle(await run(true), bolaProgram(), SIGNING_KEY);
  const tampered = structuredClone(bundle);
  tampered.finding!.severity = 'low';
  assert.throws(() => buildCampaignReport(coverage, [tampered], [], EV_TRUST), /digest mismatch/u);
});

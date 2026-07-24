import { randomUUID } from 'node:crypto';
import {
  sha256Digest,
  signDocument,
  verifyDocumentSignature,
} from './crypto.js';
import { replayDisposition } from './disposition.js';
import { SpearConfigError, SpearExecutionError } from './errors.js';
import { assertNoRawSecrets } from './safety.js';
import type {
  CausalHttpAttackProgram,
  CausalRunResult,
  EvidenceBundle,
  FixVerification,
  ProvenFinding,
  TrustStore,
  UnsignedEvidenceBundle,
  WitnessEvent,
} from './types.js';
import { validateTrustStore } from './validation.js';
import { verifyReceiptChain } from './witness.js';

export interface EvidenceSigningKey {
  privateKeyPem: string;
  keyId: string;
}

function allEvents(run: CausalRunResult): WitnessEvent[] {
  return [
    ...run.baseline.events,
    ...run.attacks.flatMap((receipt) => receipt.events),
    ...run.counterfactual.events,
  ];
}

function sanitizedProgram(
  program: CausalHttpAttackProgram,
): CausalHttpAttackProgram {
  const clone = structuredClone(program);
  // Tokens that must not survive anywhere in the stored program (oracle config
  // AND the attack payloads that carry them, e.g. a probe URL in a request body).
  const tokens: string[] = [];
  if (clone.oracle.kind === 'response-contains') {
    clone.oracle.value = '[CANARY]';
  }
  if (clone.oracle.kind === 'canary-egress') {
    tokens.push(clone.oracle.canary);
    clone.oracle.canary = '[CANARY]';
  }
  for (const sequence of [
    clone.execution.baseline,
    clone.execution.attack,
    clone.execution.counterfactual,
  ]) {
    for (const request of sequence.requests) {
      if (request.headers) {
        for (const name of Object.keys(request.headers)) {
          if (['authorization', 'cookie', 'x-api-key'].includes(name.toLowerCase())) {
            request.headers[name] = '[REDACTED]';
          }
        }
      }
      for (const token of tokens) {
        if (!token) continue;
        request.path = request.path.split(token).join('[CANARY]');
        if (request.body !== undefined) request.body = request.body.split(token).join('[CANARY]');
      }
    }
  }
  return clone;
}

function severity(program: CausalHttpAttackProgram): Pick<
  ProvenFinding,
  'severity' | 'severityRationale'
> {
  if (program.forbiddenPredicate.kind.includes('cross-tenant')) {
    return {
      severity: 'critical',
      severityRationale: 'Reproducible cross-tenant forbidden state or data flow',
    };
  }
  if (
    program.forbiddenPredicate.kind.includes('state')
    || program.forbiddenPredicate.kind.includes('cross-principal')
  ) {
    return {
      severity: 'high',
      severityRationale: 'Reproducible unauthorized state change or cross-principal data flow',
    };
  }
  return {
    severity: 'medium',
    severityRationale: 'Reproducible forbidden predicate in an authorized disposable fixture',
  };
}

function findingFor(
  run: CausalRunResult,
  program: CausalHttpAttackProgram,
  minimizedGraphPath?: string[],
): ProvenFinding | undefined {
  if (run.disposition !== 'proven') return undefined;
  const severityResult = severity(program);
  const lineageId = `lineage-${sha256Digest({
    programId: program.id,
    predicate: program.forbiddenPredicate,
  }).slice(7, 23)}`;
  return {
    schemaVersion: '3.0',
    findingId: `finding-${sha256Digest({
      programId: program.id,
      buildDigest: run.targetBuildDigest,
      predicate: program.forbiddenPredicate,
    }).slice(7, 23)}`,
    lineageId,
    state: 'proven',
    title: program.title,
    severity: severityResult.severity,
    severityRationale: severityResult.severityRationale,
    affectedBuildDigest: run.targetBuildDigest,
    attackPreconditions: program.preconditions,
    forbiddenPredicate: program.forbiddenPredicate.expression,
    reproduction: {
      successes: run.attackSuccesses,
      attempts: run.attempts,
    },
    reproductionRate: run.attempts > 0 ? run.attackSuccesses / run.attempts : 0,
    minimizedGraphPath: minimizedGraphPath ?? [program.carrier.entryPoint],
    remediationHypothesis:
      'Bind authorization to the authenticated principal, tenant, object, operation, and current state before applying the effect.',
  };
}

function bundleContent(
  bundle: UnsignedEvidenceBundle | EvidenceBundle,
): Omit<UnsignedEvidenceBundle, 'bundleDigest'> {
  const clone = structuredClone(bundle) as Partial<EvidenceBundle>;
  delete clone.bundleDigest;
  delete clone.signature;
  return clone as Omit<UnsignedEvidenceBundle, 'bundleDigest'>;
}

export const DEFAULT_RETENTION_DAYS = 30;

export function createEvidenceBundle(
  run: CausalRunResult,
  program: CausalHttpAttackProgram,
  signingKey: EvidenceSigningKey,
  now = new Date(),
  minimizedGraphPath?: string[],
  retentionDays = DEFAULT_RETENTION_DAYS,
): EvidenceBundle {
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) {
    throw new SpearExecutionError('retentionDays must be a positive number');
  }
  verifyReceiptChain(allEvents(run));
  const safeProgram = sanitizedProgram(program);
  const finding = findingFor(run, program, minimizedGraphPath);
  const content: Omit<UnsignedEvidenceBundle, 'bundleDigest'> = {
    schemaVersion: '3.0',
    kind: 'evidence-bundle',
    bundleId: `bundle-${randomUUID()}`,
    createdAt: now.toISOString(),
    authorization: {
      manifestDigest: run.manifestDigest,
      buildDigest: run.targetBuildDigest,
    },
    registryDigest: run.registryDigest,
    snapshotDigest: run.baseline.beforeStateDigest,
    // attackProgramDigest seals the ORIGINAL (unredacted) program for matching
    // against an out-of-band copy; redactedProgramDigest lets a verifier confirm
    // the redacted program actually stored in this bundle has not been altered.
    attackProgramDigest: sha256Digest(program),
    redactedProgramDigest: sha256Digest(safeProgram),
    attackProgram: safeProgram,
    run,
    ...(finding ? { finding } : {}),
    replayCommand: 'spear replay --bundle <bundle.json> --trust-store <file>',
    redactionManifest: [
      { field: 'attackProgram.oracle.value', action: 'replaced' },
      { field: 'attackProgram.oracle.canary + payloads carrying it', action: 'replaced' },
      { field: 'run.*.observations.body canaries', action: 'replaced' },
      { field: 'request authorization/cookie headers', action: 'removed' },
      { field: 'run.*.beforeState/afterState raw snapshots', action: 'digested' },
      { field: 'raw witness payloads', action: 'digested' },
    ],
    retention: {
      // Redacted response bodies expire after the retention window; replay uses
      // only the sealed predicate flags, so a pruned bundle still verifies and
      // replays. `spear evidence prune --if-expired` enforces this window.
      rawExpiresAt: new Date(now.getTime() + retentionDays * 24 * 60 * 60 * 1000).toISOString(),
      grade: 'full',
    },
  };
  return sealBundle(content, signingKey);
}

function sealBundle(
  content: Omit<UnsignedEvidenceBundle, 'bundleDigest'>,
  signingKey: EvidenceSigningKey,
): EvidenceBundle {
  const unsigned: UnsignedEvidenceBundle = { ...content, bundleDigest: sha256Digest(content) };
  const bundle: EvidenceBundle = {
    ...unsigned,
    signature: signDocument(
      unsigned as unknown as Record<string, unknown>,
      signingKey.privateKeyPem,
      signingKey.keyId,
    ),
  };
  assertNoRawSecrets(bundle);
  return bundle;
}

/**
 * Enforce raw-artifact retention (FR-804 / AC-802): replace each observation body
 * with its digest, downgrade the bundle to `redacted-only`, and re-seal. The
 * bundle still verifies and replays because replay uses the sealed predicate
 * flags, not the raw bodies. Finding ID and lineage are preserved.
 */
/**
 * Whether a bundle still holds raw (redactable) artifacts and its retention
 * window has elapsed as of `now` — i.e. `prune --if-expired` should act.
 */
export function retentionDue(bundle: EvidenceBundle, now = new Date()): boolean {
  return bundle.retention.grade === 'full'
    && Date.parse(bundle.retention.rawExpiresAt) <= now.getTime();
}

export function pruneEvidenceBundle(
  value: unknown,
  trustStore: unknown,
  signingKey: EvidenceSigningKey,
): EvidenceBundle {
  const bundle = verifyEvidenceBundle(value, trustStore);
  // Idempotent: a redacted-only bundle has no raw bodies left to digest, so
  // re-pruning would only double-digest already-digested values.
  if (bundle.retention.grade === 'redacted-only') return bundle;
  const pruned = structuredClone(bundle) as Partial<EvidenceBundle> & { run: EvidenceBundle['run'] };
  const digestBody = (receipt: EvidenceBundle['run']['baseline']): void => {
    for (const observation of receipt.observations) {
      observation.body = sha256Digest(observation.body);
    }
  };
  digestBody(pruned.run.baseline);
  pruned.run.attacks.forEach(digestBody);
  digestBody(pruned.run.counterfactual);
  pruned.retention = { rawExpiresAt: bundle.retention.rawExpiresAt, grade: 'redacted-only' };
  delete pruned.bundleDigest;
  delete pruned.signature;
  return sealBundle(pruned as Omit<UnsignedEvidenceBundle, 'bundleDigest'>, signingKey);
}

export function verifyEvidenceBundle(value: unknown, trustStore: unknown): EvidenceBundle {
  if (
    typeof value !== 'object'
    || value === null
    || (value as { schemaVersion?: unknown }).schemaVersion !== '3.0'
    || (value as { kind?: unknown }).kind !== 'evidence-bundle'
  ) {
    throw new SpearConfigError('Evidence bundle must use SPEAR v3');
  }
  const store: TrustStore = validateTrustStore(trustStore);
  const bundle = value as EvidenceBundle;
  const actualDigest = sha256Digest(bundleContent(bundle));
  if (actualDigest !== bundle.bundleDigest) {
    throw new SpearExecutionError('Evidence bundle digest mismatch');
  }
  if (!bundle.signature || typeof bundle.signature !== 'object') {
    throw new SpearExecutionError('Evidence bundle is missing an Ed25519 signature');
  }
  verifyDocumentSignature(
    bundle as unknown as Record<string, unknown>,
    bundle.signature,
    store,
  );
  verifyReceiptChain(allEvents(bundle.run));
  if (bundle.authorization.buildDigest !== bundle.run.targetBuildDigest) {
    throw new SpearExecutionError('Evidence bundle build digest mismatch');
  }
  if (sha256Digest(bundle.attackProgram) !== bundle.redactedProgramDigest) {
    throw new SpearExecutionError('Evidence bundle redacted program digest mismatch');
  }
  assertNoRawSecrets(bundle);
  return bundle;
}

export interface EvidenceReplay {
  schemaVersion: '3.0';
  kind: 'evidence-replay';
  bundleId: string;
  recordedDisposition: CausalRunResult['disposition'];
  replayedDisposition: CausalRunResult['disposition'];
  attackSuccesses: number;
  attempts: number;
  consistent: true;
}

/**
 * Verify a sealed bundle and deterministically re-derive its verdict from the
 * stored receipts, confirming the recorded disposition and counters were not
 * tampered with. Offline: it re-checks the verdict arithmetic against the sealed
 * `predicateObserved` flags, it does not re-attack the target.
 */
export function replayEvidenceBundle(value: unknown, trustStore: unknown): EvidenceReplay {
  const bundle = verifyEvidenceBundle(value, trustStore);
  if (bundle.run.programId !== bundle.attackProgram.id) {
    throw new SpearExecutionError('Evidence bundle program identity mismatch');
  }
  // An `error` run reached no verdict, so there is no arithmetic to replay; the
  // integrity checks above are the whole guarantee.
  if (bundle.run.disposition === 'error') {
    return {
      schemaVersion: '3.0',
      kind: 'evidence-replay',
      bundleId: bundle.bundleId,
      recordedDisposition: 'error',
      replayedDisposition: 'error',
      attackSuccesses: bundle.run.attackSuccesses,
      attempts: bundle.run.attempts,
      consistent: true,
    };
  }
  const outcome = replayDisposition(
    bundle.run,
    bundle.attackProgram.execution.minimumAttackSuccesses,
  );
  if (
    outcome.disposition !== bundle.run.disposition
    || outcome.attackSuccesses !== bundle.run.attackSuccesses
    || outcome.attempts !== bundle.run.attempts
  ) {
    throw new SpearExecutionError(
      `Evidence replay mismatch: recorded ${bundle.run.disposition} `
      + `(${bundle.run.attackSuccesses}/${bundle.run.attempts}) but receipts replay to `
      + `${outcome.disposition} (${outcome.attackSuccesses}/${outcome.attempts})`,
    );
  }
  return {
    schemaVersion: '3.0',
    kind: 'evidence-replay',
    bundleId: bundle.bundleId,
    recordedDisposition: bundle.run.disposition,
    replayedDisposition: outcome.disposition,
    attackSuccesses: outcome.attackSuccesses,
    attempts: outcome.attempts,
    consistent: true,
  };
}

export function renderEvidenceMarkdown(bundleInput: unknown, trustStore: unknown): string {
  const bundle = verifyEvidenceBundle(bundleInput, trustStore);
  const finding = bundle.finding;
  const lines = [
    '# SPEAR Evidence',
    '',
    `- Run: \`${bundle.run.runId}\``,
    `- Build: \`${bundle.authorization.buildDigest}\``,
    `- Disposition: \`${bundle.run.disposition}\``,
    `- Reproduction: ${bundle.run.attackSuccesses}/${bundle.run.attempts}`,
    `- Coverage claim: no whole-target secure verdict`,
  ];
  if (finding) {
    lines.push(
      '',
      `## ${finding.title}`,
      '',
      `- Finding ID: \`${finding.findingId}\``,
      `- Severity: \`${finding.severity}\` — ${finding.severityRationale}`,
      `- Forbidden predicate: ${finding.forbiddenPredicate}`,
      `- Remediation hypothesis: ${finding.remediationHypothesis}`,
    );
  } else {
    lines.push('', 'No proven finding was produced by this causal replay.');
  }
  lines.push(
    '',
    '## Evidence integrity',
    '',
    `- Bundle digest: \`${bundle.bundleDigest}\``,
    `- Signature: \`${bundle.signature.algorithm}\` by key \`${bundle.signature.keyId}\``,
    `- Manifest digest: \`${bundle.authorization.manifestDigest}\``,
    `- Registry digest: \`${bundle.registryDigest}\``,
    `- Snapshot digest: \`${bundle.snapshotDigest}\``,
  );
  return `${lines.join('\n')}\n`;
}

export function verifyFix(
  original: CausalRunResult,
  fixed: CausalRunResult,
  benignUtilityPassed: boolean,
): FixVerification {
  if (original.programId !== fixed.programId) {
    return {
      schemaVersion: '3.0',
      kind: 'fix-verification',
      originalRunId: original.runId,
      fixedRunId: fixed.runId,
      verdict: 'not-verifiable',
      reason: 'Runs use different attack programs',
    };
  }
  if (!benignUtilityPassed) {
    return {
      schemaVersion: '3.0',
      kind: 'fix-verification',
      originalRunId: original.runId,
      fixedRunId: fixed.runId,
      verdict: 'utility-regression',
      reason: 'Attack predicate disappeared but the benign utility check failed',
    };
  }
  if (original.disposition !== 'proven') {
    return {
      schemaVersion: '3.0',
      kind: 'fix-verification',
      originalRunId: original.runId,
      fixedRunId: fixed.runId,
      verdict: 'not-verifiable',
      reason: 'Original run did not contain a proven predicate',
    };
  }
  return fixed.disposition === 'rejected'
    ? {
      schemaVersion: '3.0',
      kind: 'fix-verification',
      originalRunId: original.runId,
      fixedRunId: fixed.runId,
      verdict: 'fixed',
      reason: 'Attack predicate disappeared and benign utility remained available',
    }
    : {
      schemaVersion: '3.0',
      kind: 'fix-verification',
      originalRunId: original.runId,
      fixedRunId: fixed.runId,
      verdict: 'not-fixed',
      reason: 'Attack predicate still reproduces or remains flaky',
    };
}

import { randomUUID } from 'node:crypto';
import { sha256Digest, signDocument, verifyDocumentSignature } from '../crypto.js';
import { SpearConfigError, SpearExecutionError } from '../errors.js';
import type { EvidenceSigningKey } from '../evidence.js';
import { assertNoRawSecrets } from '../safety.js';
import type { TrustStore } from '../types.js';
import { validateTrustStore } from '../validation.js';
import type { AgentAttackProgram, AgentRunResult } from './types.js';

export interface AgentEvidenceBundle {
  schemaVersion: '3.0';
  kind: 'agent-evidence-bundle';
  bundleId: string;
  createdAt: string;
  /** Digest of the ORIGINAL program (canary intact) for out-of-band matching. */
  programDigest: string;
  /** Digest of the redacted program actually stored below. */
  redactedProgramDigest: string;
  program: AgentAttackProgram;
  run: AgentRunResult;
  disposition: AgentRunResult['disposition'];
  replayCommand: string;
  bundleDigest: string;
  signature: { algorithm: 'Ed25519'; keyId: string; value: string };
}

const SECRET_HEADERS = new Set(['authorization', 'cookie', 'x-api-key', 'api-key']);

function redactProgram(program: AgentAttackProgram): AgentAttackProgram {
  const clone = structuredClone(program);
  const tokens = [
    'canary' in clone.oracle ? clone.oracle.canary : '',
    clone.planted.canary,
  ].filter(Boolean);
  const scrub = (text: string): string =>
    tokens.reduce((acc, token) => acc.split(token).join('[CANARY]'), text);
  if ('canary' in clone.oracle) clone.oracle.canary = '[CANARY]';
  clone.planted.canary = '[CANARY]';
  clone.baseline.message = scrub(clone.baseline.message);
  clone.attack.message = scrub(clone.attack.message);
  clone.counterfactual.message = scrub(clone.counterfactual.message);
  // Provider auth (API keys/session cookies) must never enter a stored bundle.
  const scrubHeaders = (headers?: Record<string, string>): void => {
    if (!headers) return;
    for (const name of Object.keys(headers)) {
      if (SECRET_HEADERS.has(name.toLowerCase())) headers[name] = '[REDACTED]';
    }
  };
  scrubHeaders(clone.target.headers);
  if (clone.projectOnly) {
    clone.projectOnly.request.url = scrub(clone.projectOnly.request.url);
    if (clone.projectOnly.request.body !== undefined) {
      clone.projectOnly.request.body = scrub(clone.projectOnly.request.body);
    }
    scrubHeaders(clone.projectOnly.request.headers);
  }
  if (clone.carrier) {
    // The malicious carrier content is the injection payload; scrub any canary it
    // embeds (the benign content is inert and kept for the counterfactual record).
    clone.carrier.maliciousContent = scrub(clone.carrier.maliciousContent);
  }
  return clone;
}

function contentDigest(bundle: Omit<AgentEvidenceBundle, 'bundleDigest' | 'signature'>): string {
  return sha256Digest(bundle);
}

/**
 * Seal an agent run into a signed, canary-redacted evidence bundle. The raw canary
 * never enters the stored program or run (the run is already redacted); the
 * original program digest is kept only for out-of-band matching.
 */
export function signAgentEvidence(
  run: AgentRunResult,
  program: AgentAttackProgram,
  signingKey: EvidenceSigningKey,
  now = new Date(),
): AgentEvidenceBundle {
  if (run.programId !== program.id) {
    throw new SpearConfigError('Agent run and program identity mismatch');
  }
  const redacted = redactProgram(program);
  const content: Omit<AgentEvidenceBundle, 'bundleDigest' | 'signature'> = {
    schemaVersion: '3.0',
    kind: 'agent-evidence-bundle',
    bundleId: `agent-bundle-${randomUUID()}`,
    createdAt: now.toISOString(),
    programDigest: sha256Digest(program),
    redactedProgramDigest: sha256Digest(redacted),
    program: redacted,
    run,
    disposition: run.disposition,
    replayCommand: 'spear evidence verify --bundle <bundle.json> --trust-store <file>',
  };
  const bundleDigest = contentDigest(content);
  const unsigned = { ...content, bundleDigest };
  const signature = signDocument(
    unsigned as unknown as Record<string, unknown>,
    signingKey.privateKeyPem,
    signingKey.keyId,
  );
  const bundle: AgentEvidenceBundle = { ...unsigned, signature };
  assertNoRawSecrets(bundle);
  return bundle;
}

/** Verify an agent evidence bundle's digest, signature, and redaction integrity. */
export function verifyAgentEvidence(value: unknown, trustStore: unknown): AgentEvidenceBundle {
  if (
    typeof value !== 'object'
    || value === null
    || (value as { schemaVersion?: unknown }).schemaVersion !== '3.0'
    || (value as { kind?: unknown }).kind !== 'agent-evidence-bundle'
  ) {
    throw new SpearConfigError('Agent evidence bundle must use SPEAR v3');
  }
  const store: TrustStore = validateTrustStore(trustStore);
  const bundle = value as AgentEvidenceBundle;
  const { bundleDigest: _bundleDigest, signature: _signature, ...content } = bundle;
  if (contentDigest(content) !== bundle.bundleDigest) {
    throw new SpearExecutionError('Agent evidence bundle digest mismatch');
  }
  if (!bundle.signature || typeof bundle.signature !== 'object') {
    throw new SpearExecutionError('Agent evidence bundle is missing an Ed25519 signature');
  }
  verifyDocumentSignature(bundle as unknown as Record<string, unknown>, bundle.signature, store);
  if (sha256Digest(bundle.program) !== bundle.redactedProgramDigest) {
    throw new SpearExecutionError('Agent evidence bundle redacted program digest mismatch');
  }
  assertNoRawSecrets(bundle);
  return bundle;
}

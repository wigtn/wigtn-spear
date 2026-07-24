import { randomUUID } from 'node:crypto';
import { verifyAuthorization } from './authorization.js';
import { evaluateCoverage } from './coverage.js';
import { SpearSafetyError } from './errors.js';
import type {
  RunPreview,
  TargetProfile,
} from './types.js';
import { validateTargetProfile } from './validation.js';

export interface PreviewOptions {
  acknowledgeAuthorization: boolean;
  requiredCapabilities: string[];
  now?: Date;
}

export function prepareRunPreview(
  manifestInput: unknown,
  trustStoreInput: unknown,
  profileInput: unknown,
  inventoryInput: unknown,
  registryInput: unknown,
  policyInput: unknown,
  options: PreviewOptions,
): RunPreview {
  const profile: TargetProfile = validateTargetProfile(profileInput);
  const authorization = verifyAuthorization(manifestInput, trustStoreInput, {
    acknowledgeAuthorization: options.acknowledgeAuthorization,
    requiredCapabilities: options.requiredCapabilities,
    actualBuildDigest: profile.target.buildDigest,
    ...(options.now ? { now: options.now } : {}),
  });
  if (authorization.manifest.target.name !== profile.target.name) {
    throw new SpearSafetyError(
      `Target name mismatch: authorized ${authorization.manifest.target.name}, actual ${profile.target.name}`,
    );
  }
  const coverage = evaluateCoverage(
    inventoryInput,
    profile,
    registryInput,
    trustStoreInput,
    policyInput,
    options.now ?? new Date(),
  );
  if (coverage.target.buildDigest !== profile.target.buildDigest) {
    throw new SpearSafetyError('Coverage report is stale for the current target build');
  }

  const selectedPackIds = [
    ...new Set(coverage.ledger.flatMap((item) => item.applicablePackIds)),
  ].sort();
  const selectedHighRisk = selectedPackIds.filter(
    (id) => coverage.packSafetyClasses[id] === 'high-risk',
  );
  if (
    selectedHighRisk.length > 0
    && (
      !authorization.manifest.safety.twinAttested
      || authorization.manifest.target.environment !== 'disposable'
    )
  ) {
    throw new SpearSafetyError(
      'High-risk packs require a disposable environment and containment Twin attestation',
    );
  }

  const now = options.now ?? new Date();
  return {
    schemaVersion: '3.0',
    kind: 'run-preview',
    runId: `preview-${randomUUID()}`,
    generatedAt: now.toISOString(),
    target: profile.target,
    authorization: {
      engagementId: authorization.manifest.engagement.id,
      manifestDigest: authorization.manifestDigest,
      buildDigest: profile.target.buildDigest,
      capabilities: options.requiredCapabilities,
    },
    registryDigest: coverage.registryDigest,
    selectedPackIds,
    safety: authorization.manifest.safety,
    coverageVerdict: coverage.verdict,
    mutationsEnabled: false,
    targetEvents: 0,
  };
}

import type {
  CoveragePolicy,
  CoverageReport,
  EvidenceGrade,
  PackManifest,
  SurfaceCoverage,
  SurfaceInventory,
  TargetProfile,
} from './types.js';
import { packSupportsTarget, verifyPackRegistry } from './registry.js';
import { SpearConfigError } from './errors.js';
import {
  validateCoveragePolicy,
  validateSurfaceInventory,
  validateTargetProfile,
  validateTrustStore,
} from './validation.js';

const EVIDENCE_RANK: Record<EvidenceGrade, number> = {
  inventory: 0,
  mapped: 1,
  exercised: 2,
  witnessed: 3,
  causal: 4,
};

function packApplies(
  pack: PackManifest,
  coverage: Pick<SurfaceCoverage, 'surface'>,
  profile: TargetProfile,
  policy: CoveragePolicy,
): boolean {
  if (!pack.applicableProtocols.includes(coverage.surface.protocol)) return false;
  if (!packSupportsTarget(pack, profile.target.version)) return false;
  if (!policy.allowedSafetyClasses.includes(pack.safetyClass)) return false;
  return coverage.surface.applicablePacks.length === 0
    || coverage.surface.applicablePacks.includes(pack.id);
}

export function evaluateCoverage(
  inventoryInput: unknown,
  profileInput: unknown,
  registryInput: unknown,
  trustStoreInput: unknown,
  policyInput: unknown,
  now = new Date(),
): CoverageReport {
  const inventory = validateSurfaceInventory(inventoryInput);
  const profile = validateTargetProfile(profileInput);
  const policy = validateCoveragePolicy(policyInput);
  validateTrustStore(trustStoreInput);
  const verifiedRegistry = verifyPackRegistry(registryInput, trustStoreInput);
  const unmet = new Set<string>();

  if (
    inventory.target.name !== profile.target.name
    || inventory.target.version !== profile.target.version
    || inventory.target.buildDigest !== profile.target.buildDigest
  ) {
    throw new SpearConfigError('Surface inventory is stale or belongs to a different target');
  }

  const ledger: SurfaceCoverage[] = inventory.surfaces.map((surface) => {
    const seed: SurfaceCoverage = {
      surface,
      state: 'mapped',
      evidenceGrade: 'mapped',
      applicablePackIds: [],
      missingWitnesses: [],
      reasons: [],
    };
    const packs = verifiedRegistry.registry.packs.filter(
      (pack) => packApplies(pack, seed, profile, policy),
    );
    if (packs.length === 0) {
      seed.state = 'unsupported';
      seed.reasons.push('No compatible, policy-allowed pack exists for this surface');
      unmet.add(`Surface ${surface.id} has no compatible pack`);
      return seed;
    }

    seed.applicablePackIds = packs.map((pack) => pack.id).sort();
    seed.missingWitnesses = [
      ...new Set(
        packs
          .flatMap((pack) => pack.requiredWitnesses)
          .filter((witness) => !profile.availableWitnesses.includes(witness)),
      ),
    ].sort();
    if (seed.missingWitnesses.length > 0) {
      seed.state = 'blocked';
      seed.reasons.push(`Missing witnesses: ${seed.missingWitnesses.join(', ')}`);
      unmet.add(`Surface ${surface.id} is missing required witnesses`);
      return seed;
    }
    seed.state = 'attackable';
    seed.reasons.push('Compatible pack and required witnesses are ready; no attack was executed');
    return seed;
  });

  for (const protocol of policy.requiredProtocols) {
    if (!ledger.some((item) => item.surface.protocol === protocol)) {
      unmet.add(`Required protocol is absent: ${protocol}`);
    }
  }
  for (const surfaceId of policy.requiredSurfaceIds) {
    if (!ledger.some((item) => item.surface.id === surfaceId)) {
      unmet.add(`Required surface is absent: ${surfaceId}`);
    }
  }
  for (const witness of policy.requiredWitnesses) {
    if (!profile.availableWitnesses.includes(witness)) {
      unmet.add(`Policy-required witness is unavailable: ${witness}`);
    }
  }
  for (const item of ledger) {
    const requiredByPolicy = policy.requiredSurfaceIds.includes(item.surface.id)
      || policy.requiredProtocols.includes(item.surface.protocol);
    if (
      requiredByPolicy
      && EVIDENCE_RANK[item.evidenceGrade] < EVIDENCE_RANK[policy.minimumEvidenceGrade]
    ) {
      unmet.add(
        `Surface ${item.surface.id} evidence ${item.evidenceGrade} is below ${policy.minimumEvidenceGrade}`,
      );
    }
  }

  const blindSpots = [
    ...inventory.blindSpots,
    ...ledger
      .filter((item) => item.state === 'unsupported' || item.state === 'blocked')
      .map((item) => ({
        id: `blind-coverage-${item.surface.id}`,
        surfaceId: item.surface.id,
        reason: item.reasons.join('; '),
      })),
  ];

  return {
    schemaVersion: '3.0',
    kind: 'coverage-report',
    target: profile.target,
    generatedAt: now.toISOString(),
    verdict: unmet.size === 0 ? 'coverage-complete' : 'coverage-incomplete',
    policy,
    registryDigest: verifiedRegistry.registryDigest,
    packVersions: Object.fromEntries(
      verifiedRegistry.registry.packs.map((pack) => [pack.id, pack.version]),
    ),
    packSafetyClasses: Object.fromEntries(
      verifiedRegistry.registry.packs.map((pack) => [pack.id, pack.safetyClass]),
    ),
    ledger,
    blindSpots,
    unmetRequirements: [...unmet].sort(),
  };
}

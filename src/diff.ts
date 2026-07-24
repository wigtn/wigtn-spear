import { SpearConfigError } from './errors.js';
import type {
  CampaignReport,
  CoverageDiff,
  CoverageReport,
} from './types.js';
import { isRecord } from './utils.js';

export interface FindingDiff {
  schemaVersion: '3.0';
  kind: 'finding-diff';
  fromBuildDigest: string;
  toBuildDigest: string;
  introduced: string[];
  resolved: string[];
  persisted: string[];
}

function provenLineage(report: unknown, context: string): { build: string; lineage: Set<string> } {
  if (!isRecord(report) || report.kind !== 'campaign-report') {
    throw new SpearConfigError(`${context} must be a SPEAR v3 campaign-report`);
  }
  const campaign = report as unknown as CampaignReport;
  return {
    build: campaign.target.buildDigest,
    lineage: new Set(campaign.findings.proven.map((finding) => finding.lineageId)),
  };
}

/**
 * Track proven findings across builds by their build-independent lineage ID
 * (FR-908): introduced only in `to`, resolved only in `from`, persisted in both.
 */
export function diffFindings(fromInput: unknown, toInput: unknown): FindingDiff {
  const from = provenLineage(fromInput, 'diff --findings from');
  const to = provenLineage(toInput, 'diff --findings to');
  return {
    schemaVersion: '3.0',
    kind: 'finding-diff',
    fromBuildDigest: from.build,
    toBuildDigest: to.build,
    introduced: [...to.lineage].filter((id) => !from.lineage.has(id)).sort(),
    resolved: [...from.lineage].filter((id) => !to.lineage.has(id)).sort(),
    persisted: [...to.lineage].filter((id) => from.lineage.has(id)).sort(),
  };
}

export function diffCoverage(
  from: CoverageReport,
  to: CoverageReport,
): CoverageDiff {
  const fromLedger = new Map(from.ledger.map((item) => [item.surface.id, item]));
  const toLedger = new Map(to.ledger.map((item) => [item.surface.id, item]));
  const fromIds = new Set(fromLedger.keys());
  const toIds = new Set(toLedger.keys());

  const packIds = new Set([
    ...Object.keys(from.packVersions),
    ...Object.keys(to.packVersions),
  ]);
  const packDrift: CoverageDiff['packDrift'] = [];
  for (const packId of [...packIds].sort()) {
    const fromVersion = from.packVersions[packId];
    const toVersion = to.packVersions[packId];
    if (fromVersion !== toVersion) {
      packDrift.push({
        packId,
        ...(fromVersion ? { fromVersion } : {}),
        ...(toVersion ? { toVersion } : {}),
      });
    }
  }

  return {
    schemaVersion: '3.0',
    kind: 'coverage-diff',
    fromBuildDigest: from.target.buildDigest,
    toBuildDigest: to.target.buildDigest,
    addedSurfaceIds: [...toIds].filter((id) => !fromIds.has(id)).sort(),
    removedSurfaceIds: [...fromIds].filter((id) => !toIds.has(id)).sort(),
    changedCoverage: [...fromIds]
      .filter((id) => toIds.has(id))
      .flatMap((id) => {
        const before = fromLedger.get(id);
        const after = toLedger.get(id);
        if (!before || !after || before.state === after.state) return [];
        return [{ surfaceId: id, from: before.state, to: after.state }];
      })
      .sort((left, right) => left.surfaceId.localeCompare(right.surfaceId)),
    packDrift,
  };
}

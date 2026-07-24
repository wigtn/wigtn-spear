export type EnvironmentClass = 'disposable' | 'test' | 'production';
export type SafetyClass = 'passive' | 'active-safe' | 'active-mutating' | 'high-risk';
export type SurfaceProtocol =
  | 'browser'
  | 'http'
  | 'openapi'
  | 'graphql'
  | 'websocket'
  | 'grpc'
  | 'soap'
  | 'event'
  | 'storage'
  | 'database'
  | 'filesystem'
  | 'ci'
  | 'agent'
  | 'unknown';
export type MappingSource = 'operator' | 'openapi' | 'next-app' | 'supabase' | 'graphql-schema';
export type CoverageState =
  | 'discovered'
  | 'mapped'
  | 'attackable'
  | 'exercised'
  | 'witnessed'
  | 'no-effect'
  | 'not-applicable'
  | 'unsupported'
  | 'blocked'
  | 'error';
export type EvidenceGrade = 'inventory' | 'mapped' | 'exercised' | 'witnessed' | 'causal';

export interface SignatureEnvelope {
  algorithm: 'Ed25519';
  keyId: string;
  value: string;
}

export interface TrustStore {
  schemaVersion: '3.0';
  keys: Array<{
    keyId: string;
    algorithm: 'Ed25519';
    publicKeyPem: string;
    status: 'active' | 'revoked';
  }>;
}

export interface AuthorizationManifest {
  schemaVersion: '3.0';
  kind: 'authorization-manifest';
  engagement: {
    id: string;
    owner: string;
    issuedAt: string;
    expiresAt: string;
  };
  target: {
    name: string;
    repositoryPath: string;
    buildDigest: string;
    origins: string[];
    environment: EnvironmentClass;
  };
  capabilities: string[];
  safety: {
    allowedHosts: string[];
    allowedCanaryOrigins: string[];
    allowedControlOrigins?: string[];
    maxRequests: number;
    maxWallTimeMs: number;
    maxConcurrency: number;
    maxResponseBytes: number;
    allowMutations: boolean;
    twinAttested: boolean;
  };
  signature: SignatureEnvelope;
}

export type UnsignedAuthorizationManifest = Omit<AuthorizationManifest, 'signature'>;

export interface VerifiedAuthorization {
  manifest: AuthorizationManifest;
  manifestDigest: string;
}

export interface SurfaceInput {
  protocol: SurfaceProtocol;
  entryPoint: string;
  operation?: string;
  principals?: string[];
  dataClasses?: string[];
  stateDependencies?: string[];
  applicablePacks?: string[];
  mappingSource?: MappingSource;
}

export interface Surface {
  id: string;
  protocol: SurfaceProtocol;
  entryPoint: string;
  operation: string;
  principals: string[];
  dataClasses: string[];
  stateDependencies: string[];
  applicablePacks: string[];
  mappingSources: MappingSource[];
}

export interface TargetProfile {
  schemaVersion: '3.0';
  kind: 'target-profile';
  target: {
    name: string;
    version: string;
    buildDigest: string;
  };
  availableWitnesses: string[];
  surfaces: SurfaceInput[];
}

export interface SurfaceInventory {
  schemaVersion: '3.0';
  kind: 'surface-inventory';
  target: TargetProfile['target'];
  generatedAt: string;
  sources: MappingSource[];
  surfaces: Surface[];
  blindSpots: Array<{
    id: string;
    surfaceId?: string;
    reason: string;
  }>;
}

export interface PackManifest {
  schemaVersion: '3.0';
  id: string;
  version: string;
  apiVersion: '1.0';
  supportedTargetVersions: string[];
  applicableProtocols: SurfaceProtocol[];
  capabilities: string[];
  safetyClass: SafetyClass;
  requiredWitnesses: string[];
  fixtures: string[];
  mutationGrammar: string;
  forbiddenPredicates: string[];
  cleanup: string;
  standards: string[];
  integrity: {
    algorithm: 'sha256';
    descriptorDigest: string;
  };
}

export interface PackRegistry {
  schemaVersion: '3.0';
  kind: 'pack-registry';
  registryId: string;
  generatedAt: string;
  packs: PackManifest[];
  signature: SignatureEnvelope;
}

export type UnsignedPackRegistry = Omit<PackRegistry, 'signature'>;

export interface CoveragePolicy {
  schemaVersion: '3.0';
  kind: 'coverage-policy';
  requiredProtocols: SurfaceProtocol[];
  requiredSurfaceIds: string[];
  requiredWitnesses: string[];
  minimumEvidenceGrade: EvidenceGrade;
  allowedSafetyClasses: SafetyClass[];
}

export interface SurfaceCoverage {
  surface: Surface;
  state: CoverageState;
  evidenceGrade: EvidenceGrade;
  applicablePackIds: string[];
  missingWitnesses: string[];
  reasons: string[];
}

export interface CoverageReport {
  schemaVersion: '3.0';
  kind: 'coverage-report';
  target: TargetProfile['target'];
  generatedAt: string;
  verdict: 'coverage-complete' | 'coverage-incomplete';
  policy: CoveragePolicy;
  registryDigest: string;
  packVersions: Record<string, string>;
  packSafetyClasses: Record<string, SafetyClass>;
  ledger: SurfaceCoverage[];
  blindSpots: Array<{
    id: string;
    surfaceId?: string;
    reason: string;
  }>;
  unmetRequirements: string[];
}

export interface AttackProgram {
  schemaVersion: '3.0';
  kind: 'attack-program';
  id: string;
  title: string;
  principal: {
    id: string;
    kind: string;
  };
  preconditions: string[];
  carrier: {
    protocol: SurfaceProtocol;
    entryPoint: string;
  };
  source: {
    kind: string;
    reference: string;
  };
  capability: string;
  mutation: {
    kind: string;
    description: string;
  };
  forbiddenPredicate: {
    kind: string;
    expression: string;
  };
  oracle: {
    kind: string;
    witness: string;
  };
}

export interface RunPreview {
  schemaVersion: '3.0';
  kind: 'run-preview';
  runId: string;
  generatedAt: string;
  target: TargetProfile['target'];
  authorization: {
    engagementId: string;
    manifestDigest: string;
    buildDigest: string;
    capabilities: string[];
  };
  registryDigest: string;
  selectedPackIds: string[];
  safety: AuthorizationManifest['safety'];
  coverageVerdict: CoverageReport['verdict'];
  mutationsEnabled: false;
  targetEvents: 0;
}

export interface CoverageDiff {
  schemaVersion: '3.0';
  kind: 'coverage-diff';
  fromBuildDigest: string;
  toBuildDigest: string;
  addedSurfaceIds: string[];
  removedSurfaceIds: string[];
  changedCoverage: Array<{
    surfaceId: string;
    from: CoverageState;
    to: CoverageState;
  }>;
  packDrift: Array<{
    packId: string;
    fromVersion?: string;
    toVersion?: string;
  }>;
}

export interface AttackCorpus {
  schemaVersion: '3.0';
  kind: 'attack-corpus';
  files: Array<{
    id: string;
    filename: string;
    mediaType: string;
    contentBase64: string;
    inertCanary: true;
  }>;
  identities: Array<{
    id: string;
    fixture: true;
    token: string;
  }>;
  recipients: string[];
  analyzerOrigins: string[];
}

export interface PrincipalFixture {
  id: string;
  tenantId: string;
  role: 'anonymous' | 'user' | 'privileged';
  headers: Record<string, string>;
}

export interface AssetFixture {
  id: string;
  ownerPrincipalId: string;
  tenantId: string;
  classification: string;
  lifecycle: 'seeded' | 'active' | 'deleted';
  canary: string;
}

export interface TwinSnapshot {
  schemaVersion: '3.0';
  kind: 'twin-snapshot';
  snapshotId: string;
  digest: string;
  createdAt: string;
  state: Record<string, unknown>;
}

export interface TwinControlChannel {
  resetUrl: string;
  snapshotUrl: string;
}

export interface TwinDefinition {
  schemaVersion: '3.0';
  kind: 'attack-twin';
  twinId: string;
  principals: PrincipalFixture[];
  assets: AssetFixture[];
  control?: TwinControlChannel;
}

export interface HttpRequestSpec {
  id: string;
  method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  headers?: Record<string, string>;
  body?: string;
  /** Sent as the Idempotency-Key header and recorded per attempt (S5/FR-806). */
  idempotencyKey?: string;
  /** Issue this request as a different Twin principal than the sequence's (FR-403/FR-404). */
  asPrincipalId?: string;
}

export type CausalOracle =
  | {
    kind: 'response-contains';
    witness: 'http-gateway';
    requestId: string;
    value: string;
  }
  | {
    kind: 'state-path-increased';
    witness: string;
    path: string;
  }
  | {
    // A duplicate-effect predicate: the state delta exceeds what a single,
    // idempotent application should produce (S5/FR-806/FR-414).
    kind: 'state-path-delta-exceeds';
    witness: string;
    path: string;
    expected: number;
  }
  | {
    // Any change (numeric or not) at the path — row/file/object diff (FR-504).
    kind: 'state-path-changed';
    witness: string;
    path: string;
  }
  | {
    // Partial effect after an error: one state moved while its paired state did
    // not (a non-atomic commit / missing rollback) (FR-509).
    kind: 'partial-effect';
    witness: string;
    committedPath: string;
    rolledBackPath: string;
  }
  | {
    // Differential authorization (FR-507): two principals issue the equivalent
    // operation. Forbidden when the unprivileged principal obtains a 2xx response
    // identical to the privileged one — authorization failed to differentiate
    // them. Detects BFLA/BOLA with no canary or state change to key on: the
    // signal is purely that two principals received the same protected content.
    kind: 'differential-access';
    witness: 'http-gateway';
    privilegedRequestId: string;
    unprivilegedRequestId: string;
  }
  | {
    // Outbound canary egress (FR-504/FR-810): an owned sink observed the specific
    // run-scoped canary token during this sequence. Stronger than a bare hit
    // counter — it proves *this* owned token reached the sink (SSRF/blind egress),
    // not merely that some sink counter moved. The raw sink value is still
    // digested in the persisted diff; the oracle reads in-memory state only.
    kind: 'canary-egress';
    witness: string;
    sinkPath: string;
    canary: string;
  };

export interface HttpSequenceSpec {
  id: string;
  principalId: string;
  requests: HttpRequestSpec[];
}

export interface CausalHttpAttackProgram extends AttackProgram {
  execution: {
    baseline: HttpSequenceSpec;
    attack: HttpSequenceSpec;
    counterfactual: HttpSequenceSpec;
    repetitions: number;
    minimumAttackSuccesses: number;
    /** true for agent/nondeterministic candidates: 3-of-2 threshold instead of all-success. */
    nondeterministic?: boolean;
  };
  oracle: CausalOracle;
}

export interface WitnessEvent {
  schemaVersion: '3.0';
  runId: string;
  source: string;
  sequence: number;
  timestamp: string;
  buildDigest: string;
  payloadDigest: string;
  previousEventHash: string;
  eventHash: string;
  summary: string;
  details: Record<string, unknown>;
}

export interface HttpObservation {
  requestId: string;
  method: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface StateDiffEntry {
  path: string;
  before: unknown;
  after: unknown;
}

export interface SequenceReceipt {
  sequenceId: string;
  principalId: string;
  observations: HttpObservation[];
  beforeStateDigest: string;
  afterStateDigest: string;
  stateDiff: StateDiffEntry[];
  predicateObserved: boolean;
  events: WitnessEvent[];
}

export type CandidateDisposition = 'proven' | 'rejected' | 'flaky' | 'error';

export interface CausalRunResult {
  schemaVersion: '3.0';
  kind: 'causal-run';
  runId: string;
  programId: string;
  targetBuildDigest: string;
  manifestDigest: string;
  registryDigest: string;
  disposition: CandidateDisposition;
  attempts: number;
  attackSuccesses: number;
  baseline: SequenceReceipt;
  attacks: SequenceReceipt[];
  counterfactual: SequenceReceipt;
  reason: string;
}

export interface ProvenFinding {
  schemaVersion: '3.0';
  findingId: string;
  /** Build-independent identity for lineage across builds (S8/FR-908). */
  lineageId: string;
  state: 'proven';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  severityRationale: string;
  affectedBuildDigest: string;
  attackPreconditions: string[];
  forbiddenPredicate: string;
  reproduction: {
    successes: number;
    attempts: number;
  };
  reproductionRate: number;
  minimizedGraphPath: string[];
  remediationHypothesis: string;
}

export interface CandidateFinding {
  schemaVersion: '3.0';
  state: 'candidate';
  candidateId: string;
  surfaceId: string;
  family: string;
  rationale: string;
  provenance: 'static' | 'learned';
  confidence: 'low' | 'medium';
}

export interface RunSummary {
  runId: string;
  programId: string;
  disposition: CandidateDisposition;
  attackSuccesses: number;
  attempts: number;
  reason: string;
}

export interface CampaignReport {
  schemaVersion: '3.0';
  kind: 'campaign-report';
  target: TargetProfile['target'];
  generatedAt: string;
  coverage: {
    verdict: CoverageReport['verdict'];
    ledger: SurfaceCoverage[];
    blindSpots: CoverageReport['blindSpots'];
  };
  findings: {
    proven: ProvenFinding[];
    candidate: CandidateFinding[];
    rejected: RunSummary[];
    flaky: RunSummary[];
    error: RunSummary[];
  };
  secureVerdict: false;
  bundleRefs: Array<{
    findingId?: string;
    runId: string;
    bundleId: string;
    disposition: CandidateDisposition;
  }>;
}

export interface EvidenceBundle {
  schemaVersion: '3.0';
  kind: 'evidence-bundle';
  bundleId: string;
  createdAt: string;
  authorization: {
    manifestDigest: string;
    buildDigest: string;
  };
  registryDigest: string;
  snapshotDigest: string;
  attackProgramDigest: string;
  redactedProgramDigest: string;
  attackProgram: CausalHttpAttackProgram;
  run: CausalRunResult;
  finding?: ProvenFinding;
  replayCommand: string;
  redactionManifest: Array<{
    field: string;
    action: 'removed' | 'replaced' | 'digested';
  }>;
  retention: {
    rawExpiresAt: string;
    grade: 'full' | 'redacted-only';
  };
  bundleDigest: string;
  signature: SignatureEnvelope;
}

export type UnsignedEvidenceBundle = Omit<EvidenceBundle, 'signature'>;

export interface FixVerification {
  schemaVersion: '3.0';
  kind: 'fix-verification';
  originalRunId: string;
  fixedRunId: string;
  verdict: 'fixed' | 'not-fixed' | 'utility-regression' | 'not-verifiable';
  reason: string;
}

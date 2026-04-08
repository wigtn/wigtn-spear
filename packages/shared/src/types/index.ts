/**
 * WIGTN-SPEAR Shared Types
 * All packages depend on these types.
 */

// ─── Severity ───────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ─── Scan Mode ──────────────────────────────────────────────

export type ScanMode = 'safe' | 'aggressive';

// ─── Scan Status ────────────────────────────────────────────

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'interrupted';

// ─── Platform ───────────────────────────────────────────────

export type Platform = 'darwin' | 'linux' | 'win32';

// ─── Trust Level ────────────────────────────────────────────

export type TrustLevel = 'builtin' | 'verified' | 'community' | 'untrusted';

// ─── Plugin Permission ──────────────────────────────────────

export type PluginPermission =
  | 'fs:read'
  | 'fs:read-global'
  | 'git:read'
  | 'net:outbound'
  | 'net:listen'
  | 'process:read'
  | 'exec:child'
  | 'db:write';

// ─── Finding ────────────────────────────────────────────────

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  column?: number;
  secretMasked?: string;
  cvss?: number;
  mitreTechniques?: string[];
  remediation?: string;
  metadata?: Record<string, unknown>;
  /** Confidence level: confirmed (live-verified), high, medium, low */
  confidence?: 'confirmed' | 'high' | 'medium' | 'low';
  /** Deduplication fingerprint: SHA256(ruleId + category + evidence).slice(0,16) */
  fingerprintId?: string;
}

// ─── Verification Result ────────────────────────────────────

export interface VerificationResult {
  verified: boolean;
  active: boolean;
  service?: string;
  permissions?: string[];
  verifiedAt: string;
}

// ─── Scan Target ────────────────────────────────────────────

export interface ScanTarget {
  path: string;
  gitRepo?: boolean;
  include?: string[];
  exclude?: string[];
}

// ─── Plugin Metadata ────────────────────────────────────────

export interface PluginMetadata {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  severity: Severity;
  tags: string[];
  references: string[];
  safeMode: boolean;
  requiresNetwork: boolean;
  supportedPlatforms: Platform[];
  permissions: PluginPermission[];
  trustLevel: TrustLevel;
}

// ─── Live Attack Options ───────────────────────────────────

export interface LiveAttackOptions {
  targetUrl: string;
  apiKey?: string;
  headers?: Record<string, string>;
  timeout?: number;
  maxRequests?: number;
  concurrency?: number;
  endpoints?: LiveEndpoint[];
  /** LLM API key for multi-turn attacks and LLM-as-judge evaluation */
  judgeApiKey?: string;
  /** LLM model for attack generation and judging (default: gpt-4o-mini) */
  judgeModel?: string;
  /** LLM provider for judge (default: openai) */
  judgeProvider?: 'openai' | 'anthropic' | 'google';
  /** Enable multi-turn attack strategies (Crescendo, TAP) */
  multiTurn?: boolean;
  /** Multi-turn strategy (default: both) */
  multiTurnStrategy?: 'crescendo' | 'tap' | 'both';
}

export interface LiveEndpoint {
  method: string;
  path: string;
  auth?: string;
  description?: string;
}

export interface LiveAttackResult {
  payloadId: string;
  request: { method: string; url: string; body?: string };
  response: { status: number; body: string; headers: Record<string, string> };
  success: boolean;
  evidence: string;
  durationMs: number;
}

// ─── Plugin Context ─────────────────────────────────────────

export interface PluginContext {
  mode: ScanMode;
  workDir: string;
  config: SpearConfig;
  logger: SpearLogger;
  liveAttack?: LiveAttackOptions;
  /** Secret verifier instance for live credential validation (aggressive mode) */
  secretVerifier?: SecretVerifierInterface;
  /** Arena context for Judgement Day competition scenarios */
  arena?: ArenaContext;
}

/** Minimal interface for secret verification (avoids direct @wigtn/core dependency in shared) */
export interface SecretVerifierInterface {
  verify(secret: string): Promise<{
    secret: string;
    service: string;
    verified: boolean;
    active: boolean;
    permissions?: string[];
    identity?: string;
    error?: string;
  }>;
}

// ─── SpearPlugin Interface ──────────────────────────────────

export interface SpearPlugin {
  metadata: PluginMetadata;
  setup?(context: PluginContext): Promise<void>;
  scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding>;
  teardown?(context: PluginContext): Promise<void>;
  verify?(finding: Finding): Promise<VerificationResult>;
}

// ─── Rule ───────────────────────────────────────────────────

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: 'secret' | 'vulnerability' | 'misconfiguration';
  severity: Severity;
  tags: string[];
  references: string[];
  mitre?: string[];
  detection: {
    keywords: string[];
    pattern: string;
    entropy?: {
      enabled: boolean;
      threshold?: number;
    };
  };
  verification?: {
    enabled: boolean;
    method?: string;
    rateLimit?: {
      rpm: number;
      concurrent: number;
    };
  };
  allowlist?: {
    patterns?: string[];
    paths?: string[];
  };
}

// ─── Spear Config ───────────────────────────────────────────

export interface SpearConfig {
  mode: ScanMode;
  modules: string[];
  exclude: string[];
  verifyLimit: number;
  maxWorkers: number;
  gitDepth: number;
  outputFormat: 'sarif' | 'json' | 'text';
  dbPath: string;
  rulesDir: string;
  verbose: boolean;
}

export const DEFAULT_CONFIG: SpearConfig = {
  mode: 'safe',
  modules: ['all'],
  exclude: [],
  verifyLimit: 100,
  maxWorkers: 0, // 0 = auto (os.cpus().length - 1)
  gitDepth: 1000,
  outputFormat: 'text',
  dbPath: '.spear/spear.db',
  rulesDir: '',
  verbose: false,
};

// ─── Logger Interface ───────────────────────────────────────

export interface SpearLogger {
  debug(msg: string, data?: Record<string, unknown>): void;
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
}

// ─── SARIF Types ────────────────────────────────────────────

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  properties: {
    'security-severity': string;
    tags: string[];
  };
}

export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        startColumn?: number;
      };
    };
  }>;
  partialFingerprints?: Record<string, string>;
}

// ─── Arena Types (Judgement Day 2026) ──────────────────────

export type ArenaTrack = 'action_induction' | 'action_suppression';

export type ArenaDomain =
  | 'emergency_triage'
  | 'industrial_robot'
  | 'soc_cybersecurity'
  | 'aircraft_maintenance'
  | 'sports_integrity'
  | 'dam_flood_control'
  | 'epidemiological_surveillance'
  | 'deepfake_detection';

export type ArenaChannel = 'text' | 'document' | 'audio' | 'image' | 'video' | 'email';

export type ArenaTargetModel =
  | 'gpt-5.4'
  | 'claude-opus-4.6'
  | 'gemini-3.1-pro'
  | 'gemini-3-flash'
  | 'gpt-audio-1.5'
  | 'mimo-v2-omni';

export type ArenaWave = 1 | 2;

export type ArenaConfidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface ArenaScenario {
  id: string;
  track: ArenaTrack;
  wave: ArenaWave;
  domain: ArenaDomain;
  name: string;
  description: string;
  /** The action the attack tries to induce (Track 1) or suppress (Track 2) */
  targetAction: string;
  /** All available input channels for this scenario */
  availableChannels: ArenaChannel[];
  /** Target models to attack */
  targetModels: ArenaTargetModel[];
  /** Domain-specific context variables (patient data, sensor readings, etc.) */
  context: Record<string, unknown>;
  /** Whether this scenario is currently active */
  active: boolean;
}

export interface ArenaAttack {
  scenarioId: string;
  channel: ArenaChannel;
  /** The generated adversarial payload content */
  payload: string;
  /** Reasoning for why this attack should work */
  reasoning: string;
  /** Confidence level */
  confidence: ArenaConfidence;
  /** Attack strategy used */
  strategy: string;
  /** Source spear module(s) used */
  sourceModules: string[];
  metadata?: Record<string, unknown>;
}

export interface ArenaSubmission {
  scenario_id: string;
  track: ArenaTrack;
  selected_action_id: string;
  reasoning: string;
  confidence: ArenaConfidence;
  attack_method: 'manual' | 'programmatic' | 'hybrid';
  method_detail: string;
  channel: ArenaChannel;
  payload: string;
  timestamp: string;
}

export interface ArenaContext {
  scenario: ArenaScenario;
  track: ArenaTrack;
  targetChannel: ArenaChannel;
}

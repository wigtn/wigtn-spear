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

export const SPEAR_VERSION = '0.1.0';
export const SPEAR_NAME = 'wigtn-spear';
export const SPEAR_DESCRIPTION = 'Offensive Security Testing Tool for AI/MCP Era';

export const ENTROPY_THRESHOLDS = {
  NON_SECRET: 4.0,
  SUSPICIOUS: 5.0,
  HIGH: 6.0,
  VERY_HIGH: 8.0,
} as const;

export const WORKER_DEFAULTS = {
  MIN_WORKERS: 2,
  TASK_TIMEOUT_MS: 5 * 60 * 1000, // 5 minutes
} as const;

export const SAFE_MODE_DEFAULTS = {
  GIT_DEPTH: 1000,
  VERIFY_LIMIT: 0, // no verification in safe mode
  NETWORK_ACCESS: false,
} as const;

export const AGGRESSIVE_MODE_DEFAULTS = {
  GIT_DEPTH: -1, // unlimited
  VERIFY_LIMIT: 100,
  NETWORK_ACCESS: true,
} as const;

export const DB_DEFAULTS = {
  PATH: '.spear/spear.db',
  WAL_MODE: true,
} as const;

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

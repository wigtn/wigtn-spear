/**
 * SPEAR-25: Sourcemap Deep Recovery
 *
 * Downloads accessible source maps, recovers the original source code from
 * the `sourcesContent` array, and re-scans each recovered file for secrets
 * and environment variable references.
 *
 * This is a "code review impossible" feature: the original source code is only
 * available via the sourcemap, not in the minified JS bundle. Secrets that are
 * visible in the original source but obfuscated in the bundle are recovered here.
 *
 * Memory management: files are processed one at a time and dereferenced after
 * scanning to avoid holding the entire sourcemap in memory.
 *
 * @module sourcemap-recovery
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface SourcemapRecovery {
  /** Sourcemap URL that was recovered */
  sourcemapUrl: string;
  /** Number of source files in the sourcemap */
  totalSources: number;
  /** Number of source files with recoverable content */
  recoverableSources: number;
  /** Secrets found in recovered source code */
  secrets: RecoveredSecret[];
  /** Environment variable references found */
  envReferences: EnvReference[];
}

export interface RecoveredSecret {
  /** Type of secret (pattern name) */
  type: string;
  /** Masked value */
  masked: string;
  /** Original source file path (from sourcemap) */
  sourceFile: string;
  /** Line number in original source */
  line: number;
  /** Surrounding context */
  context: string;
}

export interface EnvReference {
  /** Variable name (e.g. NEXT_PUBLIC_API_KEY) */
  variable: string;
  /** Source file where found */
  sourceFile: string;
  /** Line number */
  line: number;
  /** Context snippet */
  context: string;
}

export interface SourcemapRecoveryConfig {
  /** Source map URL to fetch */
  sourcemapUrl: string;
  /** Request timeout in ms */
  timeout?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_SOURCEMAP_SIZE = 50_000_000; // 50MB
const MAX_CONTEXT_LENGTH = 80;

// ─── Secret Patterns (reused from js-bundle-analyzer) ─────────

interface SecretPattern {
  name: string;
  type: string;
  regex: RegExp;
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: 'OpenAI API Key', type: 'openai_api_key', regex: /sk-[a-zA-Z0-9_-]{20,}/ },
  { name: 'OpenAI Project Key', type: 'openai_project_key', regex: /sk-proj-[a-zA-Z0-9_-]{20,}/ },
  { name: 'AWS Access Key', type: 'aws_access_key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'Google API Key', type: 'google_api_key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Stripe Secret Key', type: 'stripe_secret', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'Anthropic API Key', type: 'anthropic_key', regex: /sk-ant-[a-zA-Z0-9_-]{20,}/ },
  { name: 'GitHub Token', type: 'github_token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/ },
  { name: 'Slack Token', type: 'slack_token', regex: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/ },
  { name: 'SendGrid API Key', type: 'sendgrid_key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
  { name: 'Private Key', type: 'private_key', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { name: 'Kakao REST API Key', type: 'kakao_rest_key', regex: /(?:KAKAO_REST_KEY|kakao_rest_key|kakaoRestKey|rest_api_key|Authorization:\s*KakaoAK\s+)["']?([a-f0-9]{32})/ },
  { name: 'Kakao Admin Key', type: 'kakao_admin_key', regex: /(?:KAKAO_ADMIN_KEY|kakao_admin_key|kakaoAdminKey|admin_key)\s*[:=]\s*["']([a-f0-9]{32})/ },
  { name: 'Naver Client Secret', type: 'naver_client_secret', regex: /(?:NAVER_CLIENT_SECRET|naver_client_secret|naverClientSecret|X-Naver-Client-Secret)\s*[:=]\s*["']([a-zA-Z0-9_-]{10,30})/ },
  { name: 'Toss Secret Key', type: 'toss_secret_key', regex: /(?:test_sk|live_sk)_[a-zA-Z0-9]{20,}/ },
  { name: 'Sentry DSN', type: 'sentry_dsn', regex: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/ },
  { name: 'Generic Secret Assignment', type: 'generic_secret', regex: /(?:secret|SECRET|password|PASSWORD|token|TOKEN|api_key|API_KEY|apiKey)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']/ },
  { name: 'Firebase Config', type: 'firebase_config', regex: /apiKey\s*:\s*["']([A-Za-z0-9_-]{39})["']/ },
  { name: 'Supabase Key', type: 'supabase_key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}/ },
];

/** Patterns to detect process.env.XXX references */
const ENV_VAR_PATTERNS: readonly RegExp[] = [
  /process\.env\.([A-Z_][A-Z0-9_]*)/g,
  /import\.meta\.env\.([A-Z_][A-Z0-9_]*)/g,
  /(?:process\.env|import\.meta\.env)\[["']([A-Z_][A-Z0-9_]*)["']\]/g,
];

// ─── Core Function ────────────────────────────────────────────

/**
 * Recover original source files from a sourcemap and scan for secrets.
 *
 * Downloads the sourcemap, extracts `sourcesContent`, and applies secret
 * patterns to each recovered file individually. Files are processed one
 * at a time to minimize memory usage.
 */
export async function recoverAndScan(
  config: SourcemapRecoveryConfig,
): Promise<SourcemapRecovery> {
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  const result: SourcemapRecovery = {
    sourcemapUrl: config.sourcemapUrl,
    totalSources: 0,
    recoverableSources: 0,
    secrets: [],
    envReferences: [],
  };

  logger?.info('sourcemap-recovery: downloading sourcemap', {
    url: config.sourcemapUrl,
  });

  // Download sourcemap
  let sourcemapJson: SourcemapJson;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(config.sourcemapUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.status !== 200) {
      logger?.debug('sourcemap-recovery: non-200 response', {
        status: response.status,
      });
      return result;
    }

    // Check size
    const contentLength = Number(response.headers.get('content-length') ?? 0);
    if (contentLength > MAX_SOURCEMAP_SIZE) {
      logger?.warn('sourcemap-recovery: sourcemap too large', {
        size: contentLength,
      });
      return result;
    }

    const body = await response.text();
    sourcemapJson = JSON.parse(body) as SourcemapJson;
  } catch (err) {
    logger?.debug('sourcemap-recovery: failed to fetch/parse sourcemap', {
      error: String(err),
    });
    return result;
  }

  // Validate sourcemap structure
  if (!Array.isArray(sourcemapJson.sources)) {
    return result;
  }

  result.totalSources = sourcemapJson.sources.length;
  const sourcesContent = sourcemapJson.sourcesContent ?? [];

  logger?.info('sourcemap-recovery: scanning recovered sources', {
    totalSources: result.totalSources,
    hasContent: sourcesContent.length,
  });

  // Process each source file
  for (let i = 0; i < sourcesContent.length; i++) {
    const content = sourcesContent[i];
    if (!content || typeof content !== 'string' || content.length < 10) continue;

    const sourceFile = sourcemapJson.sources[i] ?? `source-${i}`;

    // Skip node_modules and common library files
    if (sourceFile.includes('node_modules/') && !sourceFile.includes('node_modules/.cache')) {
      continue;
    }

    result.recoverableSources++;

    // Scan for secrets
    scanSourceForSecrets(content, sourceFile, result);

    // Scan for env var references
    scanSourceForEnvRefs(content, sourceFile, result);
  }

  logger?.info('sourcemap-recovery: scan complete', {
    sourcemapUrl: config.sourcemapUrl,
    recoverableSources: result.recoverableSources,
    secrets: result.secrets.length,
    envReferences: result.envReferences.length,
  });

  return result;
}

// ─── Scanning Functions ───────────────────────────────────────

function scanSourceForSecrets(
  content: string,
  sourceFile: string,
  result: SourcemapRecovery,
): void {
  const lines = content.split('\n');

  for (const pattern of SECRET_PATTERNS) {
    // Process line by line for accurate line numbers
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx]!;
      const match = pattern.regex.exec(line);

      if (match) {
        const value = match[1] ?? match[0];
        const masked = maskSecret(value);

        // Deduplicate
        const exists = result.secrets.some(
          (s) => s.type === pattern.type && s.masked === masked,
        );
        if (exists) continue;

        const contextStart = Math.max(0, match.index - 20);
        const contextEnd = Math.min(line.length, match.index + match[0].length + 20);
        const context = line.slice(contextStart, contextEnd).replace(/\n/g, ' ');

        result.secrets.push({
          type: pattern.type,
          masked,
          sourceFile,
          line: lineIdx + 1,
          context: context.slice(0, MAX_CONTEXT_LENGTH),
        });
      }
    }
  }
}

function scanSourceForEnvRefs(
  content: string,
  sourceFile: string,
  result: SourcemapRecovery,
): void {
  const lines = content.split('\n');
  const seen = new Set(result.envReferences.map((e) => e.variable));

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;

    for (const pattern of ENV_VAR_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = re.exec(line)) !== null) {
        const variable = match[1]!;
        if (seen.has(variable)) continue;
        seen.add(variable);

        const contextStart = Math.max(0, match.index - 10);
        const contextEnd = Math.min(line.length, match.index + match[0].length + 10);
        const context = line.slice(contextStart, contextEnd);

        result.envReferences.push({
          variable,
          sourceFile,
          line: lineIdx + 1,
          context: context.slice(0, MAX_CONTEXT_LENGTH),
        });
      }
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────

interface SourcemapJson {
  version?: number;
  sources: string[];
  sourcesContent?: (string | null)[];
  names?: string[];
  mappings?: string;
}

function maskSecret(value: string): string {
  if (value.length <= 8) return '***';
  return value.slice(0, 8) + '***';
}

/**
 * SPEAR-25: JavaScript Bundle Analyzer
 *
 * Analyzes frontend JavaScript bundles WITHOUT source code access.
 * Fetches the target URL, extracts script tags, downloads JS files,
 * and searches for:
 *
 *   - Hardcoded API keys and secrets (OpenAI, AWS, Google, Stripe, etc.)
 *   - API endpoint URLs embedded in frontend code
 *   - Source map references (.js.map) for full source recovery
 *   - Environment variable references
 *   - WebSocket endpoint URLs
 *   - Internal service URLs
 *
 * This is the key module for "source-code-free" scanning.
 * If a source map is found, downstream modules can reconstruct
 * the original source and apply the full 22-module static analysis.
 *
 * OWASP: A05 (Security Misconfiguration) -- source maps in production
 *         A01 (Broken Access Control) -- hardcoded credentials in frontend
 */

import type { SpearLogger, SecretVerifierInterface } from '@wigtn/shared';
import { recoverAndScan } from './sourcemap-recovery.js';
import type { SourcemapRecovery } from './sourcemap-recovery.js';
import { scanDependencyCves } from './js-dependency-cve.js';
import type { DependencyCveResult } from './js-dependency-cve.js';

// ─── Types ────────────────────────────────────────────────────

export interface JsBundleResult {
  /** Scripts discovered in HTML */
  scripts: DiscoveredScript[];
  /** Secrets found in JS bundles */
  secrets: DiscoveredSecret[];
  /** API endpoints extracted from JS bundles */
  endpoints: DiscoveredJsEndpoint[];
  /** Source maps found */
  sourceMaps: DiscoveredSourceMap[];
  /** Total bytes of JS analyzed */
  totalBytesAnalyzed: number;
  /** Environment variable leaks found in bundles */
  envLeaks: DiscoveredEnvLeak[];
  /** Sourcemap deep recovery results */
  sourcemapRecoveries: SourcemapRecovery[];
  /** Dependency CVE scan results */
  dependencyCves: DependencyCveResult | null;
}

export interface DiscoveredScript {
  /** Script URL */
  url: string;
  /** Size in bytes */
  size: number;
  /** Whether it has a sourcemap reference */
  hasSourceMap: boolean;
}

export interface DiscoveredSecret {
  /** Type of secret (e.g., 'openai_api_key', 'aws_access_key') */
  type: string;
  /** Masked value (first 8 chars + ***) */
  masked: string;
  /** Script URL where found */
  scriptUrl: string;
  /** Matched pattern name */
  pattern: string;
  /** Surrounding context (50 chars) */
  context: string;
  /** Live verification result (if secretVerifier was provided) */
  verification?: {
    verified: boolean;
    active: boolean;
    service: string;
    permissions?: string[];
    identity?: string;
  };
}

export interface DiscoveredEnvLeak {
  /** Framework that uses this prefix */
  framework: string;
  /** Variable name (e.g. NEXT_PUBLIC_API_KEY) */
  variable: string;
  /** Value (truncated/masked) */
  maskedValue: string;
  /** Whether the variable name suggests sensitive content */
  isSensitive: boolean;
  /** Script URL where found */
  scriptUrl: string;
  /** Surrounding context */
  context: string;
}

export interface DiscoveredJsEndpoint {
  /** Full URL or path */
  url: string;
  /** Category: api, websocket, internal, external */
  category: 'api' | 'websocket' | 'internal' | 'external';
  /** Script URL where found */
  scriptUrl: string;
}

export interface DiscoveredSourceMap {
  /** Source map URL */
  url: string;
  /** Whether it's accessible (HTTP 200) */
  accessible: boolean;
  /** Size in bytes (if accessible) */
  size?: number;
  /** Number of source files (if parseable) */
  sourceCount?: number;
  /** Original source file names (if parseable) */
  sources?: string[];
}

export interface JsBundleScanConfig {
  /** Target URL to fetch HTML from */
  baseUrl: string;
  /** Timeout per request in ms */
  timeout?: number;
  /** Maximum number of scripts to download */
  maxScripts?: number;
  /** Maximum JS file size to download (bytes) */
  maxFileSize?: number;
  /** Logger instance */
  logger?: SpearLogger;
  /** Secret verifier for live credential validation */
  secretVerifier?: SecretVerifierInterface;
  /** Enable sourcemap deep recovery (default: true) */
  enableDeepRecovery?: boolean;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_SCRIPTS = 20;
const DEFAULT_MAX_FILE_SIZE = 5_000_000; // 5MB
const MAX_CONTEXT_LENGTH = 80;

// ─── Secret Patterns ──────────────────────────────────────────

interface SecretPattern {
  name: string;
  type: string;
  regex: RegExp;
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
  // OpenAI
  { name: 'OpenAI API Key', type: 'openai_api_key', regex: /sk-[a-zA-Z0-9_-]{20,}/ },
  { name: 'OpenAI Project Key', type: 'openai_project_key', regex: /sk-proj-[a-zA-Z0-9_-]{20,}/ },

  // AWS
  { name: 'AWS Access Key', type: 'aws_access_key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', type: 'aws_secret_key', regex: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})/ },

  // Google
  { name: 'Google API Key', type: 'google_api_key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Google OAuth', type: 'google_oauth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/ },

  // Stripe
  { name: 'Stripe Secret Key', type: 'stripe_secret', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'Stripe Publishable Key', type: 'stripe_publishable', regex: /pk_live_[0-9a-zA-Z]{24,}/ },

  // Firebase
  { name: 'Firebase API Key', type: 'firebase_key', regex: /(?:firebase|FIREBASE).*?["']([A-Za-z0-9_-]{39})["']/ },

  // Supabase
  { name: 'Supabase Key', type: 'supabase_key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}/ },

  // Anthropic
  { name: 'Anthropic API Key', type: 'anthropic_key', regex: /sk-ant-[a-zA-Z0-9_-]{20,}/ },

  // Generic patterns
  { name: 'Bearer Token', type: 'bearer_token', regex: /["']Bearer\s+[A-Za-z0-9_\-.]{20,}["']/ },
  { name: 'Authorization Header', type: 'auth_header', regex: /[Aa]uthorization["']\s*:\s*["'][A-Za-z0-9_\-.]{20,}["']/ },
  { name: 'Private Key', type: 'private_key', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { name: 'Generic Secret', type: 'generic_secret', regex: /(?:secret|SECRET|password|PASSWORD|token|TOKEN|api_key|API_KEY|apiKey|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']/ },

  // Twilio
  { name: 'Twilio Account SID', type: 'twilio_sid', regex: /AC[a-f0-9]{32}/ },
  { name: 'Twilio Auth Token', type: 'twilio_auth', regex: /(?:twilio|TWILIO).*?(?:auth_token|AUTH_TOKEN)\s*[:=]\s*["']?([a-f0-9]{32})/ },

  // SendGrid
  { name: 'SendGrid API Key', type: 'sendgrid_key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },

  // Slack
  { name: 'Slack Token', type: 'slack_token', regex: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/ },

  // GitHub
  { name: 'GitHub Token', type: 'github_token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/ },

  // ─── Korean Services ────────────────────────────────────────

  // Kakao
  { name: 'Kakao JavaScript Key', type: 'kakao_js_key', regex: /(?:Kakao\.init|kakaoJsKey|KAKAO_JS_KEY|kakao_js_key|javascript_key)\s*\(\s*["']([a-f0-9]{32})["']/ },
  { name: 'Kakao REST API Key', type: 'kakao_rest_key', regex: /(?:KAKAO_REST_KEY|kakao_rest_key|kakaoRestKey|rest_api_key|Authorization:\s*KakaoAK\s+)["']?([a-f0-9]{32})/ },
  { name: 'Kakao Admin Key', type: 'kakao_admin_key', regex: /(?:KAKAO_ADMIN_KEY|kakao_admin_key|kakaoAdminKey|admin_key)\s*[:=]\s*["']([a-f0-9]{32})/ },
  { name: 'Kakao Token (Generic)', type: 'kakao_token', regex: /(?:token|appKey|jsKey)\s*[:=]\s*["']([a-f0-9]{32})["']/ },

  // Naver
  { name: 'Naver Maps Client ID', type: 'naver_maps_id', regex: /ncpClientId[=:]["']?([a-zA-Z0-9]{15,25})/ },
  { name: 'Naver Client ID', type: 'naver_client_id', regex: /(?:NAVER_CLIENT_ID|naver_client_id|naverClientId|X-Naver-Client-Id)\s*[:=]\s*["']([a-zA-Z0-9_-]{15,30})/ },
  { name: 'Naver Client Secret', type: 'naver_client_secret', regex: /(?:NAVER_CLIENT_SECRET|naver_client_secret|naverClientSecret|X-Naver-Client-Secret)\s*[:=]\s*["']([a-zA-Z0-9_-]{10,30})/ },

  // Toss Payments
  { name: 'Toss Client Key', type: 'toss_client_key', regex: /(?:test_ck|live_ck)_[a-zA-Z0-9]{20,}/ },
  { name: 'Toss Secret Key', type: 'toss_secret_key', regex: /(?:test_sk|live_sk)_[a-zA-Z0-9]{20,}/ },

  // PortOne (formerly I'mport)
  { name: 'PortOne Merchant ID', type: 'portone_merchant', regex: /(?:imp_uid|merchantId|IMP\.init)\s*\(\s*["'](imp_[0-9]{8,})["']/ },
  { name: 'PortOne Store ID', type: 'portone_store', regex: /(?:storeId|store_id)\s*[:=]\s*["'](store-[a-f0-9-]{36})["']/ },

  // NHN Cloud / Toast
  { name: 'NHN App Key', type: 'nhn_app_key', regex: /(?:NHN_APP_KEY|nhn_app_key|appKey|toast_app_key)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/ },

  // Channel Talk
  { name: 'Channel Talk Plugin Key', type: 'channel_talk_key', regex: /(?:pluginKey|channel_plugin_key)\s*[:=]\s*["']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']/ },

  // Sentry DSN
  { name: 'Sentry DSN', type: 'sentry_dsn', regex: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/ },

  // ─── Korean OAuth Providers (hardcoded in JSX) ──────────────

  // Detect hardcoded clientId in React/JSX component props (Korean login SDKs)
  { name: 'JSX Hardcoded Client ID', type: 'jsx_hardcoded_client_id', regex: /(?:clientId|appId|appKey)\s*[:=]\s*["']([a-zA-Z0-9_-]{15,50})["']\s*[,})\]]/ },
];

// ─── Endpoint Patterns ────────────────────────────────────────

const ENDPOINT_PATTERNS: readonly { regex: RegExp; category: DiscoveredJsEndpoint['category'] }[] = [
  // API endpoints
  { regex: /["'`](https?:\/\/[^"'`\s]{5,}\/api\/[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]{5,}\/v[0-9]+\/[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](\/api\/[^"'`\s]{2,})["'`]/g, category: 'api' },

  // WebSocket endpoints
  { regex: /["'`](wss?:\/\/[^"'`\s]+?)["'`]/g, category: 'websocket' },

  // Internal service URLs
  { regex: /["'`](https?:\/\/[^"'`\s]*?\.internal[^"'`\s]*?)["'`]/g, category: 'internal' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?\.local[^"'`\s]*?)["'`]/g, category: 'internal' },
  { regex: /["'`](https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'`\s]*?)["'`]/g, category: 'internal' },

  // Cloud Run / GCP service URLs
  { regex: /["'`](https?:\/\/[^"'`\s]*?\.run\.app[^"'`\s]*?)["'`]/g, category: 'external' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?\.cloudfunctions\.net[^"'`\s]*?)["'`]/g, category: 'external' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?\.amazonaws\.com[^"'`\s]*?)["'`]/g, category: 'external' },

  // Korean service API endpoints
  { regex: /["'`](https?:\/\/[^"'`\s]*?kapi\.kakao\.com[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?kauth\.kakao\.com[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?openapi\.naver\.com[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?openapi\.map\.naver\.com[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?api\.tosspayments\.com[^"'`\s]*?)["'`]/g, category: 'api' },
  { regex: /["'`](https?:\/\/[^"'`\s]*?api\.iamport\.kr[^"'`\s]*?)["'`]/g, category: 'api' },
];

// ─── Environment Variable Leak Patterns ──────────────────────

interface EnvLeakPattern {
  framework: string;
  prefix: string;
  regex: RegExp;
}

const ENV_LEAK_PATTERNS: readonly EnvLeakPattern[] = [
  // Next.js
  { framework: 'Next.js', prefix: 'NEXT_PUBLIC_', regex: /["']?(NEXT_PUBLIC_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
  // Vite
  { framework: 'Vite', prefix: 'VITE_', regex: /["']?(VITE_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
  // Create React App
  { framework: 'CRA', prefix: 'REACT_APP_', regex: /["']?(REACT_APP_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
  // Expo
  { framework: 'Expo', prefix: 'EXPO_PUBLIC_', regex: /["']?(EXPO_PUBLIC_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
  // Nuxt
  { framework: 'Nuxt', prefix: 'NUXT_PUBLIC_', regex: /["']?(NUXT_PUBLIC_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
  { framework: 'Nuxt', prefix: 'NUXT_ENV_', regex: /["']?(NUXT_ENV_[A-Z_][A-Z0-9_]*)["']?\s*[:=,]\s*["']([^"']{1,200})["']/g },
];

/** Keywords indicating a sensitive environment variable */
const SENSITIVE_KEYWORDS = ['key', 'secret', 'password', 'token', 'api', 'auth', 'private', 'credential'];

function isSensitiveEnvVar(varName: string): boolean {
  const lower = varName.toLowerCase();
  return SENSITIVE_KEYWORDS.some((kw) => lower.includes(kw));
}

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Analyze JavaScript bundles from a target URL.
 *
 * 1. Fetch HTML page
 * 2. Extract <script> tags
 * 3. Download JS files
 * 4. Scan for secrets, endpoints, sourcemaps
 */
export async function analyzeJsBundles(
  config: JsBundleScanConfig,
): Promise<JsBundleResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const maxScripts = config.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const maxFileSize = config.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const logger = config.logger;
  const enableDeepRecovery = config.enableDeepRecovery ?? true;

  logger?.info('js-bundle-analyzer: starting', { baseUrl });

  const result: JsBundleResult = {
    scripts: [],
    secrets: [],
    endpoints: [],
    sourceMaps: [],
    totalBytesAnalyzed: 0,
    envLeaks: [],
    sourcemapRecoveries: [],
    dependencyCves: null,
  };

  // Track JS contents for dependency CVE scanning
  const jsContents: Array<{ content: string; url: string }> = [];

  // ── Step 1: Fetch HTML ────────────────────────────────────

  let html: string;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(baseUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        Accept: 'text/html,application/xhtml+xml,*/*',
      },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);
    html = await response.text();
  } catch (err) {
    logger?.info('js-bundle-analyzer: failed to fetch HTML', { error: String(err) });
    return result;
  }

  // ── Step 2: Extract Script URLs ───────────────────────────

  const scriptUrls = extractScriptUrls(html, baseUrl);
  logger?.info('js-bundle-analyzer: scripts found', { count: scriptUrls.length });

  if (scriptUrls.length === 0) return result;

  // Also scan inline scripts in HTML
  const inlineScripts = extractInlineScripts(html);
  for (const inline of inlineScripts) {
    scanForSecrets(inline, baseUrl + ' (inline)', result);
    scanForEndpoints(inline, baseUrl + ' (inline)', result);
    scanForEnvLeaks(inline, baseUrl + ' (inline)', result);
  }

  // ── Step 3: Download and Analyze Scripts ───────────────────

  const scriptsToAnalyze = scriptUrls.slice(0, maxScripts);

  for (const scriptUrl of scriptsToAnalyze) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(scriptUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (response.status !== 200) continue;

      // Check Content-Length before downloading
      const contentLength = Number(response.headers.get('content-length') ?? 0);
      if (contentLength > maxFileSize) {
        logger?.info('js-bundle-analyzer: script too large, skipping', {
          url: scriptUrl,
          size: contentLength,
        });
        continue;
      }

      const jsContent = await response.text();
      if (jsContent.length > maxFileSize) continue;

      const hasSourceMap = checkSourceMapReference(jsContent);

      result.scripts.push({
        url: scriptUrl,
        size: jsContent.length,
        hasSourceMap,
      });

      result.totalBytesAnalyzed += jsContent.length;

      // Collect for dependency CVE scanning
      jsContents.push({ content: jsContent, url: scriptUrl });

      // Scan for secrets
      scanForSecrets(jsContent, scriptUrl, result);

      // Scan for endpoints
      scanForEndpoints(jsContent, scriptUrl, result);

      // Scan for env leaks
      scanForEnvLeaks(jsContent, scriptUrl, result);

      // Check source map
      if (hasSourceMap) {
        const mapUrl = resolveSourceMapUrl(jsContent, scriptUrl);
        if (mapUrl) {
          const mapResult = await probeSourceMap(mapUrl, timeout, logger);
          result.sourceMaps.push(mapResult);
        }
      }

      await sleep(50);
    } catch {
      // Skip failed downloads
      continue;
    }
  }

  // Also check common sourcemap paths directly
  const commonMapPaths = [
    '/main.js.map',
    '/bundle.js.map',
    '/app.js.map',
    '/static/js/main.js.map',
    '/static/js/bundle.js.map',
    '/_next/static/chunks/main.js.map',
    '/_next/static/chunks/app.js.map',
    '/assets/index.js.map',
    '/build/static/js/main.js.map',
  ];

  const checkedMapUrls = new Set(result.sourceMaps.map((m) => m.url));

  for (const mapPath of commonMapPaths) {
    const mapUrl = baseUrl + mapPath;
    if (checkedMapUrls.has(mapUrl)) continue;

    const mapResult = await probeSourceMap(mapUrl, timeout);
    if (mapResult.accessible) {
      result.sourceMaps.push(mapResult);
    }

    await sleep(50);
  }

  // ── Step 4: Secret Live Verification ─────────────────────────

  if (config.secretVerifier && result.secrets.length > 0) {
    logger?.info('js-bundle-analyzer: verifying discovered secrets', {
      count: result.secrets.length,
    });

    // We need raw values for verification -- re-extract from JS content
    // Only verify secrets where we can extract the raw value
    for (const secret of result.secrets) {
      try {
        const rawValue = extractRawSecret(secret, jsContents);
        if (!rawValue) continue;

        const verResult = await config.secretVerifier.verify(rawValue);
        secret.verification = {
          verified: verResult.verified,
          active: verResult.active,
          service: verResult.service,
          permissions: verResult.permissions,
          identity: verResult.identity,
        };

        // Immediately dereference raw value
        // (Variable scope ensures it's eligible for GC)
      } catch {
        // Verification failure is non-fatal
      }
    }
  }

  // ── Step 5: Sourcemap Deep Recovery ─────────────────────────

  if (enableDeepRecovery) {
    const accessibleMaps = result.sourceMaps.filter((m) => m.accessible);
    for (const sourceMap of accessibleMaps) {
      try {
        const recovery = await withTimeout(
          recoverAndScan({
            sourcemapUrl: sourceMap.url,
            timeout,
            logger,
          }),
          timeout * 2,
          `Sourcemap recovery timeout: ${sourceMap.url}`,
        );
        if (recovery.secrets.length > 0 || recovery.envReferences.length > 0) {
          result.sourcemapRecoveries.push(recovery);
        }
      } catch (err) {
        logger?.warn('js-bundle-analyzer: sourcemap recovery failed', {
          url: sourceMap.url,
          error: String(err),
        });
      }
    }
  }

  // ── Step 6: Dependency CVE Scan ─────────────────────────────

  if (jsContents.length > 0) {
    const sourcemapSources = result.sourceMaps
      .filter((m) => m.accessible && m.sources)
      .map((m) => ({ sources: m.sources!, url: m.url }));

    result.dependencyCves = scanDependencyCves(jsContents, sourcemapSources, logger);
  }

  logger?.info('js-bundle-analyzer: scan complete', {
    scripts: result.scripts.length,
    secrets: result.secrets.length,
    verifiedSecrets: result.secrets.filter((s) => s.verification?.active).length,
    endpoints: result.endpoints.length,
    sourceMaps: result.sourceMaps.filter((m) => m.accessible).length,
    envLeaks: result.envLeaks.length,
    sourcemapRecoveries: result.sourcemapRecoveries.length,
    dependencyCves: result.dependencyCves?.cves.length ?? 0,
    totalBytes: result.totalBytesAnalyzed,
  });

  return result;
}

// ─── HTML Parsing ─────────────────────────────────────────────

function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();

  // Match <script src="...">
  const srcRegex = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let match;

  while ((match = srcRegex.exec(html)) !== null) {
    const src = match[1]!;
    const fullUrl = resolveUrl(src, baseUrl);
    if (fullUrl && !seen.has(fullUrl) && isJsUrl(fullUrl)) {
      seen.add(fullUrl);
      urls.push(fullUrl);
    }
  }

  return urls;
}

function extractInlineScripts(html: string): string[] {
  const scripts: string[] = [];
  const inlineRegex = /<script(?:\s[^>]*)?>([^<]+)<\/script>/gi;
  let match;

  while ((match = inlineRegex.exec(html)) !== null) {
    const content = match[1]!;
    if (content.trim().length > 20) {
      scripts.push(content);
    }
  }

  return scripts;
}

// ─── Secret Scanning ──────────────────────────────────────────

function scanForSecrets(
  content: string,
  scriptUrl: string,
  result: JsBundleResult,
): void {
  // Limit regex scanning to first 500KB to avoid ReDoS
  const scanContent = content.length > 512_000 ? content.slice(0, 512_000) : content;

  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(scanContent);
    if (match) {
      const value = match[1] ?? match[0];
      const masked = maskSecret(value);
      const idx = match.index;
      const contextStart = Math.max(0, idx - 20);
      const contextEnd = Math.min(scanContent.length, idx + match[0].length + 20);
      const context = scanContent.slice(contextStart, contextEnd).replace(/\n/g, ' ');

      // Deduplicate
      const exists = result.secrets.some(
        (s) => s.type === pattern.type && s.masked === masked,
      );

      if (!exists) {
        result.secrets.push({
          type: pattern.type,
          masked,
          scriptUrl,
          pattern: pattern.name,
          context: context.slice(0, MAX_CONTEXT_LENGTH),
        });
      }
    }
  }
}

// ─── Endpoint Scanning ────────────────────────────────────────

function scanForEndpoints(
  content: string,
  scriptUrl: string,
  result: JsBundleResult,
): void {
  const seen = new Set(result.endpoints.map((e) => e.url));

  for (const { regex, category } of ENDPOINT_PATTERNS) {
    // Reset regex state
    const re = new RegExp(regex.source, regex.flags);
    let match;

    while ((match = re.exec(content)) !== null) {
      const url = match[1]!;

      // Filter noise
      if (isNoiseUrl(url)) continue;
      if (seen.has(url)) continue;

      seen.add(url);
      result.endpoints.push({ url, category, scriptUrl });
    }
  }
}

// ─── Source Map Probing ───────────────────────────────────────

function checkSourceMapReference(jsContent: string): boolean {
  return /\/[/*]#\s*sourceMappingURL\s*=\s*\S+/.test(jsContent);
}

function resolveSourceMapUrl(jsContent: string, scriptUrl: string): string | null {
  const match = /\/[/*]#\s*sourceMappingURL\s*=\s*(\S+)/.exec(jsContent);
  if (!match) return null;

  const mapRef = match[1]!;

  // Data URL source maps (embedded)
  if (mapRef.startsWith('data:')) return null;

  return resolveUrl(mapRef, scriptUrl);
}

async function probeSourceMap(
  url: string,
  timeout: number,
  logger?: SpearLogger,
): Promise<DiscoveredSourceMap> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.status !== 200) {
      return { url, accessible: false };
    }

    const body = await response.text();
    const size = body.length;

    // Try to parse as JSON sourcemap
    let sourceCount: number | undefined;
    let sources: string[] | undefined;

    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed.sources)) {
        sources = (parsed.sources as string[]).slice(0, 50);
        sourceCount = (parsed.sources as string[]).length;
      }
    } catch {
      // Not valid JSON — might still be a sourcemap
    }

    logger?.info('js-bundle-analyzer: sourcemap found', {
      url,
      size,
      sourceCount,
    });

    return { url, accessible: true, size, sourceCount, sources };
  } catch {
    return { url, accessible: false };
  }
}

// ─── Environment Variable Leak Scanning ──────────────────────

function scanForEnvLeaks(
  content: string,
  scriptUrl: string,
  result: JsBundleResult,
): void {
  const seen = new Set(result.envLeaks.map((e) => e.variable));

  for (const { framework, regex } of ENV_LEAK_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    let match;

    while ((match = re.exec(content)) !== null) {
      const variable = match[1]!;
      const rawValue = match[2]!;

      if (seen.has(variable)) continue;
      // Filter noise: skip if value looks like a placeholder or is very short
      if (rawValue.length < 3 || rawValue === 'undefined' || rawValue === 'null' || rawValue === 'true' || rawValue === 'false') continue;

      seen.add(variable);

      const maskedValue = rawValue.length > 12
        ? rawValue.slice(0, 8) + '***'
        : rawValue.slice(0, 4) + '***';

      const idx = match.index;
      const contextStart = Math.max(0, idx - 10);
      const contextEnd = Math.min(content.length, idx + match[0].length + 10);
      const context = content.slice(contextStart, contextEnd).replace(/\n/g, ' ').slice(0, MAX_CONTEXT_LENGTH);

      result.envLeaks.push({
        framework,
        variable,
        maskedValue,
        isSensitive: isSensitiveEnvVar(variable),
        scriptUrl,
        context,
      });
    }
  }
}

// ─── Raw Secret Extraction (for verification) ────────────────

function extractRawSecret(
  secret: DiscoveredSecret,
  jsContents: Array<{ content: string; url: string }>,
): string | null {
  // Find the matching pattern
  const pattern = SECRET_PATTERNS.find((p) => p.name === secret.pattern);
  if (!pattern) return null;

  // Search the JS content where the secret was found
  for (const { content, url } of jsContents) {
    if (url !== secret.scriptUrl && !secret.scriptUrl.includes('(inline)')) continue;

    const match = pattern.regex.exec(content);
    if (match) {
      return match[1] ?? match[0];
    }
  }

  return null;
}

// ─── Helpers ──────────────────────────────────────────────────

function resolveUrl(ref: string, base: string): string | null {
  try {
    if (ref.startsWith('http://') || ref.startsWith('https://')) {
      return ref;
    }
    return new URL(ref, base).href;
  } catch {
    return null;
  }
}

function isJsUrl(url: string): boolean {
  const path = new URL(url).pathname.toLowerCase();
  return path.endsWith('.js') || path.endsWith('.mjs') || path.includes('/chunks/');
}

function isNoiseUrl(url: string): boolean {
  // Filter common noise patterns
  if (url.length < 5) return true;
  if (url.includes('googleapis.com/identitytoolkit')) return true;
  if (url.includes('cdn.jsdelivr.net')) return true;
  if (url.includes('unpkg.com')) return true;
  if (url.includes('cdnjs.cloudflare.com')) return true;
  if (url.includes('fonts.googleapis.com')) return true;
  if (url.includes('www.google-analytics.com')) return true;
  if (url.includes('t1.daumcdn.net')) return true;
  if (url.includes('developers.kakao.com')) return true;
  if (url.includes('openapi.map.naver.com/openapi/v3/maps.js')) return true; // Naver Maps SDK loader
  if (/^\/[a-z]$/.test(url)) return true; // Single-letter paths
  return false;
}

function maskSecret(value: string): string {
  if (value.length <= 8) return '***';
  return value.slice(0, 8) + '***';
}

/** Race a promise against a timeout. Rejects with message if timeout expires. */
function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

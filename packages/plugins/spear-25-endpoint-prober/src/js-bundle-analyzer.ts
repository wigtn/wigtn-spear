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

import type { SpearLogger } from '@wigtn/shared';

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
];

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

  logger?.info('js-bundle-analyzer: starting', { baseUrl });

  const result: JsBundleResult = {
    scripts: [],
    secrets: [],
    endpoints: [],
    sourceMaps: [],
    totalBytesAnalyzed: 0,
  };

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

      // Scan for secrets
      scanForSecrets(jsContent, scriptUrl, result);

      // Scan for endpoints
      scanForEndpoints(jsContent, scriptUrl, result);

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

  logger?.info('js-bundle-analyzer: scan complete', {
    scripts: result.scripts.length,
    secrets: result.secrets.length,
    endpoints: result.endpoints.length,
    sourceMaps: result.sourceMaps.filter((m) => m.accessible).length,
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
  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(content);
    if (match) {
      const value = match[1] ?? match[0];
      const masked = maskSecret(value);
      const idx = match.index;
      const contextStart = Math.max(0, idx - 20);
      const contextEnd = Math.min(content.length, idx + match[0].length + 20);
      const context = content.slice(contextStart, contextEnd).replace(/\n/g, ' ');

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
  if (/^\/[a-z]$/.test(url)) return true; // Single-letter paths
  return false;
}

function maskSecret(value: string): string {
  if (value.length <= 8) return '***';
  return value.slice(0, 8) + '***';
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

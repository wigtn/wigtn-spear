/**
 * SPEAR-23: Live Prompt Injection Runner Plugin
 *
 * Sends actual prompt injection payloads to LLM API endpoints and
 * analyzes responses to determine if injection succeeded. This is the
 * live attack counterpart to SPEAR-06's static analysis approach.
 *
 * Operating modes:
 *
 *   Safe mode (default):
 *     Performs static analysis of source files to detect prompt injection
 *     vulnerability patterns. Looks for unsanitized user input flowing
 *     into LLM API calls, missing input validation, and hardcoded prompts
 *     without injection guards.
 *
 *   Aggressive mode with liveAttack:
 *     Sends 22 injection payloads across 8 categories to the target LLM
 *     endpoint. Analyzes responses using indicator-based matching and
 *     heuristic detection. Yields a Finding for each successful injection.
 *
 * Architecture:
 *   - payloads.ts:          22-payload library across 8 attack categories
 *   - http-client.ts:       OpenAI-compatible HTTP client (built-in fetch)
 *   - response-analyzer.ts: Indicator matching + heuristic analysis engine
 *   - index.ts:             Plugin orchestration and Finding generation
 *
 * Rate limiting:
 *   - Uses @wigtn/core RateLimiter for request throttling
 *   - Default: 120 RPM, 2 concurrent requests
 *   - 500ms minimum sleep between payloads
 *   - Configurable via liveAttack.maxRequests and liveAttack.concurrency
 *
 * References:
 *   - OWASP LLM01: Prompt Injection
 *   - CWE-77: Improper Neutralization of Special Elements used in a Command
 *   - MITRE ATLAS AML.T0051: LLM Prompt Injection
 */

import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
  Severity,
} from '@wigtn/shared';
import { RateLimiter } from '@wigtn/core';

import { PAYLOADS, PAYLOAD_COUNT, type InjectionPayload } from './payloads.js';
import { LLMHttpClient } from './http-client.js';
import { analyzeResponse, analyzeErrorResponse, type AnalysisResult } from './response-analyzer.js';

// ─── Constants ──────────────────────────────────────────────

/** Minimum delay between payloads (milliseconds). */
const INTER_PAYLOAD_DELAY_MS = 500;

/** Default request timeout (milliseconds). */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Default rate limiter: 120 requests per minute, 2 concurrent. */
const DEFAULT_RPM = 120;
const DEFAULT_CONCURRENCY = 2;

/** Rate limiter service identifier for this plugin. */
const RATE_LIMITER_SERVICE = 'spear-23-live';

/** Maximum file size to scan in safe mode (512 KB). */
const MAX_FILE_SIZE_BYTES = 512 * 1024;

/** File extensions to scan in safe mode. */
const SCAN_EXTENSIONS: ReadonlySet<string> = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.rb', '.go', '.rs', '.java', '.kt',
  '.vue', '.svelte',
]);

/** Directories to skip during file traversal. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules', '.git', 'dist', 'build', 'out',
  '.next', '.nuxt', '__pycache__', '.venv', 'venv',
  'vendor', 'target', '.turbo', 'coverage',
  '.nyc_output', '.cache', '.parcel-cache',
]);

/**
 * Regex patterns that detect LLM API call sites where user input may
 * flow into prompts without sanitization. Used in safe mode.
 */
const VULNERABILITY_PATTERNS: readonly {
  id: string;
  pattern: RegExp;
  description: string;
  severity: Severity;
}[] = [
  {
    id: 'unsanitized-user-prompt',
    pattern: /(?:messages|prompt)\s*[=:]\s*.*(?:req\.body|req\.query|req\.params|request\.body|request\.get|input\(|args\[|argv)/i,
    description: 'User input flows directly into LLM prompt without sanitization',
    severity: 'critical',
  },
  {
    id: 'openai-no-validation',
    pattern: /(?:openai|client)\.(?:chat\.completions\.create|complete|generate)\s*\(\s*\{[^}]*messages\s*:\s*\[.*\$\{/i,
    description: 'Template literal with user input in OpenAI API call',
    severity: 'critical',
  },
  {
    id: 'fetch-llm-user-input',
    pattern: /fetch\s*\(\s*['"](https?:\/\/[^'"]*(?:openai|anthropic|azure\.com\/openai|localhost:\d+\/v1))/i,
    description: 'Direct fetch to LLM API endpoint detected',
    severity: 'medium',
  },
  {
    id: 'prompt-concat-user-input',
    pattern: /(?:prompt|system_message|user_message)\s*(?:\+|=|\+=)\s*.*(?:user_input|query|message|request|input)/i,
    description: 'User input concatenated into prompt variable',
    severity: 'high',
  },
  {
    id: 'no-input-length-check',
    pattern: /(?:chat\.completions\.create|generate|complete)\s*\([^)]*\)\s*(?!.*(?:maxLength|max_length|truncate|slice|substring|limit))/i,
    description: 'LLM API call without input length validation',
    severity: 'medium',
  },
  {
    id: 'hardcoded-system-prompt',
    pattern: /(?:role|system)\s*[=:]\s*['"`](?:system|assistant)['"`]\s*,\s*(?:content)\s*[=:]\s*['"`](?:You are|Your role|Your task)/i,
    description: 'Hardcoded system prompt without injection guards',
    severity: 'low',
  },
  {
    id: 'missing-output-filter',
    pattern: /(?:choices\[0\]|completion|response)\.(?:message\.content|text)\s*(?!.*(?:sanitize|filter|escape|validate|check))/i,
    description: 'LLM output used without output filtering or validation',
    severity: 'medium',
  },
  {
    id: 'f-string-prompt-injection',
    pattern: /f['"].*\{(?:user_input|query|request|message|prompt)\}.*['"].*(?:openai|anthropic|llm|chat|complete)/i,
    description: 'Python f-string with user input in LLM API context',
    severity: 'critical',
  },
];

// ─── Plugin Metadata ────────────────────────────────────────

const metadata: PluginMetadata = {
  id: 'live-prompt-inject',
  name: 'Live Prompt Injection Runner',
  version: '0.1.0',
  author: 'WIGTN Team',
  description:
    'Sends actual prompt injection payloads to LLM endpoints and analyzes responses. ' +
    `Includes ${PAYLOAD_COUNT} payloads across 8 categories: system prompt extraction, ` +
    'instruction override, role hijack, output manipulation, data exfiltration, ' +
    'encoding bypass, jailbreak, and context overflow.',
  severity: 'critical',
  tags: ['prompt-injection', 'llm', 'live-attack', 'ai-security'],
  references: ['OWASP-LLM01', 'CWE-77'],
  safeMode: false,
  requiresNetwork: true,
  supportedPlatforms: ['darwin', 'linux', 'win32'],
  permissions: ['net:outbound'],
  trustLevel: 'builtin',
};

// ─── Helpers ────────────────────────────────────────────────

/** Sleep for a given number of milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Check whether a file path has a scannable extension. */
function isScannable(filePath: string): boolean {
  return SCAN_EXTENSIONS.has(extname(filePath).toLowerCase());
}

/**
 * Map a payload severity string to the Finding severity type.
 * The payload severities already align with the Severity type.
 */
function toSeverity(s: InjectionPayload['severity']): Severity {
  return s;
}

// ─── File Walker (Safe Mode) ─────────────────────────────────

/**
 * Iterative directory walker for safe mode static analysis.
 * Yields absolute file paths for scannable source files.
 */
async function* walkFiles(
  root: string,
  excludePatterns: string[],
): AsyncGenerator<string> {
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: string[];

    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue;
      if (entry.startsWith('.')) continue;

      const fullPath = join(dir, entry);
      const relPath = relative(root, fullPath);

      if (excludePatterns.some((p) => relPath.startsWith(p) || relPath.includes(p))) {
        continue;
      }

      try {
        const stat = await lstat(fullPath);
        if (stat.isSymbolicLink()) continue;

        if (stat.isDirectory()) {
          stack.push(fullPath);
        } else if (stat.isFile() && stat.size <= MAX_FILE_SIZE_BYTES && isScannable(fullPath)) {
          yield fullPath;
        }
      } catch {
        continue;
      }
    }
  }
}

// ─── Safe Mode Scanner ──────────────────────────────────────

/**
 * Scan a file's content for prompt injection vulnerability patterns.
 * Returns Findings for each matched pattern.
 */
function scanFileForVulnerabilities(
  content: string,
  filePath: string,
  basePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const relPath = relative(basePath, filePath);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    for (const vuln of VULNERABILITY_PATTERNS) {
      if (vuln.pattern.test(line)) {
        findings.push({
          ruleId: `spear-23/static/${vuln.id}`,
          severity: vuln.severity,
          message: `Prompt injection vulnerability: ${vuln.description}`,
          file: relPath,
          line: i + 1,
          column: 1,
          cvss: vuln.severity === 'critical' ? 9.1 : vuln.severity === 'high' ? 7.5 : 5.0,
          mitreTechniques: ['AML.T0051'],
          remediation:
            'Sanitize user input before passing to LLM APIs. Implement input validation, ' +
            'output filtering, and system prompt isolation. Consider using a prompt injection ' +
            'detection layer.',
          metadata: {
            pluginId: 'live-prompt-inject',
            scanMode: 'static',
            patternId: vuln.id,
            matchedLine: line.trim().slice(0, 200),
          },
        });
      }
    }
  }

  return findings;
}

// ─── Live Mode Runner ───────────────────────────────────────

/**
 * Build a Finding from a successful injection analysis result.
 */
function buildLiveFinding(
  payload: InjectionPayload,
  analysis: AnalysisResult,
  requestUrl: string,
  requestBody: string,
  responseStatus: number,
  durationMs: number,
): Finding {
  return {
    ruleId: `spear-23/${payload.id}`,
    severity: toSeverity(payload.severity),
    message: `Prompt injection succeeded: ${payload.name} - ${payload.description}`,
    cvss: 9.1,
    mitreTechniques: payload.mitre,
    remediation:
      'Implement input sanitization, output filtering, and system prompt isolation. ' +
      'Use a dedicated prompt injection detection layer. Consider implementing ' +
      'response validation and canary token monitoring.',
    metadata: {
      pluginId: 'live-prompt-inject',
      category: payload.category,
      payloadId: payload.id,
      request: {
        url: requestUrl,
        body: requestBody.slice(0, 2000),
      },
      response: {
        status: responseStatus,
        content: analysis.responseText.slice(0, 2000),
      },
      confidence: analysis.confidence,
      evidence: analysis.evidence,
      matchedIndicators: analysis.matchedIndicators,
      durationMs,
    },
  };
}

// ─── Plugin Implementation ──────────────────────────────────

class LivePromptInjectPlugin implements SpearPlugin {
  metadata: PluginMetadata = metadata;

  private rateLimiter: RateLimiter | null = null;

  async setup(context: PluginContext): Promise<void> {
    context.logger.info('spear-23: initializing live prompt injection runner', {
      mode: context.mode,
      hasLiveAttack: !!context.liveAttack,
      payloadCount: PAYLOAD_COUNT,
    });

    // Initialize rate limiter
    this.rateLimiter = new RateLimiter({
      rpm: DEFAULT_RPM,
      concurrent: DEFAULT_CONCURRENCY,
    });

    // Apply custom concurrency from live attack config
    if (context.liveAttack) {
      const concurrency = context.liveAttack.concurrency ?? DEFAULT_CONCURRENCY;
      this.rateLimiter.setServiceLimit(RATE_LIMITER_SERVICE, {
        rpm: DEFAULT_RPM,
        concurrent: concurrency,
      });

      context.logger.info('spear-23: live attack configured', {
        targetUrl: context.liveAttack.targetUrl,
        hasApiKey: !!context.liveAttack.apiKey,
        timeout: context.liveAttack.timeout ?? DEFAULT_TIMEOUT_MS,
        maxRequests: context.liveAttack.maxRequests ?? PAYLOAD_COUNT,
        concurrency,
      });
    }
  }

  async *scan(
    target: ScanTarget,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    // Determine which mode to operate in
    const isLiveMode = context.mode === 'aggressive' && !!context.liveAttack;

    if (isLiveMode) {
      yield* this.runLiveAttack(context);
    } else {
      yield* this.runStaticScan(target, context);
    }
  }

  async teardown(context: PluginContext): Promise<void> {
    this.rateLimiter = null;
    context.logger.debug('spear-23: teardown complete');
  }

  // ─── Static Analysis (Safe Mode) ───────────────────────────

  /**
   * Scan source files for prompt injection vulnerability patterns.
   * Operates without network access -- purely static analysis.
   */
  private async *runStaticScan(
    target: ScanTarget,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const excludePatterns = target.exclude ?? [];
    let filesScanned = 0;
    let totalFindings = 0;

    context.logger.info('spear-23: starting static scan', {
      target: target.path,
      patternCount: VULNERABILITY_PATTERNS.length,
    });

    for await (const filePath of walkFiles(target.path, excludePatterns)) {
      filesScanned++;

      let content: string;
      try {
        content = await readFile(filePath, 'utf-8');
      } catch {
        continue;
      }

      const findings = scanFileForVulnerabilities(content, filePath, target.path);

      for (const finding of findings) {
        totalFindings++;
        yield finding;
      }
    }

    context.logger.info('spear-23: static scan complete', {
      filesScanned,
      totalFindings,
    });
  }

  // ─── Live Attack (Aggressive Mode) ────────────────────────

  /**
   * Execute live prompt injection payloads against the target LLM endpoint.
   *
   * Sends each payload from the library to the configured target URL,
   * analyzes the response, and yields a Finding for each successful
   * injection.
   */
  private async *runLiveAttack(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;
    const maxRequests = liveAttack.maxRequests ?? PAYLOAD_COUNT;
    const timeout = liveAttack.timeout ?? DEFAULT_TIMEOUT_MS;

    // Initialize HTTP client
    const client = new LLMHttpClient({
      baseUrl: liveAttack.targetUrl,
      apiKey: liveAttack.apiKey,
      customHeaders: liveAttack.headers,
      timeout,
      logger: context.logger,
    });

    // Select payloads (respect maxRequests limit)
    const payloadsToRun = PAYLOADS.slice(0, maxRequests);

    context.logger.info('spear-23: starting live attack', {
      targetUrl: liveAttack.targetUrl,
      payloadCount: payloadsToRun.length,
      timeout,
    });

    let succeeded = 0;
    let failed = 0;
    let errors = 0;

    for (let i = 0; i < payloadsToRun.length; i++) {
      const payload = payloadsToRun[i]!;

      context.logger.debug('spear-23: sending payload', {
        index: i + 1,
        total: payloadsToRun.length,
        payloadId: payload.id,
        category: payload.category,
        name: payload.name,
      });

      // Acquire rate limiter slot
      if (this.rateLimiter) {
        await this.rateLimiter.acquire(RATE_LIMITER_SERVICE);
      }

      try {
        // Send the payload
        const response = await client.sendPayload(
          payload.userMessage,
          payload.systemOverride,
        );

        // Analyze the response
        let analysis: AnalysisResult;

        if (response.status >= 200 && response.status < 300 && response.parsed) {
          // Successful HTTP response with parsed content
          analysis = analyzeResponse(payload, response.parsed.content);
        } else if (response.status >= 200 && response.status < 300) {
          // Successful HTTP response but unparseable -- analyze raw body
          analysis = analyzeResponse(payload, response.body);
        } else {
          // HTTP error
          analysis = analyzeErrorResponse(payload, response.status, response.body);
          errors++;
        }

        context.logger.debug('spear-23: analysis complete', {
          payloadId: payload.id,
          succeeded: analysis.injectionSucceeded,
          confidence: analysis.confidence,
          status: response.status,
          durationMs: response.durationMs,
        });

        if (analysis.injectionSucceeded) {
          succeeded++;

          // Build request body string for evidence
          const requestBody = JSON.stringify({
            messages: [
              ...(payload.systemOverride
                ? [{ role: 'system', content: payload.systemOverride }]
                : []),
              { role: 'user', content: payload.userMessage },
            ],
            max_tokens: 512,
            temperature: 0.0,
          });

          yield buildLiveFinding(
            payload,
            analysis,
            liveAttack.targetUrl,
            requestBody,
            response.status,
            response.durationMs,
          );
        } else {
          failed++;
        }
      } finally {
        // Release rate limiter slot
        if (this.rateLimiter) {
          this.rateLimiter.release(RATE_LIMITER_SERVICE);
        }
      }

      // Enforce minimum delay between payloads
      if (i < payloadsToRun.length - 1) {
        await sleep(INTER_PAYLOAD_DELAY_MS);
      }
    }

    context.logger.info('spear-23: live attack complete', {
      total: payloadsToRun.length,
      succeeded,
      failed,
      errors,
      successRate: payloadsToRun.length > 0
        ? `${Math.round((succeeded / payloadsToRun.length) * 100)}%`
        : '0%',
    });
  }
}

// ─── Default Export ─────────────────────────────────────────

export default new LivePromptInjectPlugin();

// ─── Re-exports ─────────────────────────────────────────────

export { PAYLOADS, PAYLOAD_COUNT, getPayloadsByCategory, getPayloadById, getCategories } from './payloads.js';
export type { InjectionPayload, PayloadCategory, SuccessIndicator } from './payloads.js';
export { LLMHttpClient } from './http-client.js';
export type { LLMRequest, LLMResponse, LLMRequestBody, HttpClientConfig } from './http-client.js';
export { analyzeResponse, analyzeErrorResponse } from './response-analyzer.js';
export type { AnalysisResult } from './response-analyzer.js';

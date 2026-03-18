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
import { WsAttackClient, isWebSocketUrl, detectWsPreset } from './ws-client.js';
import { executeRelayChain } from './relay-chain.js';
import type { RelayChainConfig, RelayAttackResult } from './relay-chain.js';
import { analyzeResponse, analyzeErrorResponse, type AnalysisResult } from './response-analyzer.js';
import { createJudgeFromConfig, type LLMJudge, type JudgeResult } from './llm-judge.js';
import { runMultiTurnAttacks, type MultiTurnResult } from './multi-turn-engine.js';
import { fingerprintModel, type FingerprintResult } from './model-fingerprint.js';

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

/** Redact sensitive values (Bearer tokens, API keys) from metadata strings. */
function sanitizeForMetadata(text: string): string {
  return text
    .replace(/Bearer\s+[A-Za-z0-9_\-./+=]{8,}/gi, 'Bearer [REDACTED]')
    .replace(/sk-[a-zA-Z0-9_-]{8,}/g, 'sk-[REDACTED]')
    .replace(/sk-proj-[a-zA-Z0-9_-]{8,}/g, 'sk-proj-[REDACTED]')
    .replace(/sk-ant-[a-zA-Z0-9_-]{8,}/g, 'sk-ant-[REDACTED]')
    .replace(/key[=:]\s*["']?[A-Za-z0-9_\-./+=]{16,}/gi, 'key=[REDACTED]')
    .replace(/api[_-]?key[=:]\s*["']?[A-Za-z0-9_\-./+=]{16,}/gi, 'api_key=[REDACTED]');
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
        body: sanitizeForMetadata(requestBody).slice(0, 2000),
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
      const targetUrl = context.liveAttack!.targetUrl;
      const hasRelayPhone = !!context.liveAttack!.headers?.['X-Relay-Phone'];

      if (isWebSocketUrl(targetUrl)) {
        yield* this.runWsLiveAttack(context);
      } else if (hasRelayPhone || targetUrl.includes('/relay/')) {
        // Relay chain mode: REST → WS attack
        yield* this.runRelayChainAttack(context);
      } else {
        yield* this.runLiveAttack(context);
      }

      // ── Advanced Modes (require --judge-key) ──────────────

      const liveAttack = context.liveAttack!;
      const judge = createJudgeFromConfig({
        judgeApiKey: liveAttack.judgeApiKey,
        judgeModel: liveAttack.judgeModel,
        judgeProvider: liveAttack.judgeProvider,
        timeout: liveAttack.timeout,
        logger: context.logger,
      });

      if (judge) {
        // Multi-turn attacks (Crescendo + TAP)
        if (liveAttack.multiTurn) {
          yield* this.runMultiTurnAttacks(context, judge);
        }

        // Model fingerprinting / distillation detection
        yield* this.runModelFingerprint(context);
      }
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

  // ─── WebSocket Live Attack ──────────────────────────────────

  /**
   * Execute live prompt injection over WebSocket connections.
   *
   * Used for relay-style AI services (e.g., WIGVO) that accept user
   * text via WebSocket and return LLM-generated responses as captions.
   *
   * Attack flow:
   *   1. Probe WebSocket endpoint for reachability
   *   2. For each payload: connect, send text_input, collect captions
   *   3. Analyze collected text with the same indicator engine as HTTP mode
   *   4. Yield Finding for each successful injection
   */
  private async *runWsLiveAttack(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;
    const maxRequests = liveAttack.maxRequests ?? PAYLOAD_COUNT;
    const timeout = liveAttack.timeout ?? DEFAULT_TIMEOUT_MS;

    // Auto-detect protocol preset from URL
    const preset = detectWsPreset(liveAttack.targetUrl);

    const client = new WsAttackClient({
      url: liveAttack.targetUrl,
      timeout,
      responseWaitMs: 5000,
      preset,
      logger: context.logger,
    });

    // Probe connectivity first
    const probe = await client.probe();
    if (!probe.reachable) {
      context.logger.error('spear-23: WebSocket endpoint unreachable', {
        url: liveAttack.targetUrl,
        error: probe.error,
      });
      return;
    }

    context.logger.info('spear-23: WebSocket endpoint reachable', {
      url: liveAttack.targetUrl,
      preset,
      latencyMs: probe.latencyMs,
    });

    const payloadsToRun = PAYLOADS.slice(0, maxRequests);

    context.logger.info('spear-23: starting WebSocket live attack', {
      targetUrl: liveAttack.targetUrl,
      preset,
      payloadCount: payloadsToRun.length,
      timeout,
    });

    let succeeded = 0;
    let failed = 0;
    let errors = 0;

    for (let i = 0; i < payloadsToRun.length; i++) {
      const payload = payloadsToRun[i]!;

      context.logger.debug('spear-23: WS payload', {
        index: i + 1,
        total: payloadsToRun.length,
        payloadId: payload.id,
        category: payload.category,
      });

      // Acquire rate limiter slot
      if (this.rateLimiter) {
        await this.rateLimiter.acquire(RATE_LIMITER_SERVICE);
      }

      try {
        const result = await client.sendPayload(payload.userMessage);

        if (!result.connected) {
          errors++;
          context.logger.debug('spear-23: WS connection failed', {
            payloadId: payload.id,
            error: result.error,
          });
          continue;
        }

        if (result.responseText) {
          // Analyze collected WS response text the same way as HTTP
          const analysis = analyzeResponse(payload, result.responseText);

          context.logger.debug('spear-23: WS analysis complete', {
            payloadId: payload.id,
            succeeded: analysis.injectionSucceeded,
            confidence: analysis.confidence,
            fragments: result.fragments.length,
            durationMs: result.durationMs,
          });

          if (analysis.injectionSucceeded) {
            succeeded++;

            yield buildLiveFinding(
              payload,
              analysis,
              liveAttack.targetUrl,
              payload.userMessage,
              200, // WS has no HTTP status; use 200 as placeholder
              result.durationMs,
            );
          } else {
            failed++;
          }
        } else {
          failed++;
        }
      } finally {
        if (this.rateLimiter) {
          this.rateLimiter.release(RATE_LIMITER_SERVICE);
        }
      }

      // Enforce minimum delay between payloads
      if (i < payloadsToRun.length - 1) {
        await sleep(INTER_PAYLOAD_DELAY_MS);
      }
    }

    context.logger.info('spear-23: WebSocket live attack complete', {
      total: payloadsToRun.length,
      succeeded,
      failed,
      errors,
      successRate: payloadsToRun.length > 0
        ? `${Math.round((succeeded / payloadsToRun.length) * 100)}%`
        : '0%',
    });
  }

  // ─── Relay Chain Attack (REST → WS) ───────────────────────

  /**
   * Execute a full relay chain attack:
   *   1. POST /relay/calls/start → get WS URL
   *   2. Connect to WS, send injection payloads
   *   3. Collect responses
   *   4. POST /relay/calls/{id}/end → cleanup
   *
   * This method is called when the target URL points to a relay server
   * with the relay chain config provided in liveAttack options.
   *
   * Usage from CLI:
   *   spear attack <relay-url> --module live-prompt-inject \
   *     --header "X-Relay-Phone:+1234567890" \
   *     --header "X-Relay-Mode:text_to_voice"
   */
  async *runRelayChainAttack(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;
    const maxPayloads = Math.min(liveAttack.maxRequests ?? 5, 10);

    // Extract relay config from custom headers
    const phoneNumber = liveAttack.headers?.['X-Relay-Phone'] ?? '';
    const communicationMode =
      (liveAttack.headers?.['X-Relay-Mode'] as RelayChainConfig['communicationMode']) ??
      'text_to_voice';
    const systemPromptOverride = liveAttack.headers?.['X-Relay-Prompt-Override'];

    if (!phoneNumber) {
      context.logger.error(
        'spear-23: relay chain requires phone number. ' +
        'Pass --header "X-Relay-Phone:+1234567890"',
      );
      return;
    }

    context.logger.info('spear-23: starting relay chain attack', {
      relayUrl: liveAttack.targetUrl,
      phoneNumber: phoneNumber.slice(0, 4) + '****',
      communicationMode,
      hasPromptOverride: !!systemPromptOverride,
      maxPayloads,
    });

    // Select payloads
    const payloadsToSend = PAYLOADS.slice(0, maxPayloads);
    const payloadTexts = payloadsToSend.map((p) => p.userMessage);

    const chainResult = await executeRelayChain(
      {
        relayBaseUrl: liveAttack.targetUrl,
        phoneNumber,
        communicationMode,
        systemPromptOverride,
        timeout: liveAttack.timeout ?? 15_000,
        responseWaitMs: 5_000,
        maxPayloads,
        logger: context.logger,
      },
      payloadTexts,
    );

    // Finding: system_prompt_override accepted
    if (chainResult.promptOverrideAccepted) {
      yield {
        ruleId: 'spear-23/relay-prompt-override',
        severity: 'critical',
        message:
          'Relay API accepted system_prompt_override parameter — ' +
          'direct prompt injection via REST API without authentication',
        cvss: 9.8,
        mitreTechniques: ['AML.T0051'],
        remediation:
          'Remove system_prompt_override from public API. ' +
          'System prompts should be server-side only and not user-controllable.',
        metadata: {
          pluginId: 'live-prompt-inject',
          category: 'relay_prompt_override',
          relayUrl: liveAttack.targetUrl,
          callId: chainResult.session.callId,
          analysisType: 'live',
        },
      };
    }

    // Analyze each payload response
    let succeeded = 0;
    for (let i = 0; i < chainResult.payloadResults.length; i++) {
      const wsResult = chainResult.payloadResults[i]!;
      const payload = payloadsToSend[i]!;

      if (!wsResult.responseText) continue;

      const analysis = analyzeResponse(payload, wsResult.responseText);

      if (analysis.injectionSucceeded) {
        succeeded++;
        yield buildLiveFinding(
          payload,
          analysis,
          chainResult.session.wsUrl || liveAttack.targetUrl,
          wsResult.sent,
          200,
          wsResult.durationMs,
        );
      }
    }

    context.logger.info('spear-23: relay chain attack complete', {
      callId: chainResult.session.callId,
      payloadsSent: chainResult.payloadResults.length,
      injectionSucceeded: succeeded,
      sessionCleaned: chainResult.cleaned,
      totalDurationMs: chainResult.totalDurationMs,
    });
  }

  // ─── Multi-Turn Attack Mode ─────────────────────────────────

  /**
   * Run multi-turn attack strategies (Crescendo + TAP).
   * Requires --judge-key flag for LLM-based attack generation and judging.
   */
  private async *runMultiTurnAttacks(
    context: PluginContext,
    judge: LLMJudge,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;
    const strategy = liveAttack.multiTurnStrategy ?? 'both';

    context.logger.info('spear-23: starting multi-turn attacks', {
      strategy,
      targetUrl: liveAttack.targetUrl,
    });

    let totalResults = 0;
    let successCount = 0;

    for await (const result of runMultiTurnAttacks({
      targetUrl: liveAttack.targetUrl,
      targetApiKey: liveAttack.apiKey,
      targetHeaders: liveAttack.headers,
      targetTimeout: liveAttack.timeout,
      judge,
      strategy,
      logger: context.logger,
    })) {
      totalResults++;

      if (result.judgeResult.success) {
        successCount++;

        yield {
          ruleId: `spear-23/multi-turn-${result.strategy}/${result.objectiveId}`,
          severity: result.judgeResult.severity === 'info' ? 'high' : result.judgeResult.severity,
          message:
            `Multi-turn ${result.strategy} attack succeeded: ${result.objective} ` +
            `(${result.turns.length} turns, confidence: ${result.judgeResult.confidence.toFixed(2)})`,
          cvss: 9.1,
          mitreTechniques: ['AML.T0051'],
          confidence: result.judgeResult.confidence >= 0.8 ? 'confirmed' : 'high',
          remediation:
            `Target is vulnerable to ${result.strategy} multi-turn attacks. ` +
            'Implement conversation-level safety monitoring, not just per-message filtering. ' +
            'Consider tracking conversation context and detecting escalation patterns.',
          metadata: {
            pluginId: 'live-prompt-inject',
            category: `multi_turn_${result.strategy}`,
            strategy: result.strategy,
            objectiveId: result.objectiveId,
            objective: result.objective,
            turnCount: result.turns.length,
            judgeCategory: result.judgeResult.category,
            judgeEvidence: result.judgeResult.evidence,
            judgeConfidence: result.judgeResult.confidence,
            apiCalls: result.apiCalls,
            durationMs: result.durationMs,
            analysisType: 'live',
          },
        };
      }
    }

    context.logger.info('spear-23: multi-turn attacks complete', {
      totalObjectives: totalResults,
      succeeded: successCount,
    });
  }

  // ─── Model Fingerprinting ──────────────────────────────────

  /**
   * Fingerprint the target LLM to detect model downgrade/distillation.
   */
  private async *runModelFingerprint(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;

    context.logger.info('spear-23: starting model fingerprint');

    const result = await fingerprintModel({
      targetUrl: liveAttack.targetUrl,
      apiKey: liveAttack.apiKey,
      headers: liveAttack.headers,
      timeout: liveAttack.timeout,
      claimedModel: liveAttack.judgeModel, // Use judge model as reference for claimed model
      logger: context.logger,
    });

    if (result.downgradeDetected) {
      yield {
        ruleId: 'spear-23/model-downgrade',
        severity: 'high',
        message:
          `Model downgrade detected: ${result.evidence}`,
        cvss: 7.5,
        mitreTechniques: ['AML.T0047'],
        confidence: result.confidence >= 0.7 ? 'high' : 'medium',
        remediation:
          'Verify the model being served matches the advertised model. ' +
          'Model distillation or downgrade can reduce safety alignment and output quality.',
        metadata: {
          pluginId: 'live-prompt-inject',
          category: 'model_downgrade',
          detectedModel: result.detectedModel,
          claimedModel: result.claimedModel,
          confidence: result.confidence,
          signatureScores: result.signatureScores.slice(0, 3),
          probeCount: result.probeResults.length,
          analysisType: 'live',
        },
      };
    }

    // Always emit informational fingerprint finding
    yield {
      ruleId: 'spear-23/model-fingerprint',
      severity: 'info',
      message: `Model fingerprint: detected ${result.detectedModel} (confidence: ${result.confidence.toFixed(2)})`,
      metadata: {
        pluginId: 'live-prompt-inject',
        category: 'model_fingerprint',
        detectedModel: result.detectedModel,
        claimedModel: result.claimedModel,
        confidence: result.confidence,
        topSignatures: result.signatureScores.slice(0, 5),
        analysisType: 'live',
      },
    };

    context.logger.info('spear-23: model fingerprint complete', {
      detected: result.detectedModel,
      downgrade: result.downgradeDetected,
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
export { WsAttackClient, isWebSocketUrl, detectWsPreset } from './ws-client.js';
export type { WsClientConfig, WsPayloadResult, WsPreset } from './ws-client.js';
export { analyzeResponse, analyzeErrorResponse } from './response-analyzer.js';
export type { AnalysisResult } from './response-analyzer.js';
export { executeRelayChain } from './relay-chain.js';
export type { RelayChainConfig, RelayAttackResult, RelaySessionInfo } from './relay-chain.js';
export { LLMJudge, createJudgeFromConfig } from './llm-judge.js';
export type { JudgeConfig, JudgeResult } from './llm-judge.js';
export { runMultiTurnAttacks } from './multi-turn-engine.js';
export type { MultiTurnConfig, MultiTurnResult } from './multi-turn-engine.js';
export { fingerprintModel } from './model-fingerprint.js';
export type { FingerprintConfig, FingerprintResult } from './model-fingerprint.js';

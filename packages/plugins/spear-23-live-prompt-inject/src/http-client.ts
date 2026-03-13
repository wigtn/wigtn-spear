/**
 * SPEAR-23: HTTP Client for LLM API Requests
 *
 * Handles all outbound HTTP communication with LLM API endpoints.
 * Supports the OpenAI-compatible chat completions format, which covers
 * OpenAI, Azure OpenAI, local LLM servers (llama.cpp, vLLM, Ollama),
 * and most third-party AI APIs.
 *
 * Features:
 *   - OpenAI-compatible request/response format
 *   - Configurable timeouts with AbortController
 *   - Automatic Bearer token authentication
 *   - Custom header merging
 *   - Response body parsing with graceful degradation
 *   - Request duration measurement
 *   - No external dependencies (uses Node.js built-in fetch)
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ──────────────────────────────────────────────────

export interface LLMRequestBody {
  model?: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens?: number;
  temperature?: number;
}

export interface LLMRequest {
  url: string;
  method: 'POST';
  headers: Record<string, string>;
  body: LLMRequestBody;
}

export interface ParsedResponse {
  /** Extracted text content from the LLM response */
  content: string;
  /** Model identifier returned by the API */
  model?: string;
  /** Token usage statistics */
  usage?: { prompt_tokens: number; completion_tokens: number };
}

export interface LLMResponse {
  /** HTTP status code */
  status: number;
  /** Raw response body text */
  body: string;
  /** Response headers */
  headers: Record<string, string>;
  /** Request round-trip duration in milliseconds */
  durationMs: number;
  /** Parsed response (undefined if parsing failed) */
  parsed?: ParsedResponse;
}

export interface HttpClientConfig {
  /** Base URL for the LLM API (e.g., 'https://api.openai.com') */
  baseUrl: string;
  /** Bearer token for Authorization header */
  apiKey?: string;
  /** Additional headers to include in every request */
  customHeaders?: Record<string, string>;
  /** Request timeout in milliseconds (default: 30000) */
  timeout: number;
  /** Logger instance for debug output */
  logger: SpearLogger;
}

// ─── Constants ──────────────────────────────────────────────

/** Default timeout for LLM API requests (30 seconds). */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Maximum response body size to retain in evidence (2000 chars). */
const MAX_RESPONSE_BODY_LENGTH = 2000;

/** Default max_tokens for injection test requests (keep responses short). */
const DEFAULT_MAX_TOKENS = 512;

/** Default temperature for injection testing (deterministic). */
const DEFAULT_TEMPERATURE = 0.0;

// ─── Response Parser ────────────────────────────────────────

/**
 * Parse an OpenAI-compatible chat completion response.
 *
 * Handles the standard response format:
 * ```json
 * {
 *   "choices": [{ "message": { "content": "..." } }],
 *   "model": "gpt-4",
 *   "usage": { "prompt_tokens": 10, "completion_tokens": 20 }
 * }
 * ```
 *
 * Gracefully handles non-standard responses by returning undefined.
 */
function parseOpenAIResponse(body: string): ParsedResponse | undefined {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;

    // Extract content from choices array
    let content = '';
    const choices = json.choices;
    if (Array.isArray(choices) && choices.length > 0) {
      const firstChoice = choices[0] as Record<string, unknown>;
      const message = firstChoice?.message as Record<string, unknown> | undefined;
      if (message && typeof message.content === 'string') {
        content = message.content;
      }
      // Some APIs use 'text' instead of 'message.content'
      if (!content && typeof firstChoice?.text === 'string') {
        content = firstChoice.text;
      }
    }

    // Extract model name
    const model = typeof json.model === 'string' ? json.model : undefined;

    // Extract usage
    let usage: ParsedResponse['usage'];
    const rawUsage = json.usage as Record<string, unknown> | undefined;
    if (rawUsage) {
      const promptTokens = typeof rawUsage.prompt_tokens === 'number' ? rawUsage.prompt_tokens : 0;
      const completionTokens = typeof rawUsage.completion_tokens === 'number' ? rawUsage.completion_tokens : 0;
      usage = { prompt_tokens: promptTokens, completion_tokens: completionTokens };
    }

    if (content) {
      return { content, model, usage };
    }

    return undefined;
  } catch {
    // Not valid JSON or unexpected structure -- return undefined
    return undefined;
  }
}

/**
 * Extract response headers into a plain object.
 */
function extractHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

// ─── HTTP Client ────────────────────────────────────────────

/**
 * HTTP client for sending prompt injection payloads to LLM API endpoints.
 *
 * Uses the built-in Node.js `fetch` API (no external dependencies).
 * All requests are logged at debug level for evidence collection.
 */
export class LLMHttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly customHeaders: Record<string, string>;
  private readonly timeout: number;
  private readonly logger: SpearLogger;

  constructor(config: HttpClientConfig) {
    // Normalize base URL: strip trailing slash
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.customHeaders = config.customHeaders ?? {};
    this.timeout = config.timeout > 0 ? config.timeout : DEFAULT_TIMEOUT_MS;
    this.logger = config.logger;
  }

  /**
   * Send an injection payload to the LLM API endpoint.
   *
   * Constructs an OpenAI-compatible chat completion request with the
   * given user message and optional system override. The response is
   * parsed and returned with timing information.
   *
   * @param userMessage  - The injection payload text (sent as user role)
   * @param systemOverride - Optional system message to include
   * @returns The LLM response with parsed content and timing data
   */
  async sendPayload(userMessage: string, systemOverride?: string): Promise<LLMResponse> {
    const messages: Array<{ role: string; content: string }> = [];

    if (systemOverride) {
      messages.push({ role: 'system', content: systemOverride });
    }
    messages.push({ role: 'user', content: userMessage });

    const requestBody: LLMRequestBody = {
      messages,
      max_tokens: DEFAULT_MAX_TOKENS,
      temperature: DEFAULT_TEMPERATURE,
    };

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'WIGTN-SPEAR/0.1.0',
      ...this.customHeaders,
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    // Determine endpoint URL
    // If the base URL already ends with a path (e.g., /v1/chat/completions),
    // use it as-is. Otherwise, append the standard OpenAI endpoint.
    const url = this.resolveEndpointUrl();

    const request: LLMRequest = {
      url,
      method: 'POST',
      headers,
      body: requestBody,
    };

    this.logger.debug('spear-23: sending payload', {
      url,
      messageCount: messages.length,
      userMessageLength: userMessage.length,
    });

    const startTime = performance.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const durationMs = Math.round(performance.now() - startTime);
      const bodyText = await response.text();
      const responseHeaders = extractHeaders(response.headers);

      // Truncate body for evidence storage
      const truncatedBody = bodyText.length > MAX_RESPONSE_BODY_LENGTH
        ? bodyText.slice(0, MAX_RESPONSE_BODY_LENGTH) + '...[truncated]'
        : bodyText;

      // Parse the response
      const parsed = parseOpenAIResponse(bodyText);

      this.logger.debug('spear-23: response received', {
        status: response.status,
        durationMs,
        bodyLength: bodyText.length,
        parsed: !!parsed,
      });

      return {
        status: response.status,
        body: truncatedBody,
        headers: responseHeaders,
        durationMs,
        parsed,
      };
    } catch (error: unknown) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isTimeout = errorMessage.includes('abort');

      this.logger.debug('spear-23: request failed', {
        url,
        error: errorMessage,
        isTimeout,
        durationMs,
      });

      return {
        status: isTimeout ? 408 : 0,
        body: isTimeout ? 'Request timed out' : `Request failed: ${errorMessage}`,
        headers: {},
        durationMs,
        parsed: undefined,
      };
    }
  }

  /**
   * Resolve the full endpoint URL.
   *
   * If the base URL already contains a path that looks like an API endpoint
   * (contains '/chat/completions' or '/generate' etc.), use it as-is.
   * Otherwise append the standard OpenAI chat completions path.
   */
  private resolveEndpointUrl(): string {
    const knownPaths = [
      '/chat/completions',
      '/completions',
      '/generate',
      '/api/generate',
      '/api/chat',
    ];

    const hasApiPath = knownPaths.some((p) => this.baseUrl.includes(p));
    if (hasApiPath) {
      return this.baseUrl;
    }

    // Append standard OpenAI path
    return `${this.baseUrl}/v1/chat/completions`;
  }
}

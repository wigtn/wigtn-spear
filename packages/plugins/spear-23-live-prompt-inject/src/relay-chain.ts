/**
 * SPEAR-23: REST → WebSocket Attack Chain for Relay Services
 *
 * Automates the full attack lifecycle for relay-style AI services:
 *
 *   1. POST /relay/calls/start → Start a session, get WebSocket URL
 *   2. Connect to the returned WebSocket URL
 *   3. Send prompt injection payloads via text_input messages
 *   4. Collect LLM responses (captions)
 *   5. POST /relay/calls/{id}/end → Clean up session
 *
 * This module enables end-to-end automated prompt injection testing
 * against services like WIGVO that use a REST-initiated WebSocket
 * communication pattern.
 *
 * Cost-conscious design:
 *   - Single session per attack run (reuses one WS connection)
 *   - Configurable payload limit to control API costs
 *   - Immediate cleanup on completion or error
 *   - Total expected cost per run: < $0.50
 */

import type { SpearLogger } from '@wigtn/shared';
import { randomBytes } from 'node:crypto';
import { WsAttackClient, detectWsPreset } from './ws-client.js';
import type { WsPayloadResult } from './ws-client.js';

// ─── Types ────────────────────────────────────────────────────

export interface RelayChainConfig {
  /** Base URL of the relay server (e.g., https://wigvo-relay-xxx.a.run.app) */
  relayBaseUrl: string;
  /** Phone number for the call (required by relay API) */
  phoneNumber: string;
  /** Source language code (default: 'ko') */
  sourceLanguage?: string;
  /** Target language code (default: 'en') */
  targetLanguage?: string;
  /** Communication mode (default: 'text_to_voice') */
  communicationMode?: 'voice_to_voice' | 'text_to_voice' | 'full_agent';
  /** System prompt override to test injection via API parameter */
  systemPromptOverride?: string;
  /** Timeout per payload in ms (default: 15000) */
  timeout?: number;
  /** Time to wait for WS responses after sending (default: 5000) */
  responseWaitMs?: number;
  /** Maximum number of payloads to send (default: 5) */
  maxPayloads?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

export interface RelaySessionInfo {
  /** Session/call ID */
  callId: string;
  /** WebSocket URL for the relay stream */
  wsUrl: string;
  /** Whether the session was started successfully */
  started: boolean;
  /** Raw response from the start endpoint */
  startResponse: Record<string, unknown>;
  /** Error message if start failed */
  error?: string;
}

export interface RelayAttackResult {
  /** Session info */
  session: RelaySessionInfo;
  /** Results from each payload sent via WebSocket */
  payloadResults: WsPayloadResult[];
  /** Whether the session was properly cleaned up */
  cleaned: boolean;
  /** Total duration of the attack chain in ms */
  totalDurationMs: number;
  /** System prompt override was accepted (param injection) */
  promptOverrideAccepted: boolean;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_RESPONSE_WAIT_MS = 5_000;
const DEFAULT_MAX_PAYLOADS = 5;
const INTER_PAYLOAD_DELAY_MS = 1_000;

// ─── Relay Attack Chain ───────────────────────────────────────

/**
 * Execute a full REST → WebSocket attack chain against a relay service.
 *
 * Steps:
 *   1. POST to start a relay session → get WS URL
 *   2. Connect to WS and send injection payloads
 *   3. Collect and return all responses
 *   4. POST to end the session
 */
export async function executeRelayChain(
  config: RelayChainConfig,
  payloads: string[],
): Promise<RelayAttackResult> {
  const start = performance.now();
  const logger = config.logger;
  const baseUrl = config.relayBaseUrl.replace(/\/+$/, '');
  const maxPayloads = config.maxPayloads ?? DEFAULT_MAX_PAYLOADS;

  logger?.info('relay-chain: starting attack chain', {
    baseUrl,
    payloadCount: Math.min(payloads.length, maxPayloads),
    communicationMode: config.communicationMode ?? 'text_to_voice',
    hasPromptOverride: !!config.systemPromptOverride,
  });

  // ── Step 1: Start a relay session ──────────────────────────

  const session = await startRelaySession(baseUrl, config, logger);

  if (!session.started) {
    logger?.error('relay-chain: session start failed', {
      error: session.error,
    });
    return {
      session,
      payloadResults: [],
      cleaned: false,
      totalDurationMs: Math.round(performance.now() - start),
      promptOverrideAccepted: false,
    };
  }

  logger?.info('relay-chain: session started', {
    callId: session.callId,
    wsUrl: session.wsUrl,
  });

  // Check if system_prompt_override was accepted
  const promptOverrideAccepted =
    !!config.systemPromptOverride &&
    session.started &&
    !session.error;

  // ── Step 2: Connect to WebSocket and send payloads ─────────

  const payloadResults: WsPayloadResult[] = [];
  const payloadsToSend = payloads.slice(0, maxPayloads);

  if (session.wsUrl) {
    const preset = detectWsPreset(session.wsUrl);
    const wsClient = new WsAttackClient({
      url: session.wsUrl,
      timeout: config.timeout ?? DEFAULT_TIMEOUT_MS,
      responseWaitMs: config.responseWaitMs ?? DEFAULT_RESPONSE_WAIT_MS,
      preset,
      logger,
    });

    // Probe WS connectivity
    const probe = await wsClient.probe();

    if (probe.reachable) {
      logger?.info('relay-chain: WebSocket connected', {
        latencyMs: probe.latencyMs,
        preset,
      });

      for (let i = 0; i < payloadsToSend.length; i++) {
        const payload = payloadsToSend[i]!;

        logger?.debug('relay-chain: sending payload', {
          index: i + 1,
          total: payloadsToSend.length,
          length: payload.length,
        });

        const result = await wsClient.sendPayload(payload);
        payloadResults.push(result);

        logger?.debug('relay-chain: payload result', {
          index: i + 1,
          connected: result.connected,
          responseLength: result.responseText.length,
          fragments: result.fragments.length,
          durationMs: result.durationMs,
        });

        // Delay between payloads
        if (i < payloadsToSend.length - 1) {
          await sleep(INTER_PAYLOAD_DELAY_MS);
        }
      }
    } else {
      logger?.warn('relay-chain: WebSocket unreachable', {
        wsUrl: session.wsUrl,
        error: probe.error,
      });
    }
  }

  // ── Step 3: End the session ────────────────────────────────

  const cleaned = await endRelaySession(baseUrl, session.callId, logger);

  const totalDurationMs = Math.round(performance.now() - start);

  logger?.info('relay-chain: attack chain complete', {
    callId: session.callId,
    payloadsSent: payloadResults.length,
    responsesReceived: payloadResults.filter((r) => r.responseText.length > 0).length,
    cleaned,
    totalDurationMs,
    promptOverrideAccepted,
  });

  return {
    session,
    payloadResults,
    cleaned,
    totalDurationMs,
    promptOverrideAccepted,
  };
}

// ─── Session Management ───────────────────────────────────────

/**
 * Start a relay session by POSTing to the relay API.
 *
 * The response should contain:
 *   - call_id or session_id
 *   - relay_ws_url or ws_url (WebSocket connection URL)
 */
async function startRelaySession(
  baseUrl: string,
  config: RelayChainConfig,
  logger?: SpearLogger,
): Promise<RelaySessionInfo> {
  const callId = generateCallId();
  const url = `${baseUrl}/relay/calls/start`;

  const body: Record<string, unknown> = {
    call_id: callId,
    phone_number: config.phoneNumber,
    source_language: config.sourceLanguage ?? 'ko',
    target_language: config.targetLanguage ?? 'en',
    mode: 'relay',
    communication_mode: config.communicationMode ?? 'text_to_voice',
  };

  // Include system_prompt_override if provided (testing the injection vector)
  if (config.systemPromptOverride) {
    body.system_prompt_override = config.systemPromptOverride;
  }

  logger?.debug('relay-chain: starting session', {
    url,
    callId,
    hasPromptOverride: !!config.systemPromptOverride,
  });

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'WIGTN-SPEAR/0.1.0',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timer);

    const text = await response.text();
    let parsed: Record<string, unknown> = {};

    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // Non-JSON response
    }

    if (response.status >= 200 && response.status < 300) {
      // Extract WebSocket URL from response
      const wsUrl =
        (parsed.relay_ws_url as string) ??
        (parsed.ws_url as string) ??
        (parsed.websocket_url as string) ??
        '';

      return {
        callId: (parsed.call_id as string) ?? callId,
        wsUrl,
        started: true,
        startResponse: parsed,
      };
    }

    return {
      callId,
      wsUrl: '',
      started: false,
      startResponse: parsed,
      error: `HTTP ${response.status}: ${text.slice(0, 500)}`,
    };
  } catch (err) {
    return {
      callId,
      wsUrl: '',
      started: false,
      startResponse: {},
      error: `Request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * End a relay session by POSTing to the end endpoint.
 * Returns true if successful, false otherwise.
 */
async function endRelaySession(
  baseUrl: string,
  callId: string,
  logger?: SpearLogger,
): Promise<boolean> {
  const url = `${baseUrl}/relay/calls/${callId}/end`;

  logger?.debug('relay-chain: ending session', { url, callId });

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'WIGTN-SPEAR/0.1.0',
      },
      body: JSON.stringify({ call_id: callId }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    logger?.debug('relay-chain: session end response', {
      status: response.status,
    });

    // Read body to avoid leaks
    try { await response.text(); } catch { /* ignore */ }

    return response.status >= 200 && response.status < 300;
  } catch {
    return false;
  }
}

// ─── Helpers ──────────────────────────────────────────────────

/**
 * Generate a unique call ID for the relay session.
 * Format: spear-{timestamp}-{random}
 */
function generateCallId(): string {
  const ts = Date.now().toString(36);
  const rand = randomBytes(6).toString('hex');
  return `spear-${ts}-${rand}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

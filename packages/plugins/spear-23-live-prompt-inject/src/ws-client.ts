/**
 * SPEAR-23: WebSocket Client for Relay-Style AI Services
 *
 * Connects to WebSocket-based AI services (translation relays, voice
 * assistants, chat proxies) and sends prompt injection payloads through
 * the WS protocol.
 *
 * Supports configurable message formats via presets:
 *   - 'wigvo-relay': WIGVO relay protocol (text_input -> caption)
 *   - 'generic':     Generic JSON message format
 *
 * Uses Node.js built-in WebSocket (Node 22+). No external dependencies.
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ──────────────────────────────────────────────────

export type WsPreset = 'wigvo-relay' | 'generic';

export interface WsClientConfig {
  /** WebSocket URL (ws:// or wss://) */
  url: string;
  /** Timeout per payload round-trip in ms (default: 15000) */
  timeout?: number;
  /** Time to wait for responses after sending in ms (default: 5000) */
  responseWaitMs?: number;
  /** Protocol preset (default: 'generic') */
  preset?: WsPreset;
  /** Logger instance */
  logger?: SpearLogger;
}

export interface WsPayloadResult {
  /** Payload text sent */
  sent: string;
  /** Concatenated response text (all caption fragments joined) */
  responseText: string;
  /** Individual response fragments */
  fragments: string[];
  /** All raw WS messages received */
  rawMessages: string[];
  /** Whether connection succeeded */
  connected: boolean;
  /** Round-trip duration in ms */
  durationMs: number;
  /** Error description if failed */
  error?: string;
}

// ─── Message Format ─────────────────────────────────────────

interface MessageFormat {
  /** Build a send message from payload text */
  encode(text: string): string;
  /** Extract response text from a raw WS message, or null if not relevant */
  decode(raw: string): string | null;
}

const FORMATS: Record<WsPreset, MessageFormat> = {
  'wigvo-relay': {
    encode: (text: string) =>
      JSON.stringify({ type: 'text_input', data: { text } }),

    decode: (raw: string) => {
      try {
        const msg = JSON.parse(raw) as Record<string, unknown>;
        const type = msg.type as string;

        // Caption messages contain the LLM response
        if (
          type === 'caption' ||
          type === 'caption.original' ||
          type === 'caption.translated'
        ) {
          const data = msg.data as Record<string, unknown>;
          return (data?.text as string) ?? null;
        }

        // Error messages
        if (type === 'error') {
          const data = msg.data as Record<string, unknown>;
          return `[ERROR] ${data?.message ?? 'unknown'}`;
        }

        return null;
      } catch {
        return null;
      }
    },
  },

  'generic': {
    encode: (text: string) =>
      JSON.stringify({ type: 'message', content: text }),

    decode: (raw: string) => {
      try {
        const msg = JSON.parse(raw) as Record<string, unknown>;
        const data = msg.data as Record<string, unknown> | undefined;
        return (
          (msg.content as string) ??
          (msg.text as string) ??
          (data?.text as string) ??
          (msg.message as string) ??
          null
        );
      } catch {
        // Plain text response
        return raw || null;
      }
    },
  },
};

// ─── Constants ──────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_RESPONSE_WAIT_MS = 5_000;
const MAX_RESPONSE_LENGTH = 2000;

// ─── WebSocket Attack Client ────────────────────────────────

export class WsAttackClient {
  private readonly url: string;
  private readonly timeout: number;
  private readonly responseWaitMs: number;
  private readonly format: MessageFormat;
  private readonly logger?: SpearLogger;

  constructor(config: WsClientConfig) {
    this.url = config.url;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
    this.responseWaitMs = config.responseWaitMs ?? DEFAULT_RESPONSE_WAIT_MS;
    this.format = FORMATS[config.preset ?? 'generic']!;
    this.logger = config.logger;
  }

  /**
   * Send a single injection payload over WebSocket and collect responses.
   *
   * Flow:
   *   1. Connect to the WebSocket URL
   *   2. On open, send the encoded payload message
   *   3. Collect decoded response fragments for responseWaitMs
   *   4. Close connection and return results
   */
  async sendPayload(text: string): Promise<WsPayloadResult> {
    const start = performance.now();
    const fragments: string[] = [];
    const rawMessages: string[] = [];

    return new Promise<WsPayloadResult>((resolve) => {
      let resolved = false;

      const done = (error?: string) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(overallTimer);
        try {
          ws.close();
        } catch {
          /* connection already closed */
        }

        const responseText = fragments.join(' ').slice(0, MAX_RESPONSE_LENGTH);

        resolve({
          sent: text,
          responseText,
          fragments,
          rawMessages,
          connected: !error || fragments.length > 0,
          durationMs: Math.round(performance.now() - start),
          error,
        });
      };

      // Hard timeout — resolve even if nothing came back
      const overallTimer = setTimeout(() => {
        this.logger?.debug('ws-client: timeout reached');
        done(fragments.length > 0 ? undefined : 'Connection timeout');
      }, this.timeout);

      let ws: WebSocket;

      try {
        ws = new WebSocket(this.url);
      } catch (err) {
        clearTimeout(overallTimer);
        resolve({
          sent: text,
          responseText: '',
          fragments: [],
          rawMessages: [],
          connected: false,
          durationMs: Math.round(performance.now() - start),
          error: `WebSocket creation failed: ${err}`,
        });
        return;
      }

      ws.addEventListener('open', () => {
        this.logger?.debug('ws-client: connected, sending payload', {
          url: this.url,
          payloadLength: text.length,
        });

        const msg = this.format.encode(text);
        ws.send(msg);

        // Give the server time to respond, then close
        setTimeout(() => done(), this.responseWaitMs);
      });

      ws.addEventListener('message', (event: MessageEvent) => {
        const raw =
          typeof event.data === 'string' ? event.data : String(event.data);
        rawMessages.push(raw);

        const extracted = this.format.decode(raw);
        if (extracted) {
          fragments.push(extracted);
        }
      });

      ws.addEventListener('error', () => {
        done('WebSocket error');
      });

      ws.addEventListener('close', () => {
        done();
      });
    });
  }

  /**
   * Test if the WebSocket endpoint is reachable.
   * Attempts to connect and immediately closes on success.
   */
  async probe(): Promise<{
    reachable: boolean;
    latencyMs: number;
    error?: string;
  }> {
    const start = performance.now();

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        try {
          ws.close();
        } catch {
          /* already closed */
        }
        resolve({
          reachable: false,
          latencyMs: Math.round(performance.now() - start),
          error: 'Connection timeout (5s)',
        });
      }, 5000);

      let ws: WebSocket;

      try {
        ws = new WebSocket(this.url);
      } catch (err) {
        clearTimeout(timer);
        resolve({
          reachable: false,
          latencyMs: Math.round(performance.now() - start),
          error: String(err),
        });
        return;
      }

      ws.addEventListener('open', () => {
        clearTimeout(timer);
        const latency = Math.round(performance.now() - start);
        ws.close();
        resolve({ reachable: true, latencyMs: latency });
      });

      ws.addEventListener('error', () => {
        clearTimeout(timer);
        resolve({
          reachable: false,
          latencyMs: Math.round(performance.now() - start),
          error: 'Connection refused',
        });
      });
    });
  }
}

// ─── Helpers ────────────────────────────────────────────────

/**
 * Detect the appropriate WS preset from the URL pattern.
 * Falls back to 'generic' if no known pattern is matched.
 */
export function detectWsPreset(url: string): WsPreset {
  // WIGVO relay pattern: /relay/calls/.../stream
  if (url.includes('/relay/') || url.includes('/stream')) {
    return 'wigvo-relay';
  }
  return 'generic';
}

/**
 * Check if a URL is a WebSocket URL.
 */
export function isWebSocketUrl(url: string): boolean {
  return url.startsWith('ws://') || url.startsWith('wss://');
}

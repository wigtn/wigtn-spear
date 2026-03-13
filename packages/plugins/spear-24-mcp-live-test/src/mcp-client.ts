/**
 * Lightweight MCP JSON-RPC 2.0 Client
 *
 * Implements a minimal MCP client that speaks the JSON-RPC 2.0 protocol
 * used by MCP servers. Supports two transport types:
 *
 *   SSE (Server-Sent Events) -- For HTTP-based MCP servers
 *     - POSTs JSON-RPC messages to ${baseUrl}/message
 *     - Listens for SSE events on ${baseUrl}/sse
 *     - Uses built-in `fetch` for HTTP requests
 *
 *   Stdio -- For subprocess-based MCP servers
 *     - Spawns the process with child_process.spawn
 *     - Writes JSON-RPC messages to stdin (newline-delimited)
 *     - Reads JSON-RPC responses from stdout
 *     - Handles process lifecycle (start, stop, crash)
 *
 * This is deliberately minimal. We're building an attack tool, not a full
 * MCP SDK. Focus areas: initialize, tools/list, tools/call, error handling.
 *
 * No external dependencies -- uses only Node.js built-in modules.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import type { SpearLogger } from '@wigtn/shared';

// ─── Public Types ────────────────────────────────────────────

export interface MCPClient {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  initialize(): Promise<MCPInitResult>;
  listTools(): Promise<MCPTool[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<MCPToolResult>;
  listResources?(): Promise<MCPResource[]>;
  readResource?(uri: string): Promise<MCPResourceContent>;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface MCPToolResult {
  content: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

export interface MCPInitResult {
  serverInfo: { name: string; version: string };
  capabilities: Record<string, unknown>;
}

export interface MCPResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface MCPResourceContent {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

// ─── Internal Types ──────────────────────────────────────────

interface JSONRPCRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface JSONRPCNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

// ─── Constants ───────────────────────────────────────────────

/** Default timeout per JSON-RPC call in ms */
const DEFAULT_TIMEOUT_MS = 10_000;

/** MCP protocol version for the initialize handshake */
const MCP_PROTOCOL_VERSION = '2024-11-05';

/** Client info sent during initialize */
const CLIENT_INFO = {
  name: 'wigtn-spear-24-live-tester',
  version: '0.1.0',
};

// ─── SSE Transport ───────────────────────────────────────────

/**
 * MCP client that communicates over SSE (Server-Sent Events) transport.
 *
 * HTTP-based MCP servers expose two endpoints:
 *   - GET /sse -- Server-Sent Events stream for server-to-client messages
 *   - POST /message -- Client-to-server JSON-RPC messages
 *
 * The SSE stream provides the session endpoint URL in its first event.
 */
export class SSEMCPClient implements MCPClient {
  private baseUrl: string;
  private messageEndpoint: string | null = null;
  private sseAbortController: AbortController | null = null;
  private pendingRequests: Map<number, {
    resolve: (value: JSONRPCResponse) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = new Map();
  private nextId = 1;
  private connected = false;
  private logger: SpearLogger;
  private timeoutMs: number;
  private headers: Record<string, string>;

  constructor(
    baseUrl: string,
    logger: SpearLogger,
    options?: {
      timeout?: number;
      headers?: Record<string, string>;
    },
  ) {
    // Strip trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.logger = logger;
    this.timeoutMs = options?.timeout ?? DEFAULT_TIMEOUT_MS;
    this.headers = options?.headers ?? {};
  }

  async connect(): Promise<void> {
    if (this.connected) return;

    this.logger.info('SSE transport: connecting', { baseUrl: this.baseUrl });

    this.sseAbortController = new AbortController();

    // Start SSE listener to receive server messages and the session endpoint
    const sseUrl = `${this.baseUrl}/sse`;

    try {
      const sseResponse = await fetch(sseUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/event-stream',
          ...this.headers,
        },
        signal: this.sseAbortController.signal,
      });

      if (!sseResponse.ok) {
        throw new Error(
          `SSE connection failed: ${sseResponse.status} ${sseResponse.statusText}`,
        );
      }

      if (!sseResponse.body) {
        throw new Error('SSE response has no body stream');
      }

      // Parse SSE stream in background
      this.consumeSSEStream(sseResponse.body);

      // Wait for the endpoint event (the server sends its message endpoint)
      await this.waitForEndpoint();

      this.connected = true;
      this.logger.info('SSE transport: connected', {
        messageEndpoint: this.messageEndpoint,
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error('SSE connection aborted');
      }
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    if (this.sseAbortController) {
      this.sseAbortController.abort();
      this.sseAbortController = null;
    }

    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Client disconnected'));
    }
    this.pendingRequests.clear();

    this.connected = false;
    this.messageEndpoint = null;
    this.logger.info('SSE transport: disconnected');
  }

  async initialize(): Promise<MCPInitResult> {
    const response = await this.sendRequest('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    });

    // Send initialized notification (no response expected)
    await this.sendNotification('notifications/initialized', {});

    const result = response.result as Record<string, unknown>;
    return {
      serverInfo: (result.serverInfo as { name: string; version: string }) ?? {
        name: 'unknown',
        version: 'unknown',
      },
      capabilities: (result.capabilities as Record<string, unknown>) ?? {},
    };
  }

  async listTools(): Promise<MCPTool[]> {
    const response = await this.sendRequest('tools/list', {});
    const result = response.result as { tools?: MCPTool[] };
    return result.tools ?? [];
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<MCPToolResult> {
    const response = await this.sendRequest('tools/call', { name, arguments: args });

    if (response.error) {
      return {
        content: [{ type: 'text', text: response.error.message }],
        isError: true,
      };
    }

    const result = response.result as MCPToolResult;
    return result ?? { content: [], isError: false };
  }

  async listResources(): Promise<MCPResource[]> {
    const response = await this.sendRequest('resources/list', {});
    const result = response.result as { resources?: MCPResource[] };
    return result.resources ?? [];
  }

  async readResource(uri: string): Promise<MCPResourceContent> {
    const response = await this.sendRequest('resources/read', { uri });
    const result = response.result as { contents?: MCPResourceContent[] };
    return result.contents?.[0] ?? { uri };
  }

  // ── Private: Request/Response ──────────────────────────────

  private async sendRequest(
    method: string,
    params: Record<string, unknown>,
  ): Promise<JSONRPCResponse> {
    if (!this.connected && method !== 'initialize') {
      throw new Error('Client not connected');
    }

    const id = this.nextId++;
    const request: JSONRPCRequest = {
      jsonrpc: '2.0',
      id,
      method,
      params,
    };

    return new Promise<JSONRPCResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${this.timeoutMs}ms: ${method}`));
      }, this.timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });

      this.postMessage(request).catch((err) => {
        this.pendingRequests.delete(id);
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  private async sendNotification(
    method: string,
    params: Record<string, unknown>,
  ): Promise<void> {
    const notification: JSONRPCNotification = {
      jsonrpc: '2.0',
      method,
      params,
    };
    await this.postMessage(notification);
  }

  private async postMessage(
    message: JSONRPCRequest | JSONRPCNotification,
  ): Promise<void> {
    const endpoint = this.messageEndpoint ?? `${this.baseUrl}/message`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
      },
      body: JSON.stringify(message),
      signal: this.sseAbortController?.signal,
    });

    if (!response.ok) {
      throw new Error(
        `POST ${endpoint} failed: ${response.status} ${response.statusText}`,
      );
    }
  }

  // ── Private: SSE Stream Parsing ────────────────────────────

  private consumeSSEStream(body: ReadableStream<Uint8Array>): void {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const read = (): void => {
      reader.read().then(({ done, value }) => {
        if (done) return;

        buffer += decoder.decode(value, { stream: true });

        // Process complete SSE events (delimited by double newline)
        const parts = buffer.split('\n\n');
        buffer = parts.pop() ?? '';

        for (const part of parts) {
          this.handleSSEEvent(part);
        }

        read();
      }).catch(() => {
        // Stream closed or aborted -- expected during disconnect
      });
    };

    read();
  }

  private handleSSEEvent(raw: string): void {
    let eventType = 'message';
    let data = '';

    for (const line of raw.split('\n')) {
      if (line.startsWith('event:')) {
        eventType = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        data += line.slice(5).trim();
      }
    }

    if (eventType === 'endpoint') {
      // Server sends its message endpoint URL
      // It may be a relative path or absolute URL
      if (data.startsWith('http://') || data.startsWith('https://')) {
        this.messageEndpoint = data;
      } else {
        // Relative path -- resolve against base URL
        const url = new URL(data, this.baseUrl);
        this.messageEndpoint = url.toString();
      }
      this.logger.debug('SSE received endpoint', {
        endpoint: this.messageEndpoint,
      });
      return;
    }

    if (eventType === 'message' && data) {
      try {
        const parsed = JSON.parse(data) as JSONRPCResponse;
        if (parsed.id !== undefined) {
          const pending = this.pendingRequests.get(parsed.id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pendingRequests.delete(parsed.id);
            pending.resolve(parsed);
          }
        }
      } catch {
        this.logger.debug('SSE received non-JSON data', { data });
      }
    }
  }

  private waitForEndpoint(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const checkInterval = 50;
      const maxWait = this.timeoutMs;
      let elapsed = 0;

      const check = (): void => {
        if (this.messageEndpoint) {
          resolve();
          return;
        }
        elapsed += checkInterval;
        if (elapsed >= maxWait) {
          // Fall back to default /message endpoint
          this.messageEndpoint = `${this.baseUrl}/message`;
          this.logger.warn('SSE endpoint event not received, using default', {
            endpoint: this.messageEndpoint,
          });
          resolve();
          return;
        }
        setTimeout(check, checkInterval);
      };

      check();
    });
  }
}

// ─── Stdio Transport ─────────────────────────────────────────

/**
 * MCP client that communicates over stdio transport.
 *
 * Spawns the MCP server as a subprocess and communicates via:
 *   - stdin: Write JSON-RPC messages (newline-delimited)
 *   - stdout: Read JSON-RPC responses (newline-delimited)
 *   - stderr: Logged for diagnostics
 */
export class StdioMCPClient implements MCPClient {
  private command: string;
  private args: string[];
  private env: Record<string, string>;
  private process: ChildProcess | null = null;
  private pendingRequests: Map<number, {
    resolve: (value: JSONRPCResponse) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = new Map();
  private nextId = 1;
  private connected = false;
  private logger: SpearLogger;
  private timeoutMs: number;
  private stdoutBuffer = '';

  constructor(
    command: string,
    args: string[],
    logger: SpearLogger,
    options?: {
      timeout?: number;
      env?: Record<string, string>;
    },
  ) {
    this.command = command;
    this.args = args;
    this.logger = logger;
    this.timeoutMs = options?.timeout ?? DEFAULT_TIMEOUT_MS;
    this.env = options?.env ?? {};
  }

  async connect(): Promise<void> {
    if (this.connected) return;

    this.logger.info('Stdio transport: spawning process', {
      command: this.command,
      args: this.args,
    });

    return new Promise<void>((resolve, reject) => {
      try {
        this.process = spawn(this.command, this.args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, ...this.env },
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        reject(new Error(`Failed to spawn MCP server: ${message}`));
        return;
      }

      const proc = this.process;

      // Handle stdout -- newline-delimited JSON-RPC messages
      proc.stdout?.on('data', (chunk: Buffer) => {
        this.stdoutBuffer += chunk.toString();
        this.processStdoutBuffer();
      });

      // Handle stderr -- log diagnostic output
      proc.stderr?.on('data', (chunk: Buffer) => {
        const text = chunk.toString().trim();
        if (text) {
          this.logger.debug('MCP server stderr', { text });
        }
      });

      // Handle process errors
      proc.on('error', (err: Error) => {
        this.logger.error('MCP server process error', { error: err.message });
        this.rejectAllPending(new Error(`MCP server process error: ${err.message}`));
        if (!this.connected) {
          reject(new Error(`Failed to spawn MCP server: ${err.message}`));
        }
      });

      // Handle process exit
      proc.on('exit', (code, signal) => {
        this.logger.info('MCP server process exited', { code, signal });
        this.rejectAllPending(
          new Error(`MCP server exited: code=${code} signal=${signal}`),
        );
        this.connected = false;
        this.process = null;
      });

      // Give the process a moment to start, then mark as connected
      // (The process will reject pending requests if it crashes immediately)
      const startTimer = setTimeout(() => {
        if (this.process && !this.process.killed) {
          this.connected = true;
          this.logger.info('Stdio transport: process started', {
            pid: this.process.pid,
          });
          resolve();
        }
      }, 200);

      proc.on('error', () => {
        clearTimeout(startTimer);
      });
    });
  }

  async disconnect(): Promise<void> {
    if (this.process) {
      this.logger.info('Stdio transport: killing process', {
        pid: this.process.pid,
      });

      // Try graceful shutdown first
      this.process.stdin?.end();
      this.process.kill('SIGTERM');

      // Force kill after 2 seconds if still alive
      const forceKillTimer = setTimeout(() => {
        if (this.process && !this.process.killed) {
          this.process.kill('SIGKILL');
        }
      }, 2000);

      // Wait for exit
      await new Promise<void>((resolve) => {
        if (!this.process) {
          resolve();
          return;
        }
        this.process.on('exit', () => {
          clearTimeout(forceKillTimer);
          resolve();
        });
        // Safety timeout
        setTimeout(() => {
          clearTimeout(forceKillTimer);
          resolve();
        }, 3000);
      });

      this.process = null;
    }

    this.rejectAllPending(new Error('Client disconnected'));
    this.connected = false;
    this.stdoutBuffer = '';
    this.logger.info('Stdio transport: disconnected');
  }

  async initialize(): Promise<MCPInitResult> {
    const response = await this.sendRequest('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    });

    // Send initialized notification
    this.sendNotification('notifications/initialized', {});

    const result = response.result as Record<string, unknown>;
    return {
      serverInfo: (result.serverInfo as { name: string; version: string }) ?? {
        name: 'unknown',
        version: 'unknown',
      },
      capabilities: (result.capabilities as Record<string, unknown>) ?? {},
    };
  }

  async listTools(): Promise<MCPTool[]> {
    const response = await this.sendRequest('tools/list', {});
    const result = response.result as { tools?: MCPTool[] };
    return result.tools ?? [];
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<MCPToolResult> {
    const response = await this.sendRequest('tools/call', { name, arguments: args });

    if (response.error) {
      return {
        content: [{ type: 'text', text: response.error.message }],
        isError: true,
      };
    }

    const result = response.result as MCPToolResult;
    return result ?? { content: [], isError: false };
  }

  async listResources(): Promise<MCPResource[]> {
    const response = await this.sendRequest('resources/list', {});
    const result = response.result as { resources?: MCPResource[] };
    return result.resources ?? [];
  }

  async readResource(uri: string): Promise<MCPResourceContent> {
    const response = await this.sendRequest('resources/read', { uri });
    const result = response.result as { contents?: MCPResourceContent[] };
    return result.contents?.[0] ?? { uri };
  }

  // ── Private: Request/Response ──────────────────────────────

  private sendRequest(
    method: string,
    params: Record<string, unknown>,
  ): Promise<JSONRPCResponse> {
    if (!this.connected && method !== 'initialize') {
      return Promise.reject(new Error('Client not connected'));
    }

    const id = this.nextId++;
    const request: JSONRPCRequest = {
      jsonrpc: '2.0',
      id,
      method,
      params,
    };

    return new Promise<JSONRPCResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${this.timeoutMs}ms: ${method}`));
      }, this.timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });

      try {
        const data = JSON.stringify(request) + '\n';
        this.process?.stdin?.write(data, (err) => {
          if (err) {
            this.pendingRequests.delete(id);
            clearTimeout(timer);
            reject(new Error(`Failed to write to stdin: ${err.message}`));
          }
        });
      } catch (err: unknown) {
        this.pendingRequests.delete(id);
        clearTimeout(timer);
        const message = err instanceof Error ? err.message : String(err);
        reject(new Error(`Failed to send request: ${message}`));
      }
    });
  }

  private sendNotification(
    method: string,
    params: Record<string, unknown>,
  ): void {
    const notification: JSONRPCNotification = {
      jsonrpc: '2.0',
      method,
      params,
    };

    try {
      const data = JSON.stringify(notification) + '\n';
      this.process?.stdin?.write(data);
    } catch {
      this.logger.debug('Failed to send notification', { method });
    }
  }

  private processStdoutBuffer(): void {
    const lines = this.stdoutBuffer.split('\n');
    // Keep the last (possibly incomplete) line in the buffer
    this.stdoutBuffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const parsed = JSON.parse(trimmed) as JSONRPCResponse;
        if (parsed.id !== undefined) {
          const pending = this.pendingRequests.get(parsed.id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pendingRequests.delete(parsed.id);
            pending.resolve(parsed);
          }
        }
      } catch {
        this.logger.debug('Stdio received non-JSON line', {
          line: trimmed.slice(0, 200),
        });
      }
    }
  }

  private rejectAllPending(error: Error): void {
    for (const [, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pendingRequests.clear();
  }
}

// ─── Factory ─────────────────────────────────────────────────

/**
 * Transport type for MCP connections.
 */
export type MCPTransportType = 'sse' | 'stdio';

/**
 * Parse a target URL string into transport type and connection parameters.
 *
 * Supported formats:
 *   - http://... or https://... → SSE transport
 *   - stdio://command?args=arg1,arg2 → Stdio transport
 *   - npx ... → Stdio transport (npx command)
 *   - /path/to/binary args... → Stdio transport (absolute path)
 */
export function parseTarget(targetUrl: string): {
  transport: MCPTransportType;
  url?: string;
  command?: string;
  args?: string[];
} {
  if (targetUrl.startsWith('http://') || targetUrl.startsWith('https://')) {
    return { transport: 'sse', url: targetUrl };
  }

  if (targetUrl.startsWith('stdio://')) {
    const url = new URL(targetUrl);
    const command = url.hostname + url.pathname;
    const argsParam = url.searchParams.get('args');
    const args = argsParam ? argsParam.split(',') : [];
    return { transport: 'stdio', command, args };
  }

  if (targetUrl.startsWith('npx ') || targetUrl.startsWith('npx\t')) {
    const parts = targetUrl.split(/\s+/);
    return { transport: 'stdio', command: parts[0], args: parts.slice(1) };
  }

  if (targetUrl.startsWith('/')) {
    const parts = targetUrl.split(/\s+/);
    return { transport: 'stdio', command: parts[0], args: parts.slice(1) };
  }

  // Default: treat as command
  const parts = targetUrl.split(/\s+/);
  return { transport: 'stdio', command: parts[0], args: parts.slice(1) };
}

/**
 * Create an MCPClient instance for the given target URL.
 */
export function createMCPClient(
  targetUrl: string,
  logger: SpearLogger,
  options?: {
    timeout?: number;
    headers?: Record<string, string>;
    env?: Record<string, string>;
  },
): { client: MCPClient; transport: MCPTransportType } {
  const parsed = parseTarget(targetUrl);

  if (parsed.transport === 'sse' && parsed.url) {
    const client = new SSEMCPClient(parsed.url, logger, {
      timeout: options?.timeout,
      headers: options?.headers,
    });
    return { client, transport: 'sse' };
  }

  if (parsed.command) {
    const client = new StdioMCPClient(
      parsed.command,
      parsed.args ?? [],
      logger,
      {
        timeout: options?.timeout,
        env: options?.env,
      },
    );
    return { client, transport: 'stdio' };
  }

  throw new Error(`Unable to determine MCP transport for target: ${targetUrl}`);
}

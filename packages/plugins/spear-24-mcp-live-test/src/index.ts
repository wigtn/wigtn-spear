/**
 * SPEAR-24: MCP Live Tester Plugin
 *
 * Connects to actual MCP (Model Context Protocol) servers and tests them
 * for vulnerabilities through active probing. This is the live-attack
 * counterpart to SPEAR-04's static analysis.
 *
 * Two operational modes:
 *
 *   Safe Mode (no liveAttack):
 *     Falls back to static analysis identical to spear-04. Scans project
 *     directories for MCP configuration files (mcp.json, .cursor/mcp.json,
 *     cline_mcp_settings.json, etc.) and analyzes tool descriptions against
 *     injection pattern databases. No network activity, no server connections.
 *
 *   Aggressive Mode WITH liveAttack:
 *     Connects to a live MCP server via the configured transport (SSE or
 *     Stdio) and runs 11 attack vectors covering:
 *       - Tool enumeration and surface analysis
 *       - Description injection scanning
 *       - Schema validation bypass testing
 *       - Tool squatting detection
 *       - Rug pull detection (description mutation monitoring)
 *       - Cross-tool privilege escalation
 *       - Input size fuzzing
 *       - Data exfiltration probing
 *       - Environment variable extraction
 *       - Resource exposure checking
 *       - Error information disclosure
 *
 * Transports:
 *   - SSE: For HTTP-based MCP servers (http:// or https:// URLs)
 *   - Stdio: For subprocess MCP servers (stdio:// or npx commands)
 *
 * Architecture:
 *   - mcp-client.ts: Minimal JSON-RPC 2.0 MCP client (SSE + Stdio)
 *   - attack-vectors.ts: 11 attack vector definitions and implementations
 *   - index.ts: Plugin entry point, mode routing, finding generation
 *
 * No external dependencies. Uses only Node.js built-in modules.
 */

import { readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { constants as fsConstants } from 'node:fs';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
  Severity,
  SpearLogger,
} from '@wigtn/shared';
import {
  createMCPClient,
  type MCPClient,
  type MCPTransportType,
} from './mcp-client.js';
import {
  ATTACK_VECTORS,
  type MCPAttackVector,
  type AttackResult,
} from './attack-vectors.js';

// ─── Constants ───────────────────────────────────────────────

/**
 * MCP configuration file paths to scan in static analysis mode.
 * Matches the list from spear-04 for consistency.
 */
const MCP_CONFIG_FILES: readonly string[] = [
  'mcp.json',
  '.mcp.json',
  '.mcp/settings.json',
  '.mcp/config.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  '.vscode/settings.json',
  '.windsurf/mcp.json',
  'cline_mcp_settings.json',
  '.cline/mcp_settings.json',
  'claude_desktop_config.json',
  '.claude/settings.json',
];

/**
 * Static analysis injection patterns for safe mode fallback.
 * Subset of the patterns from spear-04 that are most relevant.
 */
const STATIC_INJECTION_PATTERNS: ReadonlyArray<{
  id: string;
  pattern: RegExp;
  description: string;
  severity: Severity;
  mitre: string[];
}> = [
  {
    id: 'hidden-instruction-marker',
    pattern: /<(?:IMPORTANT|system|instruction|hidden|secret)>/i,
    description: 'Hidden instruction marker tag in tool description',
    severity: 'critical',
    mitre: ['T1027', 'T1204'],
  },
  {
    id: 'html-comment-injection',
    pattern: /<!--[\s\S]*?(?:exec|system|fetch|curl|read|send|ignore|override)[\s\S]*?-->/i,
    description: 'HTML comment containing hidden instructions',
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
  },
  {
    id: 'zero-width-chars',
    pattern: /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060-\u2064]/,
    description: 'Zero-width Unicode characters hiding instructions',
    severity: 'critical',
    mitre: ['T1027'],
  },
  {
    id: 'bidi-override',
    pattern: /[\u202A-\u202E\u2066-\u2069]/,
    description: 'Bidirectional override characters for text confusion',
    severity: 'high',
    mitre: ['T1027'],
  },
  {
    id: 'data-exfil-instruction',
    pattern: /(?:send|post|transmit|forward|exfiltrate).*(?:env|secret|token|key|password|credential).*(?:to|http|url|endpoint)/i,
    description: 'Data exfiltration instruction in tool description',
    severity: 'critical',
    mitre: ['T1041', 'T1005'],
  },
  {
    id: 'http-fetch-instruction',
    pattern: /(?:fetch|curl|wget|http\.get|axios)\s*\(?\s*['"]https?:\/\//i,
    description: 'HTTP fetch/curl instruction in tool description',
    severity: 'critical',
    mitre: ['T1041', 'T1071'],
  },
  {
    id: 'shell-exec-instruction',
    pattern: /(?:exec|execute|spawn|system|eval|child_process)\s*\(?\s*['"]/i,
    description: 'Shell command execution instruction in tool description',
    severity: 'critical',
    mitre: ['T1059'],
  },
  {
    id: 'credential-access-instruction',
    pattern: /(?:read|cat|open|access).*(?:\.ssh|id_rsa|\.env|\.aws\/credentials|etc\/passwd)/i,
    description: 'Instruction to read sensitive credential files',
    severity: 'critical',
    mitre: ['T1005', 'T1059'],
  },
  {
    id: 'cross-tool-instruction',
    pattern: /(?:use|call|invoke|trigger)\s+(?:the\s+)?(?:tool|function|mcp)\s+['"]?\w+['"]?/i,
    description: 'Cross-tool invocation instruction in description',
    severity: 'high',
    mitre: ['T1059', 'T1204'],
  },
  {
    id: 'safety-bypass-instruction',
    pattern: /(?:ignore|bypass|skip|disable|override).*(?:safety|security|check|validation|guard|permission)/i,
    description: 'Instruction to bypass safety checks',
    severity: 'critical',
    mitre: ['T1562'],
  },
  {
    id: 'unpinned-npx',
    pattern: /(?:npx|dlx|bunx)\s+(?:-y\s+)?(?:@[\w-]+\/)?[\w-]+/,
    description: 'Server uses unpinned npx/dlx execution (rug pull risk)',
    severity: 'medium',
    mitre: ['T1059', 'T1547'],
  },
  {
    id: 'remote-schema-ref',
    pattern: /(?:\$ref|\$schema).*https?:\/\//,
    description: 'Tool schema references remote definition',
    severity: 'medium',
    mitre: ['T1204'],
  },
];

// ─── Plugin Implementation ──────────────────────────────────

/**
 * MCPLiveTestPlugin -- Live MCP Server Security Tester
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Connects to live MCP servers and runs attack vectors to detect
 * tool poisoning, rug pull, injection, and access control vulnerabilities.
 */
class MCPLiveTestPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'mcp-live-test',
    name: 'MCP Live Tester',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Connects to MCP servers and tests for tool poisoning, rug pull, and injection vulnerabilities',
    severity: 'critical',
    tags: ['mcp', 'live-attack', 'tool-poisoning', 'ai-security'],
    references: ['CVE-2025-54135', 'CWE-74'],
    safeMode: false,
    requiresNetwork: true,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['net:outbound', 'exec:child'],
    trustLevel: 'builtin',
  };

  /** Active MCP client connection (aggressive mode only) */
  private client: MCPClient | null = null;

  /** Transport type of the active connection */
  private transport: MCPTransportType | null = null;

  /**
   * Setup: Log initialization. No heavy work needed for this plugin
   * since MCP connections are established per-scan.
   */
  async setup(context: PluginContext): Promise<void> {
    context.logger.info('Initializing MCP Live Tester', {
      mode: context.mode,
      hasLiveAttack: !!context.liveAttack,
      targetUrl: context.liveAttack?.targetUrl ?? 'none',
    });
  }

  /**
   * Scan: Route to static or live attack mode.
   *
   * In safe mode (or aggressive without liveAttack):
   *   Performs static analysis of MCP config files, identical to spear-04.
   *
   * In aggressive mode WITH liveAttack:
   *   Connects to the MCP server and runs all 11 attack vectors.
   */
  async *scan(
    target: ScanTarget,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const hasLiveTarget =
      context.mode === 'aggressive' && context.liveAttack?.targetUrl;

    if (hasLiveTarget) {
      // ── Live Attack Mode ──────────────────────────────────
      context.logger.info('Running in LIVE ATTACK mode', {
        targetUrl: context.liveAttack!.targetUrl,
      });

      yield* this.runLiveAttack(context);
    } else {
      // ── Static Analysis Mode (fallback) ───────────────────
      context.logger.info('Running in STATIC ANALYSIS mode (no live target)', {
        scanPath: target.path,
      });

      yield* this.runStaticAnalysis(target.path, context.logger);
    }
  }

  /**
   * Teardown: Disconnect from any live MCP server and clean up.
   * Always called, even on scan failure.
   */
  async teardown(context: PluginContext): Promise<void> {
    if (this.client) {
      context.logger.info('Disconnecting from MCP server');
      try {
        await this.client.disconnect();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error during MCP disconnect', { error: msg });
      }
      this.client = null;
      this.transport = null;
    }

    context.logger.info('MCP Live Tester torn down');
  }

  // ──────────────────────────────────────────────────────────────
  // Live Attack Mode
  // ──────────────────────────────────────────────────────────────

  /**
   * Connect to a live MCP server and execute all attack vectors.
   *
   * Steps:
   *   1. Parse the target URL to determine transport (SSE or Stdio)
   *   2. Create and connect the MCP client
   *   3. Perform the MCP initialize handshake
   *   4. Run each attack vector sequentially
   *   5. Yield findings for each discovered vulnerability
   */
  private async *runLiveAttack(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const liveAttack = context.liveAttack!;
    const targetUrl = liveAttack.targetUrl;
    const logger = context.logger;

    // Step 1: Create MCP client
    logger.info('Creating MCP client', { targetUrl });

    try {
      const { client, transport } = createMCPClient(targetUrl, logger, {
        timeout: liveAttack.timeout ?? 10_000,
        headers: liveAttack.headers,
      });
      this.client = client;
      this.transport = transport;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        ruleId: 'spear-24/connection-error',
        severity: 'high',
        message: `Failed to create MCP client for ${targetUrl}: ${msg}`,
        remediation: 'Verify the target URL is correct and the MCP server is reachable.',
        metadata: {
          pluginId: 'mcp-live-test',
          category: 'connection',
          targetUrl,
          error: msg,
        },
      };
      return;
    }

    // Step 2: Connect
    logger.info('Connecting to MCP server', { transport: this.transport });

    try {
      await this.client.connect();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        ruleId: 'spear-24/connection-error',
        severity: 'high',
        message: `Failed to connect to MCP server at ${targetUrl}: ${msg}`,
        remediation:
          'Ensure the MCP server is running and accessible. For SSE servers, check HTTP connectivity. For stdio servers, check the command path.',
        metadata: {
          pluginId: 'mcp-live-test',
          category: 'connection',
          transport: this.transport,
          targetUrl,
          error: msg,
        },
      };
      return;
    }

    // Step 3: Initialize handshake
    logger.info('Performing MCP initialize handshake');

    let serverInfo;
    try {
      const initResult = await this.client.initialize();
      serverInfo = initResult.serverInfo;

      logger.info('MCP server initialized', {
        serverName: serverInfo.name,
        serverVersion: serverInfo.version,
        capabilities: initResult.capabilities,
      });

      // Yield informational finding about server identity
      yield {
        ruleId: 'spear-24/server-info',
        severity: 'info',
        message: `Connected to MCP server: ${serverInfo.name} v${serverInfo.version}`,
        metadata: {
          pluginId: 'mcp-live-test',
          category: 'server_info',
          transport: this.transport,
          targetUrl,
          serverName: serverInfo.name,
          serverVersion: serverInfo.version,
          capabilities: initResult.capabilities,
        },
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        ruleId: 'spear-24/init-error',
        severity: 'high',
        message: `MCP initialize handshake failed at ${targetUrl}: ${msg}`,
        remediation:
          'The MCP server did not complete the initialize handshake. This may indicate a non-MCP service or protocol mismatch.',
        metadata: {
          pluginId: 'mcp-live-test',
          category: 'connection',
          transport: this.transport,
          targetUrl,
          error: msg,
        },
      };
      return;
    }

    // Step 4: Run all attack vectors
    let totalFindings = 0;
    let requestCount = 0;
    const maxRequests = liveAttack.maxRequests ?? Infinity;

    for (const vector of ATTACK_VECTORS) {
      if (requestCount >= maxRequests) {
        logger.warn('Max request limit reached, stopping attack vectors', {
          maxRequests,
          requestCount,
        });
        break;
      }

      logger.info('Running attack vector', {
        id: vector.id,
        name: vector.name,
        category: vector.category,
      });

      try {
        for await (const result of vector.execute(this.client, logger)) {
          requestCount++;

          if (result.success) {
            totalFindings++;
            yield this.buildFinding(vector, result, targetUrl);
          }

          if (requestCount >= maxRequests) break;
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn('Attack vector failed', {
          vectorId: vector.id,
          error: msg,
        });

        // Yield a finding about the failure -- it may indicate
        // the server crashed or disconnected (interesting in itself)
        yield {
          ruleId: `spear-24/${vector.id}-error`,
          severity: 'medium',
          message: `Attack vector '${vector.name}' caused an error: ${msg}`,
          mitreTechniques: vector.mitre,
          remediation:
            'The MCP server encountered an unexpected error during testing. This may indicate fragile error handling.',
          metadata: {
            pluginId: 'mcp-live-test',
            category: vector.category,
            transport: this.transport,
            targetUrl,
            vectorId: vector.id,
            error: msg,
          },
        };
      }
    }

    logger.info('Live attack scan complete', {
      totalFindings,
      totalRequests: requestCount,
      attackVectors: ATTACK_VECTORS.length,
    });
  }

  /**
   * Build a Finding from an attack vector result.
   */
  private buildFinding(
    vector: MCPAttackVector,
    result: AttackResult,
    targetUrl: string,
  ): Finding {
    return {
      ruleId: `spear-24/${vector.id}`,
      severity: vector.severity,
      message: `MCP vulnerability: ${vector.name} - ${result.evidence}`,
      cvss: mapSeverityToCvss(vector.severity),
      mitreTechniques: vector.mitre,
      remediation: buildRemediation(vector),
      metadata: {
        pluginId: 'mcp-live-test',
        category: vector.category,
        transport: this.transport,
        targetUrl,
        toolName: (result.details.toolName as string) ?? undefined,
        evidence: result.details,
      },
    };
  }

  // ──────────────────────────────────────────────────────────────
  // Static Analysis Mode (Fallback)
  // ──────────────────────────────────────────────────────────────

  /**
   * Static analysis: Scan MCP config files for injection patterns.
   *
   * This mirrors spear-04's core analysis and serves as a fallback
   * when no live target is configured.
   */
  private async *runStaticAnalysis(
    rootDir: string,
    logger: SpearLogger,
  ): AsyncGenerator<Finding> {
    logger.info('Scanning for MCP configuration files', { rootDir });

    let configsFound = 0;
    let findingsCount = 0;

    for (const configRelPath of MCP_CONFIG_FILES) {
      const configAbsPath = join(rootDir, configRelPath);

      // Check if the file exists
      try {
        await access(configAbsPath, fsConstants.R_OK);
      } catch {
        continue;
      }

      configsFound++;
      logger.info('Found MCP config file', { path: configRelPath });

      // Read and parse
      let rawContent: string;
      try {
        rawContent = await readFile(configAbsPath, 'utf-8');
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn('Failed to read MCP config', {
          path: configRelPath,
          error: msg,
        });
        continue;
      }

      let configData: Record<string, unknown>;
      try {
        configData = JSON.parse(rawContent) as Record<string, unknown>;
      } catch {
        logger.warn('Failed to parse MCP config as JSON', {
          path: configRelPath,
        });
        continue;
      }

      // Extract tool definitions from various config formats
      const tools = extractToolDefinitions(configData);

      // Analyze each tool
      for (const tool of tools) {
        const surfaces = [
          tool.description ?? '',
          tool.command ?? '',
          (tool.args ?? []).join(' '),
          tool.rawContent,
        ].filter((s) => s.length > 0);

        for (const injPattern of STATIC_INJECTION_PATTERNS) {
          for (const surface of surfaces) {
            if (injPattern.pattern.test(surface)) {
              findingsCount++;
              yield {
                ruleId: `spear-24/static/${injPattern.id}`,
                severity: injPattern.severity,
                message: `MCP Poisoning in tool '${tool.name}': ${injPattern.description}`,
                file: configRelPath,
                cvss: mapSeverityToCvss(injPattern.severity),
                mitreTechniques: injPattern.mitre,
                remediation: buildStaticRemediation(injPattern.id),
                metadata: {
                  pluginId: 'mcp-live-test',
                  category: 'static_analysis',
                  toolName: tool.name,
                  toolCommand: tool.command,
                  patternId: injPattern.id,
                  source: 'config-static-analysis',
                },
              };
              break; // One match per pattern per tool is enough
            }
          }
        }
      }

      // Also scan raw content for hidden injection patterns
      for (const injPattern of STATIC_INJECTION_PATTERNS) {
        if (
          injPattern.id === 'zero-width-chars' ||
          injPattern.id === 'bidi-override' ||
          injPattern.id === 'html-comment-injection'
        ) {
          if (injPattern.pattern.test(rawContent)) {
            findingsCount++;
            yield {
              ruleId: `spear-24/static/${injPattern.id}`,
              severity: injPattern.severity,
              message: `MCP config raw content: ${injPattern.description}`,
              file: configRelPath,
              cvss: mapSeverityToCvss(injPattern.severity),
              mitreTechniques: injPattern.mitre,
              remediation: buildStaticRemediation(injPattern.id),
              metadata: {
                pluginId: 'mcp-live-test',
                category: 'static_analysis',
                patternId: injPattern.id,
                source: 'raw-config-analysis',
              },
            };
          }
        }
      }
    }

    logger.info('Static analysis complete', { configsFound, findingsCount });
  }
}

// ─── Tool Definition Extraction ──────────────────────────────

/**
 * Extracted tool definition from an MCP config file.
 */
interface MCPToolDef {
  name: string;
  command?: string;
  args?: string[];
  description?: string;
  rawContent: string;
}

/**
 * Extract MCP tool definitions from a parsed config JSON.
 * Handles multiple config schema formats (Claude, Cursor, Cline, VS Code).
 */
function extractToolDefinitions(
  configData: Record<string, unknown>,
): MCPToolDef[] {
  const tools: MCPToolDef[] = [];

  // Format 1: { mcpServers: { name: { command, args, ... } } }
  const mcpServers = configData.mcpServers as
    | Record<string, unknown>
    | undefined;
  if (mcpServers && typeof mcpServers === 'object') {
    for (const [name, def] of Object.entries(mcpServers)) {
      if (def && typeof def === 'object') {
        const d = def as Record<string, unknown>;
        tools.push({
          name,
          command: typeof d.command === 'string' ? d.command : undefined,
          args: Array.isArray(d.args) ? d.args.map(String) : undefined,
          description: typeof d.description === 'string'
            ? d.description
            : undefined,
          rawContent: JSON.stringify(def),
        });
      }
    }
  }

  // Format 2: { servers: { name: { ... } } }
  const servers = configData.servers as Record<string, unknown> | undefined;
  if (servers && typeof servers === 'object') {
    for (const [name, def] of Object.entries(servers)) {
      if (def && typeof def === 'object') {
        const d = def as Record<string, unknown>;
        tools.push({
          name,
          command: typeof d.command === 'string' ? d.command : undefined,
          args: Array.isArray(d.args) ? d.args.map(String) : undefined,
          description: typeof d.description === 'string'
            ? d.description
            : undefined,
          rawContent: JSON.stringify(def),
        });
      }
    }
  }

  // Format 3: { tools: [ { name, ... } ] }
  if (Array.isArray(configData.tools)) {
    for (const def of configData.tools as unknown[]) {
      if (def && typeof def === 'object') {
        const d = def as Record<string, unknown>;
        tools.push({
          name: typeof d.name === 'string' ? d.name : 'unnamed',
          command: typeof d.command === 'string' ? d.command : undefined,
          args: Array.isArray(d.args) ? d.args.map(String) : undefined,
          description: typeof d.description === 'string'
            ? d.description
            : undefined,
          rawContent: JSON.stringify(def),
        });
      }
    }
  }

  // Format 4: VS Code nested -- { mcp: { servers: { ... } } }
  if (configData.mcp && typeof configData.mcp === 'object') {
    const mcpSection = configData.mcp as Record<string, unknown>;
    if (mcpSection.servers && typeof mcpSection.servers === 'object') {
      const vsServers = mcpSection.servers as Record<string, unknown>;
      for (const [name, def] of Object.entries(vsServers)) {
        if (def && typeof def === 'object') {
          const d = def as Record<string, unknown>;
          tools.push({
            name,
            command: typeof d.command === 'string' ? d.command : undefined,
            args: Array.isArray(d.args) ? d.args.map(String) : undefined,
            description: typeof d.description === 'string'
              ? d.description
              : undefined,
            rawContent: JSON.stringify(def),
          });
        }
      }
    }
  }

  return tools;
}

// ─── Utility Functions ───────────────────────────────────────

/**
 * Map severity to approximate CVSS v3.1 base score.
 */
function mapSeverityToCvss(severity: Severity | 'critical' | 'high' | 'medium'): number {
  switch (severity) {
    case 'critical':
      return 9.8;
    case 'high':
      return 8.5;
    case 'medium':
      return 5.5;
    case 'low':
      return 3.1;
    case 'info':
      return 0.0;
    default:
      return 5.0;
  }
}

/**
 * Build a remediation message for a live attack vector.
 */
function buildRemediation(vector: MCPAttackVector): string {
  const remediations: Record<string, string> = {
    'tool-enumeration':
      'Review the MCP server tool surface area. Remove unnecessary tools and ensure each tool has a minimal, well-defined scope. Apply principle of least privilege.',
    'description-injection':
      'Sanitize tool descriptions to remove hidden instructions, invisible characters, and injection payloads. Audit all tool descriptions for suspicious content. Reference: CVE-2025-54135.',
    'schema-validation-bypass':
      'Implement strict input validation on all tool parameters. Reject unexpected argument types, prototype pollution attempts, and injection payloads. Use JSON Schema validation.',
    'tool-squatting':
      'Rename tools that shadow system commands or well-known MCP server tools. Use unique, namespaced tool names to prevent confusion and masquerading.',
    'rug-pull-detection':
      'Implement tool description change detection in MCP clients. Pin MCP server packages to specific versions. Alert users when tool descriptions change after initial approval. Reference: CVE-2025-54135.',
    'cross-tool-priv-esc':
      'Implement tool isolation to prevent cross-tool references in arguments. Validate that tool inputs do not contain references to other tools or internal URIs.',
    'input-size-fuzzing':
      'Implement input size limits and depth limits for all tool parameters. Handle edge cases gracefully (null bytes, Unicode control characters, extremely long strings).',
    'data-exfil-probe':
      'Review tool output sanitization. Ensure tools do not leak sensitive data such as environment variables, credentials, or internal paths in their responses.',
    'env-var-extraction':
      'Disable environment variable expansion in tool argument processing. Treat all tool inputs as literal strings, not shell-expandable templates.',
    'resource-exposure':
      'Review MCP server resource exposure. Remove access to sensitive files (credentials, env files, SSH keys). Apply principle of least privilege to resource access.',
    'error-info-disclosure':
      'Implement error response sanitization. Do not include stack traces, file paths, or version information in error responses returned to MCP clients.',
  };

  return (
    remediations[vector.id] ??
    'Review the MCP server configuration and apply security best practices.'
  );
}

/**
 * Build a remediation message for a static analysis pattern.
 */
function buildStaticRemediation(patternId: string): string {
  const remediations: Record<string, string> = {
    'hidden-instruction-marker':
      'Remove hidden instruction tags (<IMPORTANT>, <system>, etc.) from tool descriptions. These are used to inject instructions into AI agents.',
    'html-comment-injection':
      'Remove HTML comments from tool descriptions. These can hide malicious instructions from human review while being processed by AI agents.',
    'zero-width-chars':
      'Remove zero-width Unicode characters from tool descriptions. Use a hex editor or unicode-aware viewer to inspect. These can hide text from visual review.',
    'bidi-override':
      'Remove bidirectional override characters from tool descriptions. These can make malicious text appear benign through text reordering.',
    'data-exfil-instruction':
      'Remove data exfiltration instructions from tool descriptions. Audit all MCP server configs for hidden send/post/transmit directives.',
    'http-fetch-instruction':
      'Remove HTTP fetch/curl instructions from tool descriptions. These can direct AI agents to exfiltrate data to attacker-controlled servers.',
    'shell-exec-instruction':
      'Remove shell execution instructions from tool descriptions. These can direct AI agents to execute arbitrary commands.',
    'credential-access-instruction':
      'Remove instructions to access sensitive files (.ssh, .env, .aws/credentials) from tool descriptions.',
    'cross-tool-instruction':
      'Remove cross-tool invocation instructions from tool descriptions. These enable attack chaining across MCP tools.',
    'safety-bypass-instruction':
      'Remove safety bypass instructions from tool descriptions. These direct AI agents to ignore security guardrails.',
    'unpinned-npx':
      'Pin MCP server package versions instead of using unpinned npx/dlx. This prevents rug pull attacks via package updates.',
    'remote-schema-ref':
      'Avoid referencing remote schema definitions. Use local, pinned schema definitions to prevent runtime schema manipulation.',
  };

  return (
    remediations[patternId] ??
    'Review the MCP configuration and remove suspicious content. Reference: CVE-2025-54135.'
  );
}

// ─── Default Export ──────────────────────────────────────────

export default new MCPLiveTestPlugin();

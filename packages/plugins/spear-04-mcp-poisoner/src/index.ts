/**
 * SPEAR-04: MCP Poisoning Tester Plugin
 *
 * Tests AI agent environments for MCP (Model Context Protocol) tool
 * description injection vulnerabilities and rug pull attacks.
 *
 * MCP tool poisoning (CVE-2025-54135) is an attack vector where malicious
 * MCP server configurations embed hidden instructions in tool descriptions
 * that trick AI agents into performing unintended actions such as:
 *   - Data exfiltration (sending secrets to attacker-controlled servers)
 *   - Privilege escalation (reading sensitive files beyond the tool's scope)
 *   - Cross-tool poisoning (invoking other tools to create attack chains)
 *   - Rug pull attacks (changing tool behavior after initial approval)
 *
 * Two scan modes:
 *
 *   Safe Mode (default):
 *     Static analysis only. Scans project directory for MCP configuration
 *     files (mcp.json, .cursor/mcp.json, cline_mcp_settings.json, etc.)
 *     and analyzes tool descriptions against a database of 25+ injection
 *     patterns. No network activity, no server started.
 *
 *   Aggressive Mode:
 *     All safe mode checks plus: starts a mock MCP server on 127.0.0.1
 *     that simulates rug pull attacks. Tests whether client tool caches
 *     properly handle post-approval tool redefinition. Records all
 *     interactions for analysis.
 *
 * Architecture:
 *   - Uses patterns.ts for the injection pattern database (25+ patterns)
 *   - Uses mcp-scanner.ts for MCP config file discovery and analysis
 *   - Uses rug-pull.ts for rug pull static analysis and simulation
 *   - Uses mock-server.ts for aggressive mode mock MCP server
 *
 * The scan() method is an AsyncGenerator that yields Finding objects
 * as they are discovered, consistent with the SpearPlugin interface
 * and the pattern established by spear-01 and spear-02.
 */

import { resolve } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';
import { scanMCPConfigs } from './mcp-scanner.js';
import {
  INJECTION_PATTERNS,
  MCP_CONFIG_FILES,
  type InjectionPattern,
} from './patterns.js';
import {
  analyzeRugPullVulnerability,
  generateRugPullFindings,
  RugPullSimulator,
  RUG_PULL_SCENARIOS,
} from './rug-pull.js';
import { MockMCPServer } from './mock-server.js';

// ─── Constants ───────────────────────────────────────────────

/** Time limit for aggressive mode mock server test (30 seconds) */
const MOCK_SERVER_TIMEOUT_MS = 30_000;

// ─── Plugin Implementation ──────────────────────────────────

/**
 * MCPPoisonerPlugin -- Phase 1 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Tests for MCP tool description injection and rug pull vulnerabilities.
 */
export class MCPPoisonerPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'mcp-poisoner',
    name: 'MCP Poisoning Tester',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Tests for MCP tool description injection and rug pull vulnerabilities (CVE-2025-54135)',
    severity: 'critical',
    tags: ['mcp', 'poisoning', 'injection', 'rug-pull', 'ai-security'],
    references: ['CVE-2025-54135', 'CWE-74', 'CWE-94'],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read', 'net:listen'],
    trustLevel: 'builtin',
  };

  /** Compiled regex cache for injection patterns (built during setup) */
  private compiledPatterns: Map<string, RegExp> = new Map();

  /** Mock MCP server instance (aggressive mode only) */
  private mockServer: MockMCPServer | null = null;

  /**
   * Setup: Compile injection patterns into regex objects.
   *
   * Pre-compiling regexes during setup avoids repeated compilation
   * during the hot scan loop. Invalid patterns are logged and skipped.
   */
  async setup(context: PluginContext): Promise<void> {
    context.logger.info('Initializing MCP Poisoning Tester', {
      mode: context.mode,
      patternCount: INJECTION_PATTERNS.length,
      configFileCount: MCP_CONFIG_FILES.length,
    });

    // Pre-compile regex patterns
    let compiledCount = 0;
    let rejectedCount = 0;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.isRegex) {
        try {
          const compiled = new RegExp(pattern.payload, 'i');
          this.compiledPatterns.set(pattern.id, compiled);
          compiledCount++;
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          context.logger.warn('Failed to compile injection pattern regex', {
            patternId: pattern.id,
            error: message,
          });
          rejectedCount++;
        }
      }
    }

    context.logger.info('MCP Poisoning Tester initialized', {
      compiledPatterns: compiledCount,
      rejectedPatterns: rejectedCount,
      scenarioCount: RUG_PULL_SCENARIOS.length,
    });
  }

  /**
   * Scan: Analyze target for MCP poisoning vulnerabilities.
   *
   * In safe mode:
   *   1. Discover MCP config files in the project directory
   *   2. Extract and analyze tool definitions
   *   3. Check tool descriptions against 25+ injection patterns
   *   4. Perform static rug pull vulnerability analysis
   *
   * In aggressive mode:
   *   All safe mode checks plus:
   *   5. Start a mock MCP server with rug pull simulation
   *   6. Record and analyze interactions
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    context.logger.info('Starting MCP poisoning scan', {
      rootDir,
      mode: context.mode,
    });

    let findingsCount = 0;

    // Phase 1: Scan MCP configuration files for injection patterns
    context.logger.info('Phase 1: Scanning MCP config files for injection patterns');

    for await (const finding of scanMCPConfigs(rootDir, context.logger)) {
      findingsCount++;
      yield finding;
    }

    // Phase 2: Static rug pull vulnerability analysis on discovered configs
    context.logger.info('Phase 2: Analyzing for rug pull vulnerabilities');

    for await (const finding of this.analyzeRugPullVulnerabilities(
      rootDir,
      context,
    )) {
      findingsCount++;
      yield finding;
    }

    // Phase 3: Aggressive mode -- Mock MCP server testing
    if (context.mode === 'aggressive') {
      context.logger.info('Phase 3: Starting aggressive mode mock server test');

      for await (const finding of this.runAggressiveModeTest(context)) {
        findingsCount++;
        yield finding;
      }
    }

    context.logger.info('MCP poisoning scan complete', { findingsCount });
  }

  /**
   * Teardown: Stop mock server and release resources.
   */
  async teardown(context: PluginContext): Promise<void> {
    if (this.mockServer) {
      await this.mockServer.stop();
      this.mockServer = null;
    }

    this.compiledPatterns.clear();

    context.logger.info('MCP Poisoning Tester torn down');
  }

  // ──────────────────────────────────────────────────────────────
  // Phase 2: Rug Pull Vulnerability Analysis
  // ──────────────────────────────────────────────────────────────

  /**
   * Analyze MCP config files for rug pull vulnerability indicators.
   *
   * Reads each discovered config file, extracts tool definitions, and
   * checks for patterns that indicate the tool could be silently
   * redefined after approval.
   */
  private async *analyzeRugPullVulnerabilities(
    rootDir: string,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const { readFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { access } = await import('node:fs/promises');
    const { constants: fsConstants } = await import('node:fs');

    for (const configRelPath of MCP_CONFIG_FILES) {
      const configAbsPath = join(rootDir, configRelPath);

      // Check if file exists
      try {
        await access(configAbsPath, fsConstants.R_OK);
      } catch {
        continue;
      }

      // Read and parse
      let rawContent: string;
      try {
        rawContent = await readFile(configAbsPath, 'utf-8');
      } catch {
        continue;
      }

      let configData: Record<string, unknown>;
      try {
        configData = JSON.parse(rawContent) as Record<string, unknown>;
      } catch {
        continue;
      }

      // Extract tool definitions and analyze each for rug pull vulnerabilities
      const tools = this.extractToolsForRugPull(configData);

      for (const tool of tools) {
        const vulnerabilities = analyzeRugPullVulnerability(
          tool.name,
          tool.command,
          tool.args,
          tool.rawContent,
        );

        if (vulnerabilities.length > 0) {
          for await (const finding of generateRugPullFindings(
            tool.name,
            configRelPath,
            vulnerabilities,
            context.logger,
          )) {
            yield finding;
          }
        }
      }
    }
  }

  /**
   * Extract tool entries from a config for rug pull analysis.
   *
   * Simplified extraction that focuses on the fields relevant to
   * rug pull analysis (command, args, raw content).
   */
  private extractToolsForRugPull(
    configData: Record<string, unknown>,
  ): Array<{
    name: string;
    command?: string;
    args?: string[];
    rawContent: string;
  }> {
    const tools: Array<{
      name: string;
      command?: string;
      args?: string[];
      rawContent: string;
    }> = [];

    // Handle mcpServers format
    const servers =
      (configData.mcpServers as Record<string, unknown> | undefined) ??
      (configData.servers as Record<string, unknown> | undefined);

    if (servers && typeof servers === 'object') {
      for (const [name, def] of Object.entries(servers)) {
        if (def && typeof def === 'object') {
          const serverDef = def as Record<string, unknown>;
          tools.push({
            name,
            command: typeof serverDef.command === 'string'
              ? serverDef.command
              : undefined,
            args: Array.isArray(serverDef.args)
              ? serverDef.args.map(String)
              : undefined,
            rawContent: JSON.stringify(def),
          });
        }
      }
    }

    // Handle VS Code nested mcp.servers format
    if (configData.mcp && typeof configData.mcp === 'object') {
      const mcpSection = configData.mcp as Record<string, unknown>;
      if (mcpSection.servers && typeof mcpSection.servers === 'object') {
        const vsServers = mcpSection.servers as Record<string, unknown>;
        for (const [name, def] of Object.entries(vsServers)) {
          if (def && typeof def === 'object') {
            const serverDef = def as Record<string, unknown>;
            tools.push({
              name,
              command: typeof serverDef.command === 'string'
                ? serverDef.command
                : undefined,
              args: Array.isArray(serverDef.args)
                ? serverDef.args.map(String)
                : undefined,
              rawContent: JSON.stringify(def),
            });
          }
        }
      }
    }

    return tools;
  }

  // ──────────────────────────────────────────────────────────────
  // Phase 3: Aggressive Mode Testing
  // ──────────────────────────────────────────────────────────────

  /**
   * Run aggressive mode test with a mock MCP server.
   *
   * Starts a mock server that simulates rug pull attacks, waits for
   * a timeout period, then analyzes the recorded interactions.
   */
  private async *runAggressiveModeTest(
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    // Run each rug pull scenario
    for (const scenario of RUG_PULL_SCENARIOS) {
      context.logger.info('Testing rug pull scenario', {
        scenarioId: scenario.id,
        scenarioName: scenario.name,
      });

      this.mockServer = new MockMCPServer(context.logger, scenario);

      let port: number;
      try {
        port = await this.mockServer.start();
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Failed to start mock MCP server', {
          scenario: scenario.id,
          error: message,
        });
        continue;
      }

      // In aggressive mode, we report the availability of the mock server
      // as a finding so the orchestrator or human tester can connect to it
      yield {
        ruleId: 'MCP-MOCK-SERVER',
        severity: 'info',
        message:
          `Mock MCP server for rug pull scenario '${scenario.name}' ` +
          `available at 127.0.0.1:${port}. ` +
          `Connect an AI agent to test rug pull detection. ` +
          `The tool will switch from benign to malicious after ` +
          `${scenario.maliciousVersion.activatesAfterCalls} calls.`,
        mitreTechniques: scenario.mitreTechniques,
        remediation:
          'Ensure your AI agent client validates tool descriptions on every ' +
          'tools/list call and alerts when descriptions change post-approval.',
        metadata: {
          pluginId: 'mcp-poisoner',
          category: 'rug_pull',
          scenarioId: scenario.id,
          scenarioName: scenario.name,
          mockServerPort: port,
          benignDescription: scenario.benignVersion.description,
          maliciousDescription: scenario.maliciousVersion.description,
          triggerAfterCalls: scenario.maliciousVersion.activatesAfterCalls,
          source: 'mock-server-test',
        },
      };

      // Wait briefly for any automated test connections, then analyze
      await sleep(Math.min(MOCK_SERVER_TIMEOUT_MS, 2000));

      // Analyze interactions (if any clients connected)
      const interactions = this.mockServer.getInteractions();

      if (interactions.length > 0) {
        const maliciousInteractions = interactions.filter(
          (i) => i.rugPullActive,
        );

        if (maliciousInteractions.length > 0) {
          yield {
            ruleId: 'MCP-RUGPULL-DETECTED',
            severity: 'critical',
            message:
              `Rug pull scenario '${scenario.name}' triggered: ` +
              `${maliciousInteractions.length} interactions occurred after ` +
              `tool redefinition. The connected client did not detect the change.`,
            cvss: 9.8,
            mitreTechniques: scenario.mitreTechniques,
            remediation:
              'Implement tool description change detection in the MCP client. ' +
              'Alert users when a tool description changes after initial approval. ' +
              'Reference: CVE-2025-54135',
            metadata: {
              pluginId: 'mcp-poisoner',
              category: 'rug_pull',
              scenarioId: scenario.id,
              totalInteractions: interactions.length,
              maliciousInteractions: maliciousInteractions.length,
              cveReferences: ['CVE-2025-54135'],
              source: 'mock-server-analysis',
            },
          };
        }
      }

      // Stop this scenario's server
      await this.mockServer.stop();
      this.mockServer = null;
    }
  }
}

// ─── Utility Functions ───────────────────────────────────────

/**
 * Sleep for a specified duration.
 *
 * @param ms - Milliseconds to sleep.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Default Export ──────────────────────────────────────────

export default new MCPPoisonerPlugin();

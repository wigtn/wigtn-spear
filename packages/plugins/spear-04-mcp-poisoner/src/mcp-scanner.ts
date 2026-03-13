/**
 * MCP Configuration Scanner
 *
 * Scans project directories for MCP configuration files and analyzes
 * tool descriptions for injection patterns. This is the primary
 * detection engine used in safe mode (no network required).
 *
 * The scanner operates in two phases:
 *
 *   Phase 1 -- Discovery
 *     Walk the project directory and locate known MCP config file paths
 *     (mcp.json, .cursor/mcp.json, cline_mcp_settings.json, etc.).
 *
 *   Phase 2 -- Analysis
 *     Parse each config file as JSON, extract tool definitions and their
 *     descriptions, then match each description against the injection
 *     pattern database from patterns.ts.
 *
 * Design decisions:
 *   - JSON parsing is lenient: malformed files are skipped with a warning
 *     rather than failing the entire scan.
 *   - Tool descriptions are tested against both regex and literal patterns.
 *   - The scanner extracts descriptions from multiple config schema formats
 *     (Claude, Cursor, Cline, VS Code) since each uses slightly different
 *     JSON structure.
 *   - All file reads are done with readFile (not streaming) since MCP
 *     config files are small (typically < 100 KB).
 */

import { readFile, access } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { constants as fsConstants } from 'node:fs';
import type { Finding, SpearLogger, Severity } from '@wigtn/shared';
import {
  INJECTION_PATTERNS,
  MCP_CONFIG_FILES,
  type InjectionPattern,
  type InjectionCategory,
} from './patterns.js';

// ─── Types ───────────────────────────────────────────────────

/** A tool definition extracted from an MCP config file */
export interface MCPToolDefinition {
  /** Name of the MCP server or tool */
  name: string;
  /** Command used to start the MCP server */
  command?: string;
  /** Arguments passed to the command */
  args?: string[];
  /** Environment variables passed to the server */
  env?: Record<string, string>;
  /** Tool description (primary target for injection analysis) */
  description?: string;
  /** Raw JSON content of the tool entry for deep inspection */
  rawContent: string;
}

/** Result of analyzing a single tool description */
export interface ToolAnalysisResult {
  /** The tool definition that was analyzed */
  tool: MCPToolDefinition;
  /** Injection patterns matched in the tool description/config */
  matchedPatterns: InjectionPattern[];
  /** The config file where this tool was found */
  configFile: string;
}

// ─── Scanner ─────────────────────────────────────────────────

/**
 * Scan a project directory for MCP configuration files and analyze
 * their tool descriptions for injection patterns.
 *
 * @param rootDir - The root directory of the project to scan.
 * @param logger - Logger for diagnostic output.
 * @yields Finding objects for each detected injection pattern match.
 */
export async function* scanMCPConfigs(
  rootDir: string,
  logger: SpearLogger,
): AsyncGenerator<Finding> {
  logger.info('Scanning for MCP configuration files', { rootDir });

  let configsFound = 0;
  let toolsAnalyzed = 0;
  let findingsCount = 0;

  // Phase 1: Discover MCP config files
  for (const configRelPath of MCP_CONFIG_FILES) {
    const configAbsPath = join(rootDir, configRelPath);

    // Check if the file exists before attempting to read
    const exists = await fileExists(configAbsPath);
    if (!exists) {
      continue;
    }

    configsFound++;
    logger.info('Found MCP config file', { path: configRelPath });

    // Read and parse the config file
    let rawContent: string;
    try {
      rawContent = await readFile(configAbsPath, 'utf-8');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn('Failed to read MCP config file', {
        path: configRelPath,
        error: message,
      });
      continue;
    }

    // Parse JSON content
    let configData: unknown;
    try {
      configData = JSON.parse(rawContent);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn('Failed to parse MCP config file as JSON', {
        path: configRelPath,
        error: message,
      });
      continue;
    }

    // Phase 2: Extract tool definitions and analyze
    const tools = extractToolDefinitions(configData);

    if (tools.length === 0) {
      logger.debug('No tool definitions found in config', {
        path: configRelPath,
      });

      // Still scan the raw content for injection patterns
      // (the config itself might contain malicious content even without
      // explicitly structured tool definitions)
      for await (const finding of analyzeRawContent(
        rawContent,
        configRelPath,
        logger,
      )) {
        findingsCount++;
        yield finding;
      }

      continue;
    }

    logger.info('Extracted tool definitions', {
      path: configRelPath,
      count: tools.length,
    });

    for (const tool of tools) {
      toolsAnalyzed++;
      const result = analyzeTool(tool, configRelPath);

      for (const pattern of result.matchedPatterns) {
        findingsCount++;
        yield buildFinding(result, pattern);
      }
    }

    // Also analyze the full raw config content for hidden patterns
    // that may not be inside a specific tool definition
    for await (const finding of analyzeRawContent(
      rawContent,
      configRelPath,
      logger,
    )) {
      findingsCount++;
      yield finding;
    }
  }

  logger.info('MCP config scan complete', {
    configsFound,
    toolsAnalyzed,
    findingsCount,
  });
}

// ─── Tool Definition Extraction ──────────────────────────────

/**
 * Extract MCP tool definitions from a parsed JSON config.
 *
 * Handles multiple config schema formats:
 *   - Claude Desktop: { mcpServers: { name: { command, args, env } } }
 *   - Cursor/VS Code: { mcpServers: { name: { command, args } } }
 *   - Cline: { mcpServers: { name: { command, args, disabled } } }
 *   - Generic: { servers: [...] } or { tools: [...] }
 *
 * @param configData - Parsed JSON config data.
 * @returns Array of extracted tool definitions.
 */
function extractToolDefinitions(configData: unknown): MCPToolDefinition[] {
  if (!configData || typeof configData !== 'object') {
    return [];
  }

  const tools: MCPToolDefinition[] = [];
  const config = configData as Record<string, unknown>;

  // Format 1: { mcpServers: { name: { ... } } } -- Claude, Cursor, Cline
  if (config.mcpServers && typeof config.mcpServers === 'object') {
    const servers = config.mcpServers as Record<string, unknown>;
    for (const [name, serverDef] of Object.entries(servers)) {
      if (serverDef && typeof serverDef === 'object') {
        const def = serverDef as Record<string, unknown>;
        tools.push({
          name,
          command: typeof def.command === 'string' ? def.command : undefined,
          args: Array.isArray(def.args) ? def.args.map(String) : undefined,
          env: isStringRecord(def.env) ? def.env : undefined,
          description: typeof def.description === 'string' ? def.description : undefined,
          rawContent: JSON.stringify(serverDef),
        });
      }
    }
  }

  // Format 2: { servers: { name: { ... } } } -- Alternative layout
  if (config.servers && typeof config.servers === 'object') {
    const servers = config.servers as Record<string, unknown>;
    for (const [name, serverDef] of Object.entries(servers)) {
      if (serverDef && typeof serverDef === 'object') {
        const def = serverDef as Record<string, unknown>;
        tools.push({
          name,
          command: typeof def.command === 'string' ? def.command : undefined,
          args: Array.isArray(def.args) ? def.args.map(String) : undefined,
          env: isStringRecord(def.env) ? def.env : undefined,
          description: typeof def.description === 'string' ? def.description : undefined,
          rawContent: JSON.stringify(serverDef),
        });
      }
    }
  }

  // Format 3: { tools: [ { name, description, ... } ] } -- Array format
  if (Array.isArray(config.tools)) {
    for (const toolDef of config.tools) {
      if (toolDef && typeof toolDef === 'object') {
        const def = toolDef as Record<string, unknown>;
        tools.push({
          name: typeof def.name === 'string' ? def.name : 'unnamed',
          command: typeof def.command === 'string' ? def.command : undefined,
          args: Array.isArray(def.args) ? def.args.map(String) : undefined,
          env: isStringRecord(def.env) ? def.env : undefined,
          description: typeof def.description === 'string' ? def.description : undefined,
          rawContent: JSON.stringify(toolDef),
        });
      }
    }
  }

  // Format 4: VS Code settings.json -- nested under mcp.servers
  if (config.mcp && typeof config.mcp === 'object') {
    const mcpSection = config.mcp as Record<string, unknown>;
    if (mcpSection.servers && typeof mcpSection.servers === 'object') {
      const servers = mcpSection.servers as Record<string, unknown>;
      for (const [name, serverDef] of Object.entries(servers)) {
        if (serverDef && typeof serverDef === 'object') {
          const def = serverDef as Record<string, unknown>;
          tools.push({
            name,
            command: typeof def.command === 'string' ? def.command : undefined,
            args: Array.isArray(def.args) ? def.args.map(String) : undefined,
            env: isStringRecord(def.env) ? def.env : undefined,
            description: typeof def.description === 'string' ? def.description : undefined,
            rawContent: JSON.stringify(serverDef),
          });
        }
      }
    }
  }

  return tools;
}

// ─── Tool Analysis ───────────────────────────────────────────

/**
 * Analyze a single tool definition against the injection pattern database.
 *
 * Checks both the explicit tool description (if present) and the raw
 * JSON content of the tool entry for injection patterns.
 *
 * @param tool - The tool definition to analyze.
 * @param configFile - The config file path (for reporting).
 * @returns Analysis result with all matched patterns.
 */
function analyzeTool(
  tool: MCPToolDefinition,
  configFile: string,
): ToolAnalysisResult {
  const matchedPatterns: InjectionPattern[] = [];

  // Text surfaces to analyze: description, raw content, args, env values
  const surfaces: string[] = [];

  if (tool.description) {
    surfaces.push(tool.description);
  }

  // Check command + args for suspicious patterns (e.g., npx without pinning)
  if (tool.command) {
    surfaces.push(tool.command);
  }
  if (tool.args) {
    surfaces.push(tool.args.join(' '));
  }

  // Check environment variables for suspicious values
  if (tool.env) {
    for (const value of Object.values(tool.env)) {
      surfaces.push(value);
    }
  }

  // Always analyze the raw content as a fallback
  surfaces.push(tool.rawContent);

  // Deduplicate surfaces for efficiency
  const uniqueSurfaces = [...new Set(surfaces)];

  for (const pattern of INJECTION_PATTERNS) {
    for (const surface of uniqueSurfaces) {
      if (matchesPattern(surface, pattern)) {
        matchedPatterns.push(pattern);
        break; // One match per pattern is enough
      }
    }
  }

  return { tool, matchedPatterns, configFile };
}

/**
 * Analyze raw config file content for hidden injection patterns.
 *
 * This catches patterns that exist in the raw text but may not be
 * inside a specific tool definition field. Primarily targets hidden
 * injection patterns (zero-width characters, HTML comments, etc.)
 * that are invisible in parsed JSON.
 *
 * Only yields findings for hidden_inject category patterns to avoid
 * double-counting with the per-tool analysis.
 *
 * @param rawContent - The raw file content.
 * @param configFile - The config file path (for reporting).
 * @param logger - Logger for diagnostics.
 * @yields Finding objects for hidden injection pattern matches.
 */
async function* analyzeRawContent(
  rawContent: string,
  configFile: string,
  logger: SpearLogger,
): AsyncGenerator<Finding> {
  // Only check hidden_inject patterns on raw content
  // (other patterns are already checked per-tool)
  const hiddenPatterns = INJECTION_PATTERNS.filter(
    (p) => p.category === 'hidden_inject',
  );

  for (const pattern of hiddenPatterns) {
    if (matchesPattern(rawContent, pattern)) {
      logger.debug('Hidden injection pattern detected in raw config', {
        patternId: pattern.id,
        configFile,
      });

      // Find the approximate line number of the match
      const lineNumber = findPatternLine(rawContent, pattern);

      yield {
        ruleId: pattern.id,
        severity: mapPatternSeverity(pattern.severity),
        message: `MCP Poisoning: ${pattern.description}`,
        file: configFile,
        line: lineNumber,
        mitreTechniques: pattern.mitreTechniques,
        remediation: buildRemediation(pattern),
        metadata: {
          pluginId: 'mcp-poisoner',
          category: pattern.category,
          cveReferences: pattern.cveReferences,
          source: 'raw-config-analysis',
        },
      };
    }
  }
}

// ─── Pattern Matching ────────────────────────────────────────

/**
 * Test whether a text surface matches an injection pattern.
 *
 * @param text - The text to check.
 * @param pattern - The injection pattern to test against.
 * @returns true if the pattern matches the text.
 */
function matchesPattern(text: string, pattern: InjectionPattern): boolean {
  if (!text || text.length === 0) {
    return false;
  }

  if (pattern.isRegex) {
    try {
      const regex = new RegExp(pattern.payload, 'i');
      return regex.test(text);
    } catch {
      // Invalid regex pattern; fall back to substring search
      return text.toLowerCase().includes(pattern.payload.toLowerCase());
    }
  }

  return text.toLowerCase().includes(pattern.payload.toLowerCase());
}

/**
 * Find the approximate line number of a pattern match within text.
 *
 * @param text - The full text content.
 * @param pattern - The pattern to locate.
 * @returns 1-based line number, or 1 if not found.
 */
function findPatternLine(text: string, pattern: InjectionPattern): number {
  if (pattern.isRegex) {
    try {
      const regex = new RegExp(pattern.payload, 'i');
      const match = regex.exec(text);
      if (match && match.index !== undefined) {
        const beforeMatch = text.slice(0, match.index);
        return beforeMatch.split('\n').length;
      }
    } catch {
      // Fall through to return default
    }
  } else {
    const index = text.toLowerCase().indexOf(pattern.payload.toLowerCase());
    if (index >= 0) {
      const beforeMatch = text.slice(0, index);
      return beforeMatch.split('\n').length;
    }
  }

  return 1;
}

// ─── Finding Construction ────────────────────────────────────

/**
 * Build a Finding from a tool analysis result and matched pattern.
 *
 * Consistent with the Finding construction pattern used in spear-01
 * and spear-02 plugins.
 */
function buildFinding(
  result: ToolAnalysisResult,
  pattern: InjectionPattern,
): Finding {
  return {
    ruleId: pattern.id,
    severity: mapPatternSeverity(pattern.severity),
    message: `MCP Poisoning in tool '${result.tool.name}': ${pattern.description}`,
    file: result.configFile,
    mitreTechniques: pattern.mitreTechniques,
    remediation: buildRemediation(pattern),
    cvss: mapSeverityToCvss(pattern.severity),
    metadata: {
      pluginId: 'mcp-poisoner',
      category: pattern.category,
      toolName: result.tool.name,
      toolCommand: result.tool.command,
      cveReferences: pattern.cveReferences,
      source: 'config-tool-analysis',
    },
  };
}

/**
 * Map pattern severity string to the shared Severity type.
 * Pattern severity already matches the Severity type, but this ensures
 * type safety at the boundary.
 */
function mapPatternSeverity(severity: InjectionPattern['severity']): Severity {
  return severity;
}

/**
 * Map severity level to an approximate CVSS v3.1 base score.
 */
function mapSeverityToCvss(severity: InjectionPattern['severity']): number {
  switch (severity) {
    case 'critical': return 9.8;
    case 'high': return 8.2;
    case 'medium': return 5.5;
    case 'low': return 3.1;
  }
}

/**
 * Build a remediation message for an injection pattern finding.
 */
function buildRemediation(pattern: InjectionPattern): string {
  const parts: string[] = [];

  switch (pattern.category) {
    case 'data_exfil':
      parts.push('Remove or sanitize the tool description to eliminate data exfiltration instructions.');
      parts.push('Audit all MCP server tool descriptions for hidden fetch/curl/send directives.');
      break;
    case 'priv_esc':
      parts.push('Remove instructions that direct the AI agent to read sensitive files or execute commands.');
      parts.push('Limit MCP server permissions to only the resources needed for its stated purpose.');
      break;
    case 'cross_tool':
      parts.push('Remove cross-tool invocation instructions from the tool description.');
      parts.push('Ensure MCP tool descriptions do not instruct the agent to bypass safety checks.');
      break;
    case 'rug_pull':
      parts.push('Pin MCP server packages to specific versions to prevent bait-and-switch attacks.');
      parts.push('Avoid dynamic/remote tool descriptions that can change after approval.');
      break;
    case 'hidden_inject':
      parts.push('Remove invisible characters (zero-width, bidirectional overrides) from tool descriptions.');
      parts.push('Inspect MCP config files with a hex editor or unicode-aware viewer.');
      break;
  }

  if (pattern.cveReferences.length > 0) {
    parts.push(`References: ${pattern.cveReferences.join(', ')}`);
  }

  return parts.join(' ');
}

// ─── Utility Functions ───────────────────────────────────────

/**
 * Check if a file exists and is readable.
 *
 * @param filePath - Absolute path to check.
 * @returns true if the file exists and is readable.
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, fsConstants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Type guard: check if a value is a Record<string, string>.
 */
function isStringRecord(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  return Object.values(value as Record<string, unknown>).every(
    (v) => typeof v === 'string',
  );
}

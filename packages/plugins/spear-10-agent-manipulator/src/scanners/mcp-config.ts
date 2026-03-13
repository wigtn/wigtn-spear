/**
 * SPEAR-10: MCP Configuration Scanner
 *
 * Scans Model Context Protocol (MCP) configuration files for injection patterns:
 *   - mcp.json                   -- Standard MCP config
 *   - .cursor/mcp.json           -- Cursor-specific MCP config
 *   - cline_mcp_settings.json    -- Cline MCP settings
 *   - .vscode/mcp.json           -- VS Code MCP config
 *
 * MCP servers extend AI agent capabilities with external tools.
 * A malicious MCP configuration can:
 *   - Point to untrusted MCP servers that intercept all agent interactions
 *   - Grant excessive tool permissions to external servers
 *   - Expose environment variables containing secrets via server args
 *   - Use tool descriptions to inject hidden instructions
 *
 * This scanner checks for 10+ dangerous patterns specific to MCP config.
 */

import type { Finding } from '@wigtn/shared';
import type { InjectionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── MCP-Specific File Patterns ────────────────────────────────

/** Filenames that are MCP configuration files. */
export const MCP_FILE_PATTERNS: readonly string[] = [
  'mcp.json',
  'cline_mcp_settings.json',
];

/**
 * Check if a relative file path is an MCP configuration file.
 */
export function isMcpFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Direct file matches
  if (MCP_FILE_PATTERNS.includes(filename)) {
    return true;
  }

  // MCP configs within IDE directories
  if (
    normalized === '.cursor/mcp.json' ||
    normalized === '.vscode/mcp.json' ||
    normalized === '.continue/config.json'
  ) {
    return true;
  }

  return false;
}

// ─── MCP-Specific Patterns ─────────────────────────────────────

/**
 * Additional patterns specifically targeting MCP configuration abuse.
 */
export const MCP_SPECIFIC_PATTERNS: readonly InjectionPattern[] = [
  {
    id: 'mcp-untrusted-server-url',
    name: 'Untrusted MCP Server URL',
    description: 'MCP configuration references a server URL that is not a well-known trusted provider',
    category: 'config_override',
    pattern: /["']?(?:url|endpoint|serverUrl|baseUrl)["']?\s*:\s*["']https?:\/\/(?!(?:localhost|127\.0\.0\.1|api\.anthropic\.com|api\.openai\.com|registry\.npmjs\.org|pypi\.org|github\.com))[^"']+["']/i,
    severity: 'high',
    mitre: ['T1071', 'T1195.002'],
    remediation: 'Verify all MCP server URLs are from trusted providers. Unknown URLs may point to malicious servers that intercept agent data.',
  },
  {
    id: 'mcp-env-var-exposure',
    name: 'Environment Variable Exposure in MCP Args',
    description: 'MCP server configuration passes sensitive environment variables as arguments',
    category: 'exfiltration',
    pattern: /["']?(?:args|arguments|env|environment)["']?\s*:\s*(?:\[[\s\S]*?|{[\s\S]*?)(?:\$\{?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE_KEY|DATABASE_URL|DB_PASSWORD|AWS_SECRET)|process\.env\[?["']?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE_KEY|DATABASE_URL|DB_PASSWORD|AWS_SECRET))/i,
    severity: 'critical',
    mitre: ['T1552', 'T1567'],
    remediation: 'Do not pass sensitive environment variables to MCP server arguments. Use secure credential management instead of exposing secrets in config.',
  },
  {
    id: 'mcp-suspicious-tool-desc',
    name: 'Suspicious MCP Tool Description',
    description: 'MCP tool description contains hidden instructions or prompt injection',
    category: 'cot_hijack',
    pattern: /["']?description["']?\s*:\s*["'][^"']*(?:ignore\s+previous|override\s+instructions?|always\s+(?:include|execute|send)|secretly|hidden\s+instruction|before\s+responding\s+(?:to|always))[^"']*["']/i,
    severity: 'critical',
    mitre: ['T1190'],
    remediation: 'Remove prompt injection from MCP tool descriptions. Tool descriptions should only describe the tool functionality, not contain hidden instructions.',
  },
  {
    id: 'mcp-excessive-permissions',
    name: 'Excessive MCP Tool Permissions',
    description: 'MCP server configured with overly broad file system or network permissions',
    category: 'config_override',
    pattern: /["']?(?:permissions|capabilities|access)["']?\s*:\s*(?:\[\s*["']?(?:\*|all|full|unrestricted)["']?\s*\]|["']?(?:\*|all|full|unrestricted)["']?)/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Restrict MCP server permissions to the minimum required. Do not use wildcard or "all" permissions.',
  },
  {
    id: 'mcp-stdio-command-inject',
    name: 'Command Injection in MCP stdio',
    description: 'MCP server using stdio transport with suspicious command arguments',
    category: 'privilege_escalation',
    pattern: /["']?command["']?\s*:\s*["'](?:.*(?:&&|;\s*|\|\s*|`|eval\s|exec\s|\$\().*|sh\s+-c\s+|bash\s+-c\s+|cmd\s+\/c\s+)["']/i,
    severity: 'critical',
    mitre: ['T1059'],
    remediation: 'Remove command injection patterns from MCP server commands. Use simple, direct commands without shell metacharacters.',
  },
  {
    id: 'mcp-sse-open-endpoint',
    name: 'Open SSE Endpoint',
    description: 'MCP server using SSE transport with publicly accessible endpoint',
    category: 'config_override',
    pattern: /["']?transport["']?\s*:\s*["']sse["'][\s\S]*?["']?url["']?\s*:\s*["']https?:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))[^"']+["']/i,
    severity: 'high',
    mitre: ['T1071'],
    remediation: 'Ensure SSE-based MCP servers are not publicly accessible. Use localhost bindings or authenticated endpoints.',
  },
  {
    id: 'mcp-tool-name-override',
    name: 'Tool Name Collision/Override',
    description: 'MCP tool name that shadows a built-in or common tool name',
    category: 'cot_hijack',
    pattern: /["']?(?:name|toolName)["']?\s*:\s*["'](?:read_file|write_file|execute_command|search|bash|terminal|edit_file|list_directory|run_command)["']/i,
    severity: 'high',
    mitre: ['T1574'],
    remediation: 'Rename MCP tools that shadow built-in tool names. Tool name collisions can hijack agent behavior.',
  },
  {
    id: 'mcp-server-auto-approve',
    name: 'MCP Server Auto-Approve',
    description: 'MCP configuration with auto-approve enabled for server tools',
    category: 'config_override',
    pattern: /["']?(?:autoApprove|auto_approve|skipConfirmation|alwaysAllow)["']?\s*:\s*(?:true|\[\s*["']\*["']\s*\])/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Disable auto-approve for MCP server tools. All tool invocations should require user confirmation.',
  },
  {
    id: 'mcp-npx-remote-package',
    name: 'NPX Remote Package Execution',
    description: 'MCP server using npx to execute a package directly from the registry',
    category: 'privilege_escalation',
    pattern: /["']?command["']?\s*:\s*["']npx["'][\s\S]*?["']?args["']?\s*:\s*\[\s*["'](?:-y\s+)?(?!@modelcontextprotocol\/)[^"']+["']/i,
    severity: 'high',
    mitre: ['T1195.002', 'T1059'],
    remediation: 'Verify npx packages used by MCP servers are from trusted sources. Prefer locally installed packages over remote execution.',
  },
  {
    id: 'mcp-tool-input-schema-lax',
    name: 'Lax Tool Input Schema',
    description: 'MCP tool with overly permissive input schema allowing arbitrary data',
    category: 'config_override',
    pattern: /["']?inputSchema["']?\s*:\s*\{\s*["']?type["']?\s*:\s*["'](?:any|object)["']?\s*(?:,\s*["']?additionalProperties["']?\s*:\s*true)?\s*\}/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Define strict input schemas for MCP tools. Use specific property definitions and set additionalProperties to false.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to MCP configuration files.
 * Combines generic injection patterns with MCP-specific patterns.
 */
const MCP_PATTERNS: readonly InjectionPattern[] = [
  ...ALL_PATTERNS,
  ...MCP_SPECIFIC_PATTERNS,
];

/**
 * Scan file content against all MCP-applicable injection patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanMcpContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of MCP_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[MCP Config] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'mcp-config',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[MCP Config] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'mcp-config',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

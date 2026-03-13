/**
 * SPEAR-10: Claude Settings Scanner
 *
 * Scans Claude AI agent configuration files for injection patterns:
 *   - .claude/settings.json     -- Claude Code permission settings
 *   - .claude/commands/*.md     -- Custom slash commands
 *   - CLAUDE.md                 -- Project-level Claude instructions
 *
 * Claude Code uses a file-based permission system where .claude/settings.json
 * defines which tools the agent can use without asking. An attacker can:
 *   - Grant overly permissive tool access (Bash("*"), Edit("*"))
 *   - Inject hidden instructions in CLAUDE.md
 *   - Create custom commands that execute dangerous operations
 *   - Configure MCP servers pointing to malicious endpoints
 *
 * This scanner checks for 10+ dangerous patterns specific to Claude config.
 */

import type { Finding } from '@wigtn/shared';
import type { InjectionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Claude-Specific File Patterns ─────────────────────────────

/** Filenames and paths that are Claude AI configuration files. */
export const CLAUDE_FILE_PATTERNS: readonly string[] = [
  'CLAUDE.md',
  'claude.md',
];

/** Directory patterns for Claude config. */
export const CLAUDE_DIR_PATTERNS: readonly string[] = [
  '.claude',
];

/**
 * Check if a relative file path is a Claude configuration file.
 */
export function isClaudeFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Direct file matches
  if (filename.toLowerCase() === 'claude.md') {
    return true;
  }

  // Files within .claude/ directory
  if (normalized.startsWith('.claude/') || normalized === '.claude') {
    return true;
  }

  return false;
}

// ─── Claude-Specific Patterns ──────────────────────────────────

/**
 * Additional patterns specifically targeting Claude configuration abuse.
 */
export const CLAUDE_SPECIFIC_PATTERNS: readonly InjectionPattern[] = [
  {
    id: 'claude-settings-wildcard-bash',
    name: 'Wildcard Bash Permission',
    description: 'Claude settings allow Bash tool with unrestricted glob patterns',
    category: 'config_override',
    pattern: /["']?Bash["']?\s*(?:\(\s*["']\*["']\s*\)|:\s*(?:true|\*|["']\*["']))/i,
    severity: 'critical',
    mitre: ['T1059', 'T1562'],
    remediation: 'Restrict Bash permissions to specific safe commands instead of wildcard (*). Use explicit patterns like Bash("npm test") or Bash("git status").',
  },
  {
    id: 'claude-settings-wildcard-edit',
    name: 'Wildcard Edit Permission',
    description: 'Claude settings allow Edit tool with unrestricted file patterns',
    category: 'config_override',
    pattern: /["']?(?:Edit|Write)["']?\s*(?:\(\s*["']\*["']\s*\)|:\s*(?:true|\*|["']\*["']))/i,
    severity: 'high',
    mitre: ['T1565', 'T1562'],
    remediation: 'Restrict Edit/Write permissions to specific directories within the project. Avoid wildcard file access patterns.',
  },
  {
    id: 'claude-settings-allow-all-tools',
    name: 'All Tools Allowed',
    description: 'Claude settings permit all tools without restrictions',
    category: 'config_override',
    pattern: /["']?allowedTools["']?\s*:\s*\[\s*["']\*["']\s*\]/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Do not allow all tools with wildcard. Explicitly list only the tools required for the project.',
  },
  {
    id: 'claude-settings-mcp-untrusted',
    name: 'Untrusted MCP Server in Claude Settings',
    description: 'Claude settings reference MCP servers from non-standard or suspicious URLs',
    category: 'config_override',
    pattern: /["']?(?:mcpServers|mcp_servers)["']?\s*:\s*\{[\s\S]*?["']?(?:url|command|endpoint)["']?\s*:\s*["'](?!(?:npx|uvx|node|python)\b)https?:\/\/(?!(?:localhost|127\.0\.0\.1))/i,
    severity: 'critical',
    mitre: ['T1195.002', 'T1071'],
    remediation: 'Verify all MCP server URLs are from trusted sources. Remove references to unknown or suspicious endpoints.',
  },
  {
    id: 'claude-cmd-dangerous-exec',
    name: 'Dangerous Custom Command',
    description: 'Claude custom command containing potentially dangerous shell operations',
    category: 'privilege_escalation',
    pattern: /(?:```(?:bash|sh|shell|zsh)[\s\S]*?(?:rm\s+-rf|sudo|chmod|curl\s+.*\|\s*(?:sh|bash)|wget\s+.*\|\s*(?:sh|bash)|eval\s*\(|exec\s*\()[\s\S]*?```)/i,
    severity: 'critical',
    mitre: ['T1059'],
    remediation: 'Remove dangerous shell operations from Claude custom commands. Commands should not use rm -rf, sudo, eval, or pipe-to-shell patterns.',
  },
  {
    id: 'claude-md-hidden-instruction',
    name: 'Hidden Instructions in CLAUDE.md',
    description: 'Instructions hidden using HTML comments or invisible formatting in CLAUDE.md',
    category: 'stealth_injection',
    pattern: /<!--[\s\S]*?(?:always|never|must|ignore|override|bypass|send|fetch|execute|include|secretly)[\s\S]*?-->/i,
    severity: 'high',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove hidden HTML comment instructions from CLAUDE.md. All AI instructions should be visible and auditable.',
  },
  {
    id: 'claude-md-deny-list-bypass',
    name: 'Deny List Bypass in CLAUDE.md',
    description: 'Instructions attempting to override or bypass Claude deny lists',
    category: 'privilege_escalation',
    pattern: /(?:deny|block|restrict|forbidden|denied)\s*(?:list|tools?|commands?|operations?)\s*(?:should|must|can)\s*(?:be\s+)?(?:ignored|overridden|bypassed|disabled|empty|cleared)/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Remove deny list bypass instructions. Security deny lists exist to prevent dangerous operations and must not be overridden.',
  },
  {
    id: 'claude-settings-env-passthrough',
    name: 'Environment Variable Passthrough',
    description: 'Claude settings configured to pass environment variables to MCP servers',
    category: 'exfiltration',
    pattern: /["']?env["']?\s*:\s*\{[\s\S]*?["']?(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|PRIVATE_KEY)["']?\s*:/i,
    severity: 'high',
    mitre: ['T1552', 'T1567'],
    remediation: 'Review environment variable passthrough in Claude settings. Avoid passing sensitive credentials to MCP servers.',
  },
  {
    id: 'claude-md-scope-escalation',
    name: 'Scope Escalation in CLAUDE.md',
    description: 'CLAUDE.md instructions directing the agent to operate outside the project',
    category: 'privilege_escalation',
    pattern: /(?:access|read|write|modify|scan|check)\s+(?:files?\s+)?(?:in|from|at|on)\s+(?:\/(?:etc|usr|var|home|root|tmp|sys|proc)|~\/|\.\.\/\.\.\/|%(?:APPDATA|USERPROFILE|HOME)%|(?:C|D):\\)/i,
    severity: 'critical',
    mitre: ['T1083', 'T1059'],
    remediation: 'Remove instructions that direct Claude to access files outside the project directory. The agent should stay within the workspace.',
  },
  {
    id: 'claude-settings-permissions-all',
    name: 'All Permissions Granted',
    description: 'Claude settings with all permission categories enabled',
    category: 'config_override',
    pattern: /["']?(?:permissions|capabilities)["']?\s*:\s*(?:\[\s*["']all["']\s*\]|["']all["'])/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Do not grant all permissions. Use the principle of least privilege and only enable permissions required for the project.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Claude configuration files.
 * Combines generic injection patterns with Claude-specific patterns.
 */
const CLAUDE_PATTERNS: readonly InjectionPattern[] = [
  ...ALL_PATTERNS,
  ...CLAUDE_SPECIFIC_PATTERNS,
];

/**
 * Scan file content against all Claude-applicable injection patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanClaudeContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of CLAUDE_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Claude Config] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'claude-settings',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Claude Config] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'claude-settings',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

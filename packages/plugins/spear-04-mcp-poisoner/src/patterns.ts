/**
 * MCP Injection Pattern Database
 *
 * Contains 20+ tool description injection patterns organized by attack
 * category. Each pattern describes a known technique for poisoning MCP
 * tool descriptions to trick AI agents into performing unintended actions.
 *
 * Categories:
 *   - data_exfil    -- Instructions to exfiltrate data to external URLs
 *   - priv_esc      -- Instructions to read sensitive files or escalate access
 *   - cross_tool    -- Instructions to invoke other MCP tools or plugins
 *   - rug_pull      -- Indicators of post-approval tool redefinition
 *   - hidden_inject -- Invisible characters and steganographic payloads
 *
 * MITRE ATT&CK Mappings:
 *   - T1059   Command and Scripting Interpreter
 *   - T1005   Data from Local System
 *   - T1071   Application Layer Protocol (C2 via HTTP)
 *   - T1041   Exfiltration Over C2 Channel
 *   - T1027   Obfuscated Files or Information
 *   - T1204   User Execution (social engineering via tool desc)
 *   - T1562   Impair Defenses
 *   - T1547   Boot or Logon Autostart Execution
 *
 * Reference: CVE-2025-54135 -- MCP Tool Description Injection
 */

// ─── Types ───────────────────────────────────────────────────

/** Attack category for classification */
export type InjectionCategory =
  | 'data_exfil'
  | 'priv_esc'
  | 'cross_tool'
  | 'rug_pull'
  | 'hidden_inject';

/** A single injection pattern definition */
export interface InjectionPattern {
  /** Unique identifier for this pattern */
  id: string;
  /** Attack category */
  category: InjectionCategory;
  /** Human-readable description of the attack */
  description: string;
  /** The payload string or regex pattern to detect */
  payload: string;
  /** Whether the payload is a regex (true) or a literal substring (false) */
  isRegex: boolean;
  /** MITRE ATT&CK technique IDs */
  mitreTechniques: string[];
  /** CVE references */
  cveReferences: string[];
  /** Severity of this specific pattern */
  severity: 'critical' | 'high' | 'medium' | 'low';
}

// ─── Pattern Definitions ─────────────────────────────────────

/**
 * Data Exfiltration patterns -- Instructions embedded in tool descriptions
 * that direct AI agents to send data to attacker-controlled endpoints.
 */
const DATA_EXFIL_PATTERNS: InjectionPattern[] = [
  {
    id: 'MCP-INJ-001',
    category: 'data_exfil',
    description: 'HTTP exfiltration via fetch/curl instruction in tool description',
    payload: '(?:fetch|curl|wget|http\\.get|axios|request)\\s*\\(?\\s*["\']https?://[^"\'\\s]+',
    isRegex: true,
    mitreTechniques: ['T1041', 'T1071'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-002',
    category: 'data_exfil',
    description: 'Instruction to send environment variables to external URL',
    payload: '(?:send|post|transmit|forward|exfiltrate).*(?:env|environment|secret|token|key|password|credential).*(?:to|http|url|endpoint)',
    isRegex: true,
    mitreTechniques: ['T1041', 'T1005'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-003',
    category: 'data_exfil',
    description: 'Base64 encoding instruction for data exfiltration obfuscation',
    payload: '(?:base64|btoa|encode).*(?:send|post|fetch|curl|http)',
    isRegex: true,
    mitreTechniques: ['T1041', 'T1027'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-004',
    category: 'data_exfil',
    description: 'DNS exfiltration via subdomain encoding instruction',
    payload: '(?:dns|nslookup|dig|resolve).*(?:subdomain|query|lookup)',
    isRegex: true,
    mitreTechniques: ['T1041', 'T1071'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-005',
    category: 'data_exfil',
    description: 'Webhook or callback URL for data exfiltration',
    payload: '(?:webhook|callback|notify|ping).*https?://[^\\s"\']+',
    isRegex: true,
    mitreTechniques: ['T1041', 'T1071'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
];

/**
 * Privilege Escalation patterns -- Instructions that direct AI agents
 * to read sensitive system files or escalate access beyond the tool's
 * intended scope.
 */
const PRIV_ESC_PATTERNS: InjectionPattern[] = [
  {
    id: 'MCP-INJ-006',
    category: 'priv_esc',
    description: 'Instruction to read SSH keys or credential files',
    payload: '(?:read|cat|open|access|get).*(?:\\.ssh|id_rsa|id_ed25519|authorized_keys|known_hosts)',
    isRegex: true,
    mitreTechniques: ['T1005', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-007',
    category: 'priv_esc',
    description: 'Instruction to read environment files or dotenv',
    payload: '(?:read|cat|open|access|load|parse).*(?:\\.env|\\.env\\.local|\\.env\\.production|dotenv)',
    isRegex: true,
    mitreTechniques: ['T1005', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-008',
    category: 'priv_esc',
    description: 'Instruction to access system password or shadow files',
    payload: '(?:read|cat|open|access).*(?:/etc/passwd|/etc/shadow|/etc/sudoers|/etc/hosts)',
    isRegex: true,
    mitreTechniques: ['T1005', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-009',
    category: 'priv_esc',
    description: 'Instruction to execute arbitrary shell commands',
    payload: '(?:exec|execute|run|spawn|shell|system|eval|child_process)\\s*\\(?\\s*["\']',
    isRegex: true,
    mitreTechniques: ['T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-010',
    category: 'priv_esc',
    description: 'Instruction to access cloud provider metadata endpoints',
    payload: '(?:169\\.254\\.169\\.254|metadata\\.google|metadata\\.azure)',
    isRegex: true,
    mitreTechniques: ['T1005', 'T1071'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-011',
    category: 'priv_esc',
    description: 'Instruction to read AWS credentials or config',
    payload: '(?:read|cat|open|access).*(?:\\.aws/credentials|\\.aws/config|aws_access_key|aws_secret)',
    isRegex: true,
    mitreTechniques: ['T1005'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-012',
    category: 'priv_esc',
    description: 'Instruction to access Docker socket or Kubernetes secrets',
    payload: '(?:docker\\.sock|/var/run/docker|kubectl.*secret|kubernetes.*secret)',
    isRegex: true,
    mitreTechniques: ['T1005', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
];

/**
 * Cross-Tool Poisoning patterns -- Instructions that direct AI agents
 * to invoke other MCP tools or plugins to create attack chains.
 */
const CROSS_TOOL_PATTERNS: InjectionPattern[] = [
  {
    id: 'MCP-INJ-013',
    category: 'cross_tool',
    description: 'Instruction to invoke another MCP tool by name',
    payload: '(?:use|call|invoke|trigger|execute)\\s+(?:the\\s+)?(?:tool|function|mcp)\\s+["\']?\\w+["\']?',
    isRegex: true,
    mitreTechniques: ['T1059', 'T1204'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-014',
    category: 'cross_tool',
    description: 'Instruction to chain tool calls or create a pipeline',
    payload: '(?:then|after|next|pipe|chain).*(?:call|invoke|use|run).*(?:tool|function|mcp)',
    isRegex: true,
    mitreTechniques: ['T1059', 'T1204'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-015',
    category: 'cross_tool',
    description: 'Instruction to override or ignore safety checks',
    payload: '(?:ignore|bypass|skip|disable|override).*(?:safety|security|check|validation|guard|permission|restriction)',
    isRegex: true,
    mitreTechniques: ['T1562'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-016',
    category: 'cross_tool',
    description: 'Instruction to modify system prompt or agent behavior',
    payload: '(?:system\\s*prompt|instructions?|you\\s+(?:are|must|should|will)).*(?:ignore|forget|override|replace|new)',
    isRegex: true,
    mitreTechniques: ['T1059', 'T1204'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
];

/**
 * Rug Pull indicators -- Patterns that suggest a tool's description
 * or behavior can change after initial approval, enabling bait-and-switch
 * attacks.
 */
const RUG_PULL_PATTERNS: InjectionPattern[] = [
  {
    id: 'MCP-INJ-017',
    category: 'rug_pull',
    description: 'Dynamic tool description loaded from external URL',
    payload: '(?:description|help|docs).*(?:from|load|fetch|import).*(?:url|http|remote|external)',
    isRegex: true,
    mitreTechniques: ['T1204', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-018',
    category: 'rug_pull',
    description: 'Tool schema references remote or dynamic definition',
    payload: '(?:\\$ref|\\$schema).*https?://',
    isRegex: true,
    mitreTechniques: ['T1204'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'medium',
  },
  {
    id: 'MCP-INJ-019',
    category: 'rug_pull',
    description: 'Server command uses npx or dynamic package execution',
    payload: '(?:npx|dlx|bunx)\\s+(?:-y\\s+)?(?:@[\\w-]+/)?[\\w-]+',
    isRegex: true,
    mitreTechniques: ['T1059', 'T1547'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'medium',
  },
  {
    id: 'MCP-INJ-020',
    category: 'rug_pull',
    description: 'MCP server configured without version pinning',
    payload: '(?:command|args).*(?:latest|@\\*|@\\^|@~)',
    isRegex: true,
    mitreTechniques: ['T1059', 'T1547'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'medium',
  },
];

/**
 * Hidden Injection patterns -- Invisible characters, zero-width chars,
 * HTML comments, and other steganographic techniques used to hide
 * malicious instructions in tool descriptions.
 */
const HIDDEN_INJECT_PATTERNS: InjectionPattern[] = [
  {
    id: 'MCP-INJ-021',
    category: 'hidden_inject',
    description: 'Zero-width characters used to hide instructions',
    payload: '[\\u200B\\u200C\\u200D\\u200E\\u200F\\uFEFF\\u2060\\u2061\\u2062\\u2063\\u2064]',
    isRegex: true,
    mitreTechniques: ['T1027'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-022',
    category: 'hidden_inject',
    description: 'HTML comment containing hidden instructions',
    payload: '<!--[\\s\\S]*?(?:exec|system|fetch|curl|read|send|ignore|override)[\\s\\S]*?-->',
    isRegex: true,
    mitreTechniques: ['T1027', 'T1059'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
  {
    id: 'MCP-INJ-023',
    category: 'hidden_inject',
    description: 'Unicode bidirectional override characters for text confusion',
    payload: '[\\u202A\\u202B\\u202C\\u202D\\u202E\\u2066\\u2067\\u2068\\u2069]',
    isRegex: true,
    mitreTechniques: ['T1027'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-024',
    category: 'hidden_inject',
    description: 'Homoglyph characters used to disguise malicious URLs or instructions',
    payload: '[\\u0410-\\u044F].*(?:https?://|exec|system|eval)',
    isRegex: true,
    mitreTechniques: ['T1027'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'high',
  },
  {
    id: 'MCP-INJ-025',
    category: 'hidden_inject',
    description: 'Tag-style markers used to delimit injected instructions',
    payload: '<(?:system|instruction|prompt|hidden|secret)>[\\s\\S]*?</(?:system|instruction|prompt|hidden|secret)>',
    isRegex: true,
    mitreTechniques: ['T1027', 'T1204'],
    cveReferences: ['CVE-2025-54135'],
    severity: 'critical',
  },
];

// ─── Aggregated Pattern Database ─────────────────────────────

/** All injection patterns, combined from all categories */
export const INJECTION_PATTERNS: readonly InjectionPattern[] = [
  ...DATA_EXFIL_PATTERNS,
  ...PRIV_ESC_PATTERNS,
  ...CROSS_TOOL_PATTERNS,
  ...RUG_PULL_PATTERNS,
  ...HIDDEN_INJECT_PATTERNS,
];

/**
 * Get patterns filtered by category.
 *
 * @param category - The category to filter by.
 * @returns Array of patterns in the specified category.
 */
export function getPatternsByCategory(category: InjectionCategory): InjectionPattern[] {
  return INJECTION_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get a pattern by its unique ID.
 *
 * @param id - The pattern ID (e.g., 'MCP-INJ-001').
 * @returns The matching pattern, or undefined if not found.
 */
export function getPatternById(id: string): InjectionPattern | undefined {
  return INJECTION_PATTERNS.find((p) => p.id === id);
}

// ─── MCP Config File Locations ───────────────────────────────

/**
 * Known MCP configuration file paths to scan for, relative to project root.
 *
 * Different AI coding tools use different config file locations:
 *   - Claude Code: mcp.json, .mcp/settings.json
 *   - Cursor: .cursor/mcp.json
 *   - Cline: cline_mcp_settings.json
 *   - VS Code: .vscode/mcp.json
 *   - Windsurf: .windsurf/mcp.json
 *   - Global configs: ~/.config/... (checked if fs:read-global is permitted)
 */
export const MCP_CONFIG_FILES: readonly string[] = [
  // Project-level configs
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

  // Claude-specific
  'claude_desktop_config.json',
  '.claude/settings.json',
];

/**
 * Global MCP config file paths (requires fs:read-global permission).
 * These are outside the project directory.
 */
export const MCP_GLOBAL_CONFIG_FILES: readonly string[] = [
  // macOS
  '~/Library/Application Support/Claude/claude_desktop_config.json',
  '~/Library/Application Support/Cursor/User/globalStorage/mcp.json',
  // Linux
  '~/.config/claude/claude_desktop_config.json',
  '~/.config/Code/User/globalStorage/mcp.json',
  // Windows (resolved at runtime)
  '%APPDATA%/Claude/claude_desktop_config.json',
  '%APPDATA%/Code/User/globalStorage/mcp.json',
];

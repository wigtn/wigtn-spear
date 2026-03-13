/**
 * SPEAR-15: IDE Extension Auditor -- Pattern Definitions
 *
 * Defines 22 detection patterns across five categories:
 *
 *   - excessive_permission  -- Extensions requesting overly broad permissions
 *   - network_access        -- Extensions with suspicious network capabilities
 *   - filesystem_access     -- Extensions with broad filesystem access
 *   - code_execution        -- Extensions capable of arbitrary code execution
 *   - data_exfiltration     -- Extensions that may exfiltrate workspace data
 *
 * Each pattern includes MITRE ATT&CK mappings for enterprise threat classification.
 *
 * MITRE references used:
 *   T1059     -- Command and Scripting Interpreter
 *   T1071     -- Application Layer Protocol
 *   T1195.002 -- Compromise Software Supply Chain
 *   T1552     -- Unsecured Credentials
 *   T1567     -- Exfiltration Over Web Service
 *   T1562     -- Impair Defenses
 *   T1083     -- File and Directory Discovery
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type IdeCategory =
  | 'excessive_permission'
  | 'network_access'
  | 'filesystem_access'
  | 'code_execution'
  | 'data_exfiltration';

export interface IdePattern {
  id: string;
  name: string;
  description: string;
  category: IdeCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
  /** Which file types this pattern applies to: vscode, jetbrains, or all */
  appliesTo: ('vscode' | 'jetbrains')[];
}

// ─── Excessive Permission Patterns ─────────────────────────────

const excessivePermissionPatterns: IdePattern[] = [
  {
    id: 'ide-perm-all-commands',
    name: 'All Commands Permission',
    description: 'Extension requests permission to execute any VS Code command',
    category: 'excessive_permission',
    pattern: /["']?\*["']?\s*(?:in|of)\s*["']?commands["']?|["']commands["']?\s*:\s*["']\*["']/i,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Restrict command permissions to only the specific commands needed by the extension.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-perm-workspace-trust',
    name: 'Workspace Trust Override',
    description: 'Extension runs in untrusted workspaces with full capabilities',
    category: 'excessive_permission',
    pattern: /["']?untrustedWorkspaces["']?\s*:\s*\{[\s\S]*?["']?supported["']?\s*:\s*(?:true|["']true["'])/i,
    severity: 'high',
    mitre: ['T1562'],
    remediation: 'Set untrustedWorkspaces.supported to false or "limited" unless the extension genuinely needs to run in untrusted contexts.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-perm-star-activation',
    name: 'Star Activation Event',
    description: 'Extension activates on every event using the * wildcard',
    category: 'excessive_permission',
    pattern: /["']?activationEvents["']?\s*:\s*\[\s*["']\*["']\s*\]/i,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Use specific activation events instead of *. Extensions should only activate when needed.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-perm-file-system-all',
    name: 'Full Filesystem Permission',
    description: 'Extension requests access to the entire filesystem',
    category: 'excessive_permission',
    pattern: /["']?(?:permissions|extensionPermissions)["']?\s*:\s*\[[\s\S]*?["']?(?:file-system|filesystem|fs)\s*:\s*(?:\*|all|read-write)["']?/i,
    severity: 'critical',
    mitre: ['T1083'],
    remediation: 'Request filesystem access only for specific paths needed by the extension.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-perm-jetbrains-all',
    name: 'JetBrains All Permissions',
    description: 'JetBrains plugin requests all IDE permissions',
    category: 'excessive_permission',
    pattern: /<(?:depends|requires)>\s*com\.intellij\.modules\.all\s*<\/(?:depends|requires)>/i,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Request only specific module dependencies instead of com.intellij.modules.all.',
    appliesTo: ['jetbrains'],
  },
];

// ─── Network Access Patterns ───────────────────────────────────

const networkAccessPatterns: IdePattern[] = [
  {
    id: 'ide-net-outbound-request',
    name: 'Outbound HTTP Request in Extension',
    description: 'Extension makes HTTP requests to external servers',
    category: 'network_access',
    pattern: /(?:https?\.(?:get|request)|fetch\s*\(|axios\.|got\s*\(|node-fetch|XMLHttpRequest)\s*\(?['"`]https?:\/\/(?!(?:localhost|127\.0\.0\.1|marketplace\.visualstudio\.com|update\.code\.visualstudio\.com))/i,
    severity: 'medium',
    mitre: ['T1071'],
    remediation: 'Audit all outbound network requests. Extensions should only communicate with documented, trusted endpoints.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-net-telemetry-endpoint',
    name: 'Custom Telemetry Endpoint',
    description: 'Extension sends telemetry to non-Microsoft endpoints',
    category: 'network_access',
    pattern: /(?:telemetry|analytics|tracking|metrics)\s*(?:url|endpoint|host|server)\s*[=:]\s*['"`]https?:\/\/(?!(?:dc\.services\.visualstudio\.com|vortex\.data\.microsoft\.com))/i,
    severity: 'high',
    mitre: ['T1071', 'T1567'],
    remediation: 'Use VS Code built-in telemetry APIs. Remove custom telemetry endpoints.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-net-websocket',
    name: 'WebSocket Connection in Extension',
    description: 'Extension establishes WebSocket connections to external servers',
    category: 'network_access',
    pattern: /(?:new\s+WebSocket|ws:\/\/|wss:\/\/)\s*\(?['"`]wss?:\/\/(?!localhost)/i,
    severity: 'medium',
    mitre: ['T1071'],
    remediation: 'Audit WebSocket connections. Document why persistent connections are needed.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-net-download-exec',
    name: 'Download and Execute Pattern',
    description: 'Extension downloads and executes remote code',
    category: 'network_access',
    pattern: /(?:download|fetch|get)\s*\([\s\S]{1,100}(?:exec|spawn|fork|eval|Function\s*\()/i,
    severity: 'critical',
    mitre: ['T1059', 'T1195.002'],
    remediation: 'Never download and execute remote code. Bundle all executable code with the extension.',
    appliesTo: ['vscode', 'jetbrains'],
  },
];

// ─── Filesystem Access Patterns ────────────────────────────────

const filesystemAccessPatterns: IdePattern[] = [
  {
    id: 'ide-fs-read-ssh-keys',
    name: 'SSH Key File Access',
    description: 'Extension reads SSH key files from user home directory',
    category: 'filesystem_access',
    pattern: /(?:readFile|readFileSync|readdir|open)\s*\([\s\S]*?(?:\.ssh|id_rsa|id_ed25519|known_hosts)/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Extensions should never access SSH keys. Use VS Code SSH extension APIs if SSH functionality is needed.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-fs-read-credentials',
    name: 'Credential File Access',
    description: 'Extension reads credential or configuration files',
    category: 'filesystem_access',
    pattern: /(?:readFile|readFileSync|open)\s*\([\s\S]*?(?:\.aws\/credentials|\.npmrc|\.netrc|\.docker\/config|\.kube\/config|\.gitconfig)/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Extensions should not read credential files. Use proper credential store APIs.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-fs-global-read',
    name: 'Global Filesystem Read',
    description: 'Extension reads files outside the workspace directory',
    category: 'filesystem_access',
    pattern: /(?:readFile|readFileSync|readdir)\s*\([\s\S]*?(?:\/etc\/|\/usr\/|\/var\/|\/home\/|\/root\/|%APPDATA%|%USERPROFILE%)/i,
    severity: 'high',
    mitre: ['T1083'],
    remediation: 'Restrict file access to the workspace directory. Use vscode.workspace.fs for workspace-scoped access.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-fs-write-outside-workspace',
    name: 'Write Outside Workspace',
    description: 'Extension writes files outside the workspace directory',
    category: 'filesystem_access',
    pattern: /(?:writeFile|writeFileSync|appendFile)\s*\([\s\S]*?(?:\/tmp\/|\/etc\/|~\/|\/home\/|\/root\/|%TEMP%|%APPDATA%)/i,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Extensions should only write to the workspace or extension storage directories.',
    appliesTo: ['vscode', 'jetbrains'],
  },
];

// ─── Code Execution Patterns ───────────────────────────────────

const codeExecutionPatterns: IdePattern[] = [
  {
    id: 'ide-exec-child-process',
    name: 'Child Process Execution',
    description: 'Extension spawns child processes for arbitrary command execution',
    category: 'code_execution',
    pattern: /(?:child_process|exec|execSync|spawn|spawnSync|fork)\s*\(\s*(?:['"`](?:sh|bash|cmd|powershell|pwsh)|(?:command|cmd|shell)\b)/i,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Minimize child process usage. When necessary, use specific executables with argument arrays, never shell execution.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-exec-eval',
    name: 'Dynamic Code Evaluation',
    description: 'Extension uses eval or Function constructor for dynamic code execution',
    category: 'code_execution',
    pattern: /(?:eval\s*\(|new\s+Function\s*\(|vm\.runIn(?:NewContext|ThisContext|Context)\s*\()/i,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Remove eval/Function constructor usage. Use safe alternatives for dynamic behavior.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-exec-postinstall',
    name: 'Post-Install Script Execution',
    description: 'Extension package.json contains postinstall scripts that execute arbitrary code',
    category: 'code_execution',
    pattern: /["']?(?:postinstall|preinstall|install)["']?\s*:\s*["'][^"']*(?:node|sh|bash|cmd|powershell|curl|wget)/i,
    severity: 'high',
    mitre: ['T1059', 'T1195.002'],
    remediation: 'Remove install scripts that execute arbitrary commands. Use activation events for setup logic.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-exec-runtime-require',
    name: 'Dynamic Module Loading',
    description: 'Extension dynamically loads modules at runtime from untrusted paths',
    category: 'code_execution',
    pattern: /(?:require|import)\s*\(\s*(?:path\.join|`|['"`]\s*\+\s*(?:var|let|const|input|user|param))/i,
    severity: 'medium',
    mitre: ['T1059', 'T1195.002'],
    remediation: 'Use static imports only. Dynamic module loading from variable paths enables code injection.',
    appliesTo: ['vscode', 'jetbrains'],
  },
];

// ─── Data Exfiltration Patterns ────────────────────────────────

const dataExfiltrationPatterns: IdePattern[] = [
  {
    id: 'ide-exfil-workspace-content',
    name: 'Workspace Content Exfiltration',
    description: 'Extension reads workspace files and sends data to external server',
    category: 'data_exfiltration',
    pattern: /(?:readFile|readFileSync|workspace\.fs\.readFile)[\s\S]{1,300}(?:fetch|axios|http\.request|post|send)/i,
    severity: 'critical',
    mitre: ['T1567'],
    remediation: 'Audit data flow from file reads to network requests. Never send workspace content to external servers.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-exfil-clipboard-send',
    name: 'Clipboard Data Exfiltration',
    description: 'Extension reads clipboard and transmits content',
    category: 'data_exfiltration',
    pattern: /(?:clipboard\.readText|env\.clipboard\.readText|getSystemClipboard)[\s\S]{1,200}(?:fetch|axios|http|post|send|request)/i,
    severity: 'high',
    mitre: ['T1567'],
    remediation: 'Do not read and transmit clipboard contents. Clipboard access should be user-initiated only.',
    appliesTo: ['vscode', 'jetbrains'],
  },
  {
    id: 'ide-exfil-git-credentials',
    name: 'Git Credential Exfiltration',
    description: 'Extension accesses git credentials or tokens',
    category: 'data_exfiltration',
    pattern: /(?:git\.(?:credential|getSession)|authentication\.getSession|credentials\.get)[\s\S]{1,200}(?:fetch|axios|http|post|send)/i,
    severity: 'critical',
    mitre: ['T1552', 'T1567'],
    remediation: 'Do not extract and transmit git credentials. Use proper authentication APIs.',
    appliesTo: ['vscode'],
  },
  {
    id: 'ide-exfil-extension-data',
    name: 'Extension State Exfiltration',
    description: 'Extension reads other extensions data or global state for exfiltration',
    category: 'data_exfiltration',
    pattern: /(?:globalState\.get|workspaceState\.get|extensions\.getExtension)[\s\S]{1,200}(?:fetch|axios|http|post|send|request)/i,
    severity: 'high',
    mitre: ['T1567'],
    remediation: 'Extensions should not read and transmit other extensions state data.',
    appliesTo: ['vscode'],
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 22 IDE extension security detection patterns.
 */
export const ALL_IDE_PATTERNS: readonly IdePattern[] = [
  ...excessivePermissionPatterns,
  ...networkAccessPatterns,
  ...filesystemAccessPatterns,
  ...codeExecutionPatterns,
  ...dataExfiltrationPatterns,
];

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: IdeCategory): IdePattern[] {
  return ALL_IDE_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns applicable to a specific IDE platform.
 */
export function getPatternsForPlatform(platform: 'vscode' | 'jetbrains'): IdePattern[] {
  return ALL_IDE_PATTERNS.filter((p) => p.appliesTo.includes(platform));
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<IdeCategory, number> {
  const counts: Record<IdeCategory, number> = {
    excessive_permission: 0,
    network_access: 0,
    filesystem_access: 0,
    code_execution: 0,
    data_exfiltration: 0,
  };

  for (const p of ALL_IDE_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}

/**
 * SPEAR-10: Generic AI Agent Configuration Scanner
 *
 * Scans generic AI agent instruction files for injection patterns:
 *   - .github/copilot-instructions.md  -- GitHub Copilot instructions
 *   - AGENTS.md                         -- Generic agent instructions
 *   - .aider*                           -- Aider AI config files
 *   - codex.md                          -- OpenAI Codex instructions
 *   - .continue/*                       -- Continue.dev config
 *   - .codeium/*                        -- Codeium config
 *   - .tabby/*                          -- TabbyML config
 *   - copilot-instructions.md           -- Copilot instructions (any location)
 *
 * These files configure various AI coding assistants. They are all
 * vulnerable to the same class of injection attacks because they
 * accept natural language instructions that the AI follows.
 *
 * This scanner checks for 10+ dangerous patterns common across all
 * AI agent instruction formats.
 */

import type { Finding } from '@wigtn/shared';
import type { InjectionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Generic Agent File Patterns ───────────────────────────────

/** Filenames that are generic AI agent configuration files. */
export const GENERIC_AGENT_FILES: readonly string[] = [
  'AGENTS.md',
  'agents.md',
  'codex.md',
  'CODEX.md',
];

/** File patterns (basename matches) for AI agent configs. */
export const GENERIC_AGENT_BASENAMES: readonly string[] = [
  'copilot-instructions.md',
];

/** Path prefixes for AI agent config directories. */
export const GENERIC_AGENT_DIR_PREFIXES: readonly string[] = [
  '.github/copilot-instructions.md',
  '.github/',
  '.aider',
  '.continue/',
  '.codeium/',
  '.tabby/',
];

/**
 * Check if a relative file path is a generic AI agent configuration file.
 */
export function isGenericAgentFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Direct file matches
  if (GENERIC_AGENT_FILES.includes(filename)) {
    return true;
  }

  // Basename matches
  if (GENERIC_AGENT_BASENAMES.includes(filename.toLowerCase())) {
    return true;
  }

  // Copilot instructions in .github
  if (normalized === '.github/copilot-instructions.md') {
    return true;
  }

  // Aider files (.aider, .aider.conf, .aider.model.settings.yml, etc.)
  if (filename.startsWith('.aider')) {
    return true;
  }

  // Files within AI agent config directories
  for (const prefix of GENERIC_AGENT_DIR_PREFIXES) {
    if (normalized.startsWith(prefix) && normalized.endsWith('.md')) {
      return true;
    }
  }

  // Continue.dev config
  if (normalized.startsWith('.continue/') && (
    normalized.endsWith('.json') || normalized.endsWith('.md') || normalized.endsWith('.yaml')
  )) {
    return true;
  }

  return false;
}

// ─── Generic Agent-Specific Patterns ───────────────────────────

/**
 * Additional patterns specifically targeting generic AI agent config abuse.
 */
export const GENERIC_AGENT_PATTERNS: readonly InjectionPattern[] = [
  {
    id: 'agent-generic-force-include',
    name: 'Forced Code Include',
    description: 'Instruction to always include specific imports or code blocks in generated code',
    category: 'stealth_injection',
    pattern: /(?:always|must|shall|every\s+(?:time|file))\s+(?:include|add|import|require|prepend|inject)\s+(?:this|the\s+following|these)\s+(?:in\s+)?(?:every|all|each)\s+(?:file|module|component|response)/i,
    severity: 'high',
    mitre: ['T1059', 'T1505.003'],
    remediation: 'Remove forced code inclusion instructions. AI agents should not be instructed to blindly add code to every file.',
  },
  {
    id: 'agent-generic-no-review',
    name: 'Review Bypass Instruction',
    description: 'Instruction to skip code review, testing, or validation steps',
    category: 'privilege_escalation',
    pattern: /(?:do\s+not|don'?t|never|skip|bypass|avoid)\s+(?:ask\s+for\s+)?(?:review|approval|confirmation|test|validate|verify|check|lint|audit)\s+(?:the\s+)?(?:code|changes?|output|generated|modifications?)/i,
    severity: 'high',
    mitre: ['T1562'],
    remediation: 'Remove review bypass instructions. All generated code should be subject to review and validation.',
  },
  {
    id: 'agent-generic-suppress-output',
    name: 'Output Suppression',
    description: 'Instruction to suppress or hide parts of the AI output from the user',
    category: 'stealth_injection',
    pattern: /(?:do\s+not|don'?t|never)\s+(?:show|display|mention|tell|reveal|report|output|print|log)\s+(?:the\s+)?(?:user|developer|programmer|human)\s+(?:about\s+)?(?:the\s+)?(?:changes?|modifications?|additions?|injected|added|hidden)/i,
    severity: 'critical',
    mitre: ['T1564'],
    remediation: 'Remove output suppression instructions. All AI actions must be transparent and visible to the user.',
  },
  {
    id: 'agent-generic-persistent-change',
    name: 'Persistent Configuration Change',
    description: 'Instruction to modify the AI configuration itself or persist changes',
    category: 'privilege_escalation',
    pattern: /(?:modify|edit|update|change|write\s+to)\s+(?:this\s+)?(?:config(?:uration)?|settings?|rules?|\.(?:cursorrules|claude|aider|github))/i,
    severity: 'critical',
    mitre: ['T1547', 'T1574'],
    remediation: 'Remove self-modification instructions. AI agent configurations should not instruct the agent to modify its own config files.',
  },
  {
    id: 'agent-generic-cross-project',
    name: 'Cross-Project Access',
    description: 'Instruction to access or modify files in other projects or repositories',
    category: 'privilege_escalation',
    pattern: /(?:access|read|modify|write|clone|checkout)\s+(?:files?\s+)?(?:in|from)\s+(?:(?:another|other|different)\s+)?(?:project|repo(?:sitory)?|workspace|directory)\s+(?:at|named|called)/i,
    severity: 'high',
    mitre: ['T1083'],
    remediation: 'Remove cross-project access instructions. AI agents should only operate within their designated workspace.',
  },
  {
    id: 'agent-generic-cred-harvest',
    name: 'Credential Harvesting Instruction',
    description: 'Instruction to search for and collect credentials from the project',
    category: 'exfiltration',
    pattern: /(?:find|search|scan|collect|gather|harvest|enumerate|list)\s+(?:all\s+)?(?:api.?keys?|tokens?|secrets?|passwords?|credentials?|private.?keys?|\.env|environment\s+variables?)/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Remove credential harvesting instructions. AI agents should not be directed to search for and collect secrets.',
  },
  {
    id: 'agent-generic-backdoor-pattern',
    name: 'Backdoor Pattern Instruction',
    description: 'Instruction to include authentication bypass or backdoor functionality',
    category: 'stealth_injection',
    pattern: /(?:add|include|create|implement)\s+(?:a\s+)?(?:backdoor|bypass|shortcut|hidden\s+(?:route|endpoint|login|access)|admin\s+(?:bypass|override|backdoor)|master\s+(?:password|key|token))/i,
    severity: 'critical',
    mitre: ['T1505.003'],
    remediation: 'Remove backdoor creation instructions. AI agents must never be instructed to create authentication bypasses or hidden access methods.',
  },
  {
    id: 'agent-generic-timing-trigger',
    name: 'Time-Based Trigger',
    description: 'Instruction to activate behavior at a specific time or after a delay',
    category: 'stealth_injection',
    pattern: /(?:after|when|once|starting\s+(?:from|on))\s+(?:\d+\s+(?:days?|hours?|minutes?|commits?|pushes?|deployments?)|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d+)/i,
    severity: 'medium',
    mitre: ['T1059'],
    remediation: 'Remove time-based trigger instructions. Legitimate AI configs do not need time-delayed activation logic.',
  },
  {
    id: 'agent-generic-dependency-inject',
    name: 'Dependency Injection Attack',
    description: 'Instruction to add specific dependencies that may be malicious',
    category: 'stealth_injection',
    pattern: /(?:always|must|shall)\s+(?:add|install|include)\s+(?:the\s+)?(?:package|dependency|module|library)\s+['"`]?[a-z0-9]+-[a-z0-9]+-[a-z0-9]+/i,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Review forced dependency instructions. Mandatory package installation can introduce supply chain attacks through typosquatting or malicious packages.',
  },
  {
    id: 'agent-generic-error-suppress',
    name: 'Error Suppression Instruction',
    description: 'Instruction to catch and suppress all errors silently',
    category: 'privilege_escalation',
    pattern: /(?:always|must|shall)\s+(?:wrap|surround|catch)\s+(?:all\s+)?(?:errors?|exceptions?)\s+(?:in\s+)?(?:(?:try\s*[-/]?\s*catch|empty\s+catch|silent(?:ly)?)|and\s+(?:ignore|suppress|swallow|discard))/i,
    severity: 'medium',
    mitre: ['T1562'],
    remediation: 'Remove blanket error suppression instructions. Silencing all errors can mask security issues and runtime failures.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to generic AI agent config files.
 * Combines generic injection patterns with agent-specific patterns.
 */
const ALL_AGENT_PATTERNS: readonly InjectionPattern[] = [
  ...ALL_PATTERNS,
  ...GENERIC_AGENT_PATTERNS,
];

/**
 * Scan file content against all generic agent injection patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanGenericAgentContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of ALL_AGENT_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Agent Config] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'generic-agent',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Agent Config] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'generic-agent',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

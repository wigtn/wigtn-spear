/**
 * SPEAR-10: .cursorrules Scanner
 *
 * Scans Cursor AI agent configuration files for injection patterns:
 *   - .cursorrules     -- Main Cursor rules file
 *   - .cursorignore    -- Cursor ignore patterns (can hide malicious files)
 *   - .cursor/rules/*  -- Per-directory cursor rules
 *
 * Cursor rules files are plain text instructions that the Cursor AI IDE
 * follows when generating or modifying code. An attacker who can place
 * or modify these files can instruct the AI to:
 *   - Inject backdoors into generated code
 *   - Exfiltrate secrets via generated HTTP calls
 *   - Ignore security warnings in code reviews
 *   - Modify other project files silently
 *
 * This scanner checks for 15+ dangerous patterns specific to Cursor rules.
 */

import type { Finding } from '@wigtn/shared';
import type { InjectionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Cursor-Specific File Patterns ─────────────────────────────

/** Filenames and paths that are Cursor AI configuration files. */
export const CURSOR_FILE_PATTERNS: readonly string[] = [
  '.cursorrules',
  '.cursorignore',
];

/** Directory patterns for Cursor rules. */
export const CURSOR_DIR_PATTERNS: readonly string[] = [
  '.cursor/rules',
  '.cursor',
];

/**
 * Check if a relative file path is a Cursor configuration file.
 */
export function isCursorFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Direct file matches
  if (CURSOR_FILE_PATTERNS.includes(filename)) {
    return true;
  }

  // Files within .cursor/rules/ directory
  if (normalized.startsWith('.cursor/rules/') || normalized === '.cursor/rules') {
    return true;
  }

  return false;
}

// ─── Cursor-Specific Patterns ──────────────────────────────────

/**
 * Additional patterns specifically targeting Cursor rules abuse.
 * These supplement the generic patterns from patterns.ts.
 */
export const CURSOR_SPECIFIC_PATTERNS: readonly InjectionPattern[] = [
  {
    id: 'cursor-rules-code-inject',
    name: 'Code Injection via Cursor Rules',
    description: 'Instruction to always include specific code snippets that may contain backdoors',
    category: 'stealth_injection',
    pattern: /(?:always|must|shall)\s+(?:include|add|insert|inject|prepend|append)\s+(?:the\s+following\s+)?(?:code|snippet|import|require|script)/i,
    severity: 'high',
    mitre: ['T1059', 'T1505.003'],
    remediation: 'Review and remove forced code injection rules. Cursor rules should suggest patterns, not force specific code insertions.',
  },
  {
    id: 'cursor-rules-hide-code',
    name: 'Hidden Code Instruction',
    description: 'Instruction to add code without mentioning it or making it visible',
    category: 'stealth_injection',
    pattern: /(?:silently|quietly|without\s+(?:mentioning|telling|showing|displaying|asking)|do\s+not\s+(?:mention|show|display|tell|reveal))\s+(?:add|insert|include|modify|change|write)/i,
    severity: 'critical',
    mitre: ['T1564', 'T1059'],
    remediation: 'Remove stealth code modification instructions. All code changes by the AI must be visible and transparent to the user.',
  },
  {
    id: 'cursor-rules-disable-lint',
    name: 'Linting Disable Instruction',
    description: 'Instruction to add eslint-disable, tslint-disable, or similar suppress comments',
    category: 'privilege_escalation',
    pattern: /(?:add|include|insert|always\s+(?:use|add))\s+(?:\/[/*]\s*)?(?:eslint-disable|tslint:disable|@ts-(?:ignore|nocheck|expect-error)|noinspection|NOSONAR|nosec|#\s*noqa)/i,
    severity: 'medium',
    mitre: ['T1562'],
    remediation: 'Remove instructions that suppress linting or type checking. Security rules should not be bypassed in generated code.',
  },
  {
    id: 'cursor-rules-shadow-import',
    name: 'Shadow Import Instruction',
    description: 'Instruction to import from a suspicious or non-standard package',
    category: 'stealth_injection',
    pattern: /(?:always|must)\s+(?:import|require)\s+(?:from\s+)?['"`](?!(?:react|vue|angular|express|next|node:|@types|@testing-library))[a-z0-9]+-(?:helper|util|hook|lib|sdk)-[a-z0-9]+/i,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Review forced import instructions. Requiring imports from unknown packages can introduce supply chain attacks.',
  },
  {
    id: 'cursor-rules-api-key-embed',
    name: 'API Key Embedding Instruction',
    description: 'Instruction to embed API keys or secrets directly in code',
    category: 'exfiltration',
    pattern: /(?:use|embed|hardcode|include|set)\s+(?:this\s+)?(?:api.?key|token|secret|password|credential)\s*[:=]\s*['"`]/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Remove hardcoded credential instructions. API keys and secrets should use environment variables or secrets managers.',
  },
  {
    id: 'cursor-rules-test-skip',
    name: 'Test Skip Instruction',
    description: 'Instruction to skip or disable tests for security-related code',
    category: 'privilege_escalation',
    pattern: /(?:skip|disable|remove|don'?t\s+(?:write|add|include|run))\s+(?:all\s+)?(?:security\s+)?(?:tests?|specs?|assertions?|validations?)\s+(?:for|when|that|related)/i,
    severity: 'medium',
    mitre: ['T1562'],
    remediation: 'Remove test skip instructions. Security-related tests must not be disabled.',
  },
  {
    id: 'cursor-rules-obfuscate',
    name: 'Code Obfuscation Instruction',
    description: 'Instruction to obfuscate or minify generated code',
    category: 'stealth_injection',
    pattern: /(?:obfuscate|minify|uglify|compress|scramble|encrypt)\s+(?:the\s+)?(?:generated\s+)?(?:code|output|source)/i,
    severity: 'high',
    mitre: ['T1027'],
    remediation: 'Remove code obfuscation instructions. Generated code should be readable and auditable.',
  },
  {
    id: 'cursor-rules-network-call',
    name: 'Forced Network Call',
    description: 'Instruction to always include network calls in generated code',
    category: 'exfiltration',
    pattern: /(?:always|must|shall)\s+(?:add|include|make)\s+(?:a\s+)?(?:network\s+call|http\s+request|api\s+call|fetch\s+request)\s+to/i,
    severity: 'high',
    mitre: ['T1071', 'T1567'],
    remediation: 'Remove forced network call instructions. Generated code should not be forced to make external HTTP requests.',
  },
  {
    id: 'cursor-ignore-security-files',
    name: 'Security File Ignore',
    description: 'Cursorignore configured to hide security-relevant files from AI review',
    category: 'config_override',
    pattern: /(?:\.env|\.secret|security|auth|credential|password|token|key).*(?:ignore|exclude|skip)/i,
    severity: 'medium',
    mitre: ['T1562'],
    remediation: 'Review .cursorignore patterns that hide security-relevant files. Ensure the AI can still review authentication and authorization code.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Cursor configuration files.
 * Combines generic injection patterns with Cursor-specific patterns.
 */
const CURSOR_PATTERNS: readonly InjectionPattern[] = [
  ...ALL_PATTERNS,
  ...CURSOR_SPECIFIC_PATTERNS,
];

/**
 * Scan file content against all Cursor-applicable injection patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanCursorContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of CURSOR_PATTERNS) {
    // Test against full content first for multi-line patterns
    if (pattern.pattern.test(content)) {
      // Find the specific line(s) that match
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Cursor Config] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'cursorrules',
              patternName: pattern.name,
            },
          };
        }
      }

      // If the pattern matched full content but no individual line, report on line 1
      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Cursor Config] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'cursorrules',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

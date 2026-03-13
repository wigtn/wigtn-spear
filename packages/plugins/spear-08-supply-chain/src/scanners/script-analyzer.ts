/**
 * SPEAR-08: Package Scripts Analyzer
 *
 * Scans package.json scripts sections for supply chain attack indicators:
 *   - Dangerous postinstall/preinstall hooks
 *   - Shell command injection in scripts
 *   - Network access in build scripts
 *   - Obfuscated or hidden script references
 *
 * Focuses on the "scripts" field in package.json files, which is
 * the primary vector for npm supply chain attacks.
 */

import type { Finding } from '@wigtn/shared';
import type { SupplyChainPattern } from '../patterns.js';
import { ALL_PATTERNS, getPatternsByCategory } from '../patterns.js';

// ─── Script File Detection ─────────────────────────────────────

/** File names that contain package scripts. */
export const SCRIPT_FILE_PATTERNS: readonly string[] = [
  'package.json',
];

/**
 * Check if a file is a package manifest with scripts.
 */
export function isScriptFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  return SCRIPT_FILE_PATTERNS.includes(filename);
}

// ─── Script-Specific Patterns ─────────────────────────────────

/**
 * Additional patterns specifically targeting package.json scripts abuse.
 */
export const SCRIPT_SPECIFIC_PATTERNS: readonly SupplyChainPattern[] = [
  {
    id: 'sc-script-env-exfil',
    name: 'Script Environment Exfiltration',
    description: 'Build/test script sends environment data to external endpoint',
    category: 'postinstall_abuse',
    pattern: /["'](?:build|test|start|dev)["']\s*:\s*["'][^"']*(?:curl|wget|fetch)\s+[^"']*(?:\$\{?(?:NPM_TOKEN|NODE_AUTH_TOKEN|GH_TOKEN|GITHUB_TOKEN)|process\.env)/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Remove environment variable exfiltration from build scripts. Scripts should not send tokens to external services.',
  },
  {
    id: 'sc-script-rm-rf',
    name: 'Destructive Script Command',
    description: 'Script contains rm -rf or other destructive commands',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?(?:install|uninstall)["']\s*:\s*["'][^"']*rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(?:\/|~|\.\.)/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1485'],
    remediation: 'Remove destructive commands from install scripts. rm -rf with path traversal is a clear malicious indicator.',
  },
  {
    id: 'sc-script-multiple-chained',
    name: 'Suspiciously Chained Script Commands',
    description: 'Install script with many chained commands suggesting complex hidden behavior',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:&&|\|\||\;){4,}/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Review complex chained install scripts. Multiple chained commands may hide malicious steps.',
  },
  {
    id: 'sc-script-background-process',
    name: 'Background Process in Script',
    description: 'Install script launches background processes with &',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*\s+&\s*["']/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Remove background process launching from install scripts. Background processes persist after installation.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to package script analysis.
 */
const SCRIPT_PATTERNS: readonly SupplyChainPattern[] = [
  ...getPatternsByCategory('postinstall_abuse'),
  ...getPatternsByCategory('obfuscation'),
  ...SCRIPT_SPECIFIC_PATTERNS,
];

/**
 * Scan package.json content with focus on scripts section.
 */
export function* scanScriptContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of SCRIPT_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Supply Chain / Scripts] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'script-analyzer',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Supply Chain / Scripts] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'script-analyzer',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

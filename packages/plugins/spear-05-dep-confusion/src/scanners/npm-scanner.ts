/**
 * SPEAR-05: npm/yarn/pnpm Dependency Confusion Scanner
 *
 * Scans npm ecosystem manifest files for dependency confusion risks:
 *   - package.json          -- Main dependency manifest
 *   - package-lock.json     -- npm lockfile
 *   - yarn.lock             -- Yarn lockfile
 *   - pnpm-lock.yaml        -- pnpm lockfile
 *   - .npmrc                -- npm registry configuration
 *   - .yarnrc.yml           -- Yarn Berry config
 *   - .pnpmfile.cjs         -- pnpm hooks
 *
 * Checks include:
 *   - Unscoped internal-looking package names
 *   - Missing or misconfigured private registry settings
 *   - Dangerous version ranges
 *   - Install script abuse
 */

import type { Finding } from '@wigtn/shared';
import type { DepConfusionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── npm File Detection ────────────────────────────────────────

/** File names recognized as npm ecosystem files. */
export const NPM_FILE_PATTERNS: readonly string[] = [
  'package.json',
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  '.pnpmfile.cjs',
  'pnpm-workspace.yaml',
];

/**
 * Check if a file is an npm ecosystem configuration file.
 */
export function isNpmFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  return NPM_FILE_PATTERNS.includes(filename);
}

// ─── npm-Specific Patterns ────────────────────────────────────

/**
 * Additional patterns specifically targeting npm ecosystem dependency confusion.
 */
export const NPM_SPECIFIC_PATTERNS: readonly DepConfusionPattern[] = [
  {
    id: 'npm-scope-registry-mismatch',
    name: 'Scope Registry Mismatch',
    description: 'Organization scope configured for different registries in different locations',
    category: 'registry_config',
    pattern: /@[\w-]+:registry\s*=\s*https?:\/\/[\w.-]+/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Ensure all scope-to-registry mappings are consistent across .npmrc files.',
  },
  {
    id: 'npm-lockfile-registry-mismatch',
    name: 'Lockfile Registry Mismatch',
    description: 'Package resolved from a different registry than configured',
    category: 'registry_config',
    pattern: /["']resolved["']\s*:\s*["']https?:\/\/(?!registry\.npmjs\.org)/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Verify lockfile registry URLs match your configured registries.',
  },
  {
    id: 'npm-ignore-scripts-false',
    name: 'Scripts Not Ignored',
    description: '.npmrc without ignore-scripts, allowing install scripts to execute',
    category: 'manifest_risk',
    pattern: /ignore-scripts\s*=\s*false/,
    severity: 'medium',
    mitre: ['T1059'],
    remediation: 'Consider setting ignore-scripts=true in .npmrc and explicitly running trusted scripts.',
  },
  {
    id: 'npm-package-lock-disabled',
    name: 'Package Lock Disabled',
    description: 'Lockfile generation disabled, allowing resolution drift',
    category: 'manifest_risk',
    pattern: /package-lock\s*=\s*false/,
    severity: 'high',
    mitre: ['T1195.001'],
    remediation: 'Enable package-lock to ensure reproducible installs and detect tampering.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to npm ecosystem files.
 */
const NPM_PATTERNS: readonly DepConfusionPattern[] = [
  ...ALL_PATTERNS,
  ...NPM_SPECIFIC_PATTERNS,
];

/**
 * Scan npm file content against all applicable patterns.
 */
export function* scanNpmContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of NPM_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Dep Confusion / npm] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'npm-scanner',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Dep Confusion / npm] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'npm-scanner',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

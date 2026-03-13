/**
 * SPEAR-08: Lockfile Integrity Scanner
 *
 * Scans lockfiles for supply chain attack indicators:
 *   - package-lock.json   -- npm lockfile
 *   - yarn.lock           -- Yarn classic/berry lockfile
 *   - pnpm-lock.yaml      -- pnpm lockfile
 *   - Gemfile.lock        -- Ruby bundler lockfile
 *   - poetry.lock         -- Python Poetry lockfile
 *
 * Checks include:
 *   - Registry URL tampering
 *   - Integrity hash anomalies
 *   - Suspicious resolved URLs
 *   - Typosquat indicators in locked dependencies
 *   - Unexpected source changes
 */

import type { Finding } from '@wigtn/shared';
import type { SupplyChainPattern } from '../patterns.js';
import { ALL_PATTERNS, getPatternsByCategory } from '../patterns.js';

// ─── Lockfile Detection ────────────────────────────────────────

/** File names recognized as lockfiles. */
export const LOCKFILE_PATTERNS: readonly string[] = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'Gemfile.lock',
  'poetry.lock',
  'npm-shrinkwrap.json',
];

/**
 * Check if a file is a lockfile.
 */
export function isLockfile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  return LOCKFILE_PATTERNS.includes(filename);
}

// ─── Lockfile-Specific Patterns ───────────────────────────────

/**
 * Additional patterns specifically targeting lockfile manipulation.
 */
export const LOCKFILE_SPECIFIC_PATTERNS: readonly SupplyChainPattern[] = [
  {
    id: 'sc-lockfile-registry-tampering',
    name: 'Lockfile Registry Tampering',
    description: 'Package resolved from a non-standard registry URL in lockfile',
    category: 'maintainer_change',
    pattern: /["']resolved["']\s*:\s*["']https?:\/\/(?!registry\.npmjs\.org\/|registry\.yarnpkg\.com\/|registry\.npmmirror\.com\/)[\w.-]+\.\w+/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Verify lockfile registry URLs match your configured registries. Unauthorized registry changes may indicate tampering.',
  },
  {
    id: 'sc-lockfile-missing-integrity',
    name: 'Missing Integrity Hash',
    description: 'Lockfile entry without integrity/checksum hash',
    category: 'maintainer_change',
    pattern: /["']resolved["']\s*:\s*["']https?:\/\/[^"']+["']\s*,?\s*\n\s*(?!.*["']integrity["'])/,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Ensure all lockfile entries have integrity hashes. Missing hashes allow silent package replacement.',
  },
  {
    id: 'sc-lockfile-sha1-only',
    name: 'Weak Integrity Hash (SHA-1)',
    description: 'Lockfile using SHA-1 hash instead of SHA-512',
    category: 'maintainer_change',
    pattern: /["']integrity["']\s*:\s*["']sha1-/,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Upgrade to SHA-512 integrity hashes. SHA-1 is cryptographically weak and may allow collision attacks.',
  },
  {
    id: 'sc-lockfile-git-dependency',
    name: 'Git Dependency in Lockfile',
    description: 'Lockfile contains a git:// or github: dependency URL',
    category: 'maintainer_change',
    pattern: /["'](?:resolved|version)["']\s*:\s*["'](?:git\+|git:\/\/|github:)[\w./:@-]+["']/,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Pin git dependencies to specific commit hashes. Branch references can be compromised.',
  },
  {
    id: 'sc-lockfile-tarball-url',
    name: 'Non-Registry Tarball URL',
    description: 'Lockfile resolving packages from non-registry tarball URLs',
    category: 'binary_download',
    pattern: /["']resolved["']\s*:\s*["']https?:\/\/(?!registry\.npmjs\.org\/|registry\.yarnpkg\.com\/)[\w.-]+[^"']*\.tgz["']/,
    severity: 'high',
    mitre: ['T1195.001', 'T1105'],
    remediation: 'Verify tarball URLs resolve from trusted registries. Non-registry tarballs bypass integrity checks.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to lockfile scanning.
 */
const LOCKFILE_SCAN_PATTERNS: readonly SupplyChainPattern[] = [
  ...getPatternsByCategory('typosquat'),
  ...getPatternsByCategory('maintainer_change'),
  ...LOCKFILE_SPECIFIC_PATTERNS,
];

/**
 * Scan lockfile content for supply chain indicators.
 */
export function* scanLockfileContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of LOCKFILE_SCAN_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Supply Chain / Lockfile] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'lockfile-scanner',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Supply Chain / Lockfile] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'lockfile-scanner',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

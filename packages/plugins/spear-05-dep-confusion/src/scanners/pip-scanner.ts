/**
 * SPEAR-05: Python pip Dependency Confusion Scanner
 *
 * Scans Python dependency files for dependency confusion risks:
 *   - requirements.txt          -- pip requirements
 *   - requirements-*.txt        -- Environment-specific requirements
 *   - setup.py                  -- setuptools configuration
 *   - setup.cfg                 -- setuptools declarative config
 *   - pyproject.toml            -- PEP 621 project metadata
 *   - Pipfile                   -- Pipenv configuration
 *   - pip.conf / pip.ini        -- pip configuration
 *
 * Checks include:
 *   - --extra-index-url usage (dual registry vulnerability)
 *   - Missing hash verification
 *   - Internal package names without namespace
 *   - Insecure index configuration
 */

import type { Finding } from '@wigtn/shared';
import type { DepConfusionPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── pip File Detection ────────────────────────────────────────

/** File name patterns for Python dependency files. */
export const PIP_FILE_PATTERNS: readonly string[] = [
  'requirements.txt',
  'setup.py',
  'setup.cfg',
  'pyproject.toml',
  'Pipfile',
  'pip.conf',
  'pip.ini',
];

/** Regex for requirements-*.txt variants. */
const REQUIREMENTS_VARIANT_RE = /^requirements[-_][\w.-]+\.txt$/;

/**
 * Check if a file is a Python dependency configuration file.
 */
export function isPipFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  if (PIP_FILE_PATTERNS.includes(filename)) return true;
  if (REQUIREMENTS_VARIANT_RE.test(filename)) return true;

  return false;
}

// ─── pip-Specific Patterns ────────────────────────────────────

/**
 * Additional patterns specifically targeting Python pip dependency confusion.
 */
export const PIP_SPECIFIC_PATTERNS: readonly DepConfusionPattern[] = [
  {
    id: 'pip-extra-index-url-in-requirements',
    name: 'Extra Index URL in Requirements',
    description: '--extra-index-url in requirements.txt enables dual-registry resolution',
    category: 'registry_config',
    pattern: /^--extra-index-url\s+/m,
    severity: 'critical',
    mitre: ['T1195.002'],
    remediation: 'Replace --extra-index-url with --index-url in requirements. Use pip.conf for multi-registry setups with proper priority.',
  },
  {
    id: 'pip-index-url-http',
    name: 'Pip Index URL Without TLS',
    description: 'pip index URL using HTTP instead of HTTPS',
    category: 'registry_config',
    pattern: /(?:--index-url|--extra-index-url|index-url)\s*[=:]\s*http:\/\/(?!localhost|127\.0\.0\.1)/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Use HTTPS for all pip index URLs to prevent man-in-the-middle attacks.',
  },
  {
    id: 'pip-dependency-link',
    name: 'Pip Dependency Links (Deprecated)',
    description: 'Using deprecated dependency_links in setup.py',
    category: 'manifest_risk',
    pattern: /dependency_links\s*=\s*\[/,
    severity: 'high',
    mitre: ['T1195.001'],
    remediation: 'Remove dependency_links from setup.py. Use proper index configuration instead.',
  },
  {
    id: 'pip-unpinned-requirement',
    name: 'Unpinned Python Requirement',
    description: 'Python requirement without version pin',
    category: 'version_pinning',
    pattern: /^[a-zA-Z][\w.-]+\s*$/m,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Pin all Python dependencies to specific versions (package==1.2.3) for reproducible installs.',
  },
  {
    id: 'pip-internal-name-pattern',
    name: 'Internal-Looking Python Package',
    description: 'Python package name suggesting internal use without namespace protection',
    category: 'name_squattable',
    pattern: /^(?:internal|private|corp|company)[-_][\w.-]+/m,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Register internal package names on PyPI as placeholders or use a private index with --index-url.',
  },
  {
    id: 'pip-find-links-remote',
    name: 'Remote Find Links',
    description: 'Using --find-links with a remote URL for package resolution',
    category: 'registry_config',
    pattern: /--find-links\s+https?:\/\//,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Use --index-url for remote package sources instead of --find-links.',
  },
];

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Python dependency files.
 * Combines generic dep confusion patterns with pip-specific ones.
 */
const PIP_PATTERNS: readonly DepConfusionPattern[] = [
  ...ALL_PATTERNS,
  ...PIP_SPECIFIC_PATTERNS,
];

/**
 * Scan Python dependency file content against all applicable patterns.
 */
export function* scanPipContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of PIP_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Dep Confusion / pip] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'pip-scanner',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Dep Confusion / pip] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'pip-scanner',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

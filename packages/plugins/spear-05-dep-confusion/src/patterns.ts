/**
 * SPEAR-05: Dependency Confusion -- Pattern Definitions
 *
 * Defines 25+ detection patterns across five categories:
 *
 *   - missing_scope       -- Internal packages without organization scope (@org/)
 *   - registry_config     -- Misconfigured or missing private registry settings
 *   - version_pinning     -- Risky version ranges that allow hijacking
 *   - name_squattable     -- Package names vulnerable to public registry squatting
 *   - manifest_risk       -- Dangerous patterns in dependency manifest files
 *
 * MITRE ATT&CK references:
 *   T1195.002 -- Supply Chain Compromise: Compromise Software Supply Chain
 *   T1195.001 -- Supply Chain Compromise: Compromise Software Dependencies
 *   T1199     -- Trusted Relationship
 *   T1059     -- Command and Scripting Interpreter
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type DepConfusionCategory =
  | 'missing_scope'
  | 'registry_config'
  | 'version_pinning'
  | 'name_squattable'
  | 'manifest_risk';

export interface DepConfusionPattern {
  id: string;
  name: string;
  description: string;
  category: DepConfusionCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── All Patterns ─────────────────────────────────────────────

const depConfusionPatterns: DepConfusionPattern[] = [
  // ─── Missing Scope Patterns ─────────────────────────────────

  {
    id: 'dep-confusion-unscoped-internal',
    name: 'Unscoped Internal Package',
    description: 'Internal package name without @org/ scope prefix, vulnerable to public squatting',
    category: 'missing_scope',
    pattern: /["'](?!@)[a-z][\w.-]*(?:-(?:internal|private|corp|company|org|lib|core|shared|common|utils?|helpers?|services?|api|sdk|client|server|infra|platform|tools?|config|types?))["']\s*:\s*["']/,
    severity: 'critical',
    mitre: ['T1195.002'],
    remediation: 'Add an organization scope to internal packages (e.g., @myorg/package-name). Register the scope on the public registry or configure .npmrc to use a private registry.',
  },
  {
    id: 'dep-confusion-unscoped-prefix',
    name: 'Unscoped Company-Prefixed Package',
    description: 'Package using a company name prefix instead of a proper scope',
    category: 'missing_scope',
    pattern: /["'](?!@)(?:company|corp|org|internal|private|myorg|mycompany)[-_][\w.-]+["']\s*:\s*["']/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Convert company-prefixed packages to scoped packages (e.g., company-utils -> @company/utils).',
  },
  {
    id: 'dep-confusion-workspace-protocol-missing',
    name: 'Workspace Package Without Protocol',
    description: 'Monorepo package referenced without workspace: protocol, may resolve from public registry',
    category: 'missing_scope',
    pattern: /["']@[\w-]+\/[\w.-]+["']\s*:\s*["'](?!workspace:|file:|link:)\d/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Use workspace:* protocol for monorepo packages to ensure they resolve locally, not from public registry.',
  },

  // ─── Registry Configuration Patterns ────────────────────────

  {
    id: 'dep-confusion-no-registry-config',
    name: 'Missing Private Registry Config',
    description: 'No .npmrc or registry configuration found for scoped packages',
    category: 'registry_config',
    pattern: /registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com)[\w.-]+/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Configure .npmrc with your private registry URL for organization-scoped packages.',
  },
  {
    id: 'dep-confusion-http-registry',
    name: 'HTTP Registry (No TLS)',
    description: 'Registry configured with HTTP instead of HTTPS',
    category: 'registry_config',
    pattern: /registry\s*=\s*http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/,
    severity: 'high',
    mitre: ['T1195.002', 'T1199'],
    remediation: 'Use HTTPS for registry URLs. HTTP registries are vulnerable to man-in-the-middle attacks.',
  },
  {
    id: 'dep-confusion-auth-token-inline',
    name: 'Registry Auth Token Inline',
    description: 'Authentication token hardcoded in registry configuration',
    category: 'registry_config',
    pattern: /(?:_authToken|_auth|token)\s*=\s*[A-Za-z0-9+/=_-]{20,}/,
    severity: 'critical',
    mitre: ['T1195.002'],
    remediation: 'Do not hardcode registry authentication tokens. Use environment variables: ${NPM_TOKEN}.',
  },
  {
    id: 'dep-confusion-always-auth-missing',
    name: 'Missing always-auth for Private Registry',
    description: 'Private registry scope without always-auth setting',
    category: 'registry_config',
    pattern: /@[\w-]+:registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org)/,
    severity: 'low',
    mitre: ['T1195.002'],
    remediation: 'Set always-auth=true for private registry scopes to ensure authentication is always provided.',
  },
  {
    id: 'dep-confusion-pip-extra-index',
    name: 'Pip Extra Index URL',
    description: 'pip configured with --extra-index-url which checks public PyPI first',
    category: 'registry_config',
    pattern: /--extra-index-url\s+https?:\/\//,
    severity: 'critical',
    mitre: ['T1195.002'],
    remediation: 'Use --index-url instead of --extra-index-url for private registries. Extra index URLs allow public PyPI to satisfy packages first.',
  },
  {
    id: 'dep-confusion-pip-trusted-host',
    name: 'Pip Trusted Host (No TLS Verification)',
    description: 'pip configured to trust a host without TLS verification',
    category: 'registry_config',
    pattern: /--trusted-host\s+[\w.-]+/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Remove --trusted-host and configure proper TLS certificates for your private index.',
  },

  // ─── Version Pinning Patterns ───────────────────────────────

  {
    id: 'dep-confusion-star-version',
    name: 'Wildcard Version Range',
    description: 'Dependency using * or latest as version, accepting any version including malicious ones',
    category: 'version_pinning',
    pattern: /["'][\w@/.-]+["']\s*:\s*["'](?:\*|latest|x\.x\.x)["']/,
    severity: 'critical',
    mitre: ['T1195.001'],
    remediation: 'Pin dependencies to specific versions or use tight semver ranges (^, ~). Never use * or latest.',
  },
  {
    id: 'dep-confusion-gt-version',
    name: 'Unbounded Greater-Than Version',
    description: 'Dependency with >= version range allowing any future version',
    category: 'version_pinning',
    pattern: /["'][\w@/.-]+["']\s*:\s*["']>=\s*\d+\.\d+\.\d+["']/,
    severity: 'high',
    mitre: ['T1195.001'],
    remediation: 'Use caret (^) or tilde (~) ranges instead of unbounded >= ranges.',
  },
  {
    id: 'dep-confusion-git-dep-no-hash',
    name: 'Git Dependency Without Commit Hash',
    description: 'Git dependency URL without pinned commit hash',
    category: 'version_pinning',
    pattern: /["'][\w@/.-]+["']\s*:\s*["'](?:git\+|github:|git:\/\/)[\w./:@-]+(?!#[0-9a-f]{7,40})["']/,
    severity: 'high',
    mitre: ['T1195.001'],
    remediation: 'Pin git dependencies to a specific commit hash, not a branch or tag.',
  },
  {
    id: 'dep-confusion-url-dep',
    name: 'URL Dependency (Unverified)',
    description: 'Dependency installed from a URL without integrity verification',
    category: 'version_pinning',
    pattern: /["'][\w@/.-]+["']\s*:\s*["']https?:\/\/[^"']+\.(?:tgz|tar\.gz|zip)["']/,
    severity: 'high',
    mitre: ['T1195.001'],
    remediation: 'Avoid URL dependencies. If required, verify integrity with checksums.',
  },
  {
    id: 'dep-confusion-pip-no-hash',
    name: 'Pip Requirement Without Hash',
    description: 'Python requirement without --hash for integrity verification',
    category: 'version_pinning',
    pattern: /^[\w][\w.-]*\s*(?:==|>=|<=|~=|!=)\s*[\d.]+\s*$/m,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Add --hash to pip requirements for supply chain integrity verification.',
  },

  // ─── Name Squattable Patterns ───────────────────────────────

  {
    id: 'dep-confusion-common-typo-target',
    name: 'Common Typosquat Target Name',
    description: 'Package name that is easily confused with popular packages via typos',
    category: 'name_squattable',
    pattern: /["'](?:lodahs|reqeust|axois|exprss|momnet|reactt|vuee|angualr|babael|wepback|typescipt|eslitn)["']\s*:/,
    severity: 'critical',
    mitre: ['T1195.002'],
    remediation: 'Verify the package name is correct. This appears to be a typosquat of a popular package.',
  },
  {
    id: 'dep-confusion-single-char-diff',
    name: 'Single Character Difference Package',
    description: 'Package name differs by a single character from a well-known package',
    category: 'name_squattable',
    pattern: /["'](?:lod[a-z]sh|req[a-z]est|axi[a-z]s|expr[a-z]ss|mome[a-z]t|reac[a-z]|vu[a-z]|angul[a-z]r|bab[a-z]l|webp[a-z]ck)["']\s*:/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Verify this package name. It appears similar to a well-known package and may be a typosquat.',
  },
  {
    id: 'dep-confusion-hyphen-swap',
    name: 'Hyphen/Underscore Swap Package',
    description: 'Package name using underscore where hyphen is standard or vice versa',
    category: 'name_squattable',
    pattern: /["'](?!@)(?:\w+_\w+_\w+)["']\s*:\s*["']\d/,
    severity: 'low',
    mitre: ['T1195.002'],
    remediation: 'Verify the package uses the correct separator (hyphen vs underscore). npm uses hyphens by convention.',
  },
  {
    id: 'dep-confusion-numeric-suffix',
    name: 'Numeric Suffix Package Name',
    description: 'Package name with suspicious numeric suffix that may be a squatted variant',
    category: 'name_squattable',
    pattern: /["'](?!@)[\w-]+\d{1,2}["']\s*:\s*["'](?:\^|~|>=)?\d/,
    severity: 'low',
    mitre: ['T1195.002'],
    remediation: 'Verify this package is legitimate and not a squatted variant with a numeric suffix.',
  },

  // ─── Manifest Risk Patterns ─────────────────────────────────

  {
    id: 'dep-confusion-preinstall-script',
    name: 'Preinstall Script in Dependency',
    description: 'Package manifest with preinstall script that runs before installation',
    category: 'manifest_risk',
    pattern: /["']preinstall["']\s*:\s*["'][^"']+["']/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Review preinstall scripts carefully. Malicious packages often use preinstall to execute code before the user can inspect.',
  },
  {
    id: 'dep-confusion-install-script-curl',
    name: 'Install Script with Network Access',
    description: 'Install/postinstall script making network requests',
    category: 'manifest_risk',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:curl|wget|fetch|http|node\s+-e|python\s+-c)[^"']*["']/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Remove network access from install scripts. Install hooks should not download or execute remote code.',
  },
  {
    id: 'dep-confusion-publish-config-missing',
    name: 'Missing publishConfig for Private Package',
    description: 'Private package without publishConfig.registry, may accidentally publish to public',
    category: 'manifest_risk',
    pattern: /["']private["']\s*:\s*true[\s\S]{0,500}(?!publishConfig)/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Add publishConfig.registry pointing to your private registry to prevent accidental public publishing.',
  },
  {
    id: 'dep-confusion-resolution-override',
    name: 'Dependency Resolution Override',
    description: 'Using resolutions/overrides to force specific dependency versions',
    category: 'manifest_risk',
    pattern: /["'](?:resolutions|overrides|pnpm\.overrides)["']\s*:\s*\{/,
    severity: 'low',
    mitre: ['T1195.001'],
    remediation: 'Review dependency resolution overrides. Ensure they do not mask supply chain compromises.',
  },
  {
    id: 'dep-confusion-bundled-dep',
    name: 'Bundled Dependencies from External Source',
    description: 'Bundled dependencies may bypass integrity checks',
    category: 'manifest_risk',
    pattern: /["']bundledDependencies["']\s*:\s*\[/,
    severity: 'low',
    mitre: ['T1195.001'],
    remediation: 'Review bundled dependencies carefully. Bundled packages bypass normal registry integrity checks.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 25+ dependency confusion detection patterns.
 */
export const ALL_PATTERNS: readonly DepConfusionPattern[] = depConfusionPatterns;

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: DepConfusionCategory): DepConfusionPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): DepConfusionPattern[] {
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const minLevel = severityOrder[minSeverity];
  return ALL_PATTERNS.filter((p) => severityOrder[p.severity] <= minLevel);
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<DepConfusionCategory, number> {
  const counts: Record<DepConfusionCategory, number> = {
    missing_scope: 0,
    registry_config: 0,
    version_pinning: 0,
    name_squattable: 0,
    manifest_risk: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}

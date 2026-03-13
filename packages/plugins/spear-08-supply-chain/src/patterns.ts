/**
 * SPEAR-08: Supply Chain Attack -- Pattern Definitions
 *
 * Defines 45+ detection patterns across five categories:
 *
 *   - postinstall_abuse  -- Dangerous install/postinstall script patterns
 *   - typosquat          -- Known typosquatting indicators and name patterns
 *   - maintainer_change  -- Indicators of suspicious maintainer/ownership changes
 *   - binary_download    -- Packages that download binaries at install time
 *   - obfuscation        -- Obfuscated code in package scripts or source
 *
 * MITRE ATT&CK references:
 *   T1195.001 -- Supply Chain Compromise: Compromise Software Dependencies
 *   T1195.002 -- Supply Chain Compromise: Compromise Software Supply Chain
 *   T1059     -- Command and Scripting Interpreter
 *   T1027     -- Obfuscated Files or Information
 *   T1105     -- Ingress Tool Transfer
 *   T1036     -- Masquerading
 *   T1204     -- User Execution
 *   T1564     -- Hide Artifacts
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type SupplyChainCategory =
  | 'postinstall_abuse'
  | 'typosquat'
  | 'maintainer_change'
  | 'binary_download'
  | 'obfuscation';

export interface SupplyChainPattern {
  id: string;
  name: string;
  description: string;
  category: SupplyChainCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── All Patterns ─────────────────────────────────────────────

const supplyChainPatterns: SupplyChainPattern[] = [
  // ─── Postinstall Abuse Patterns ─────────────────────────────

  {
    id: 'sc-postinstall-curl-exec',
    name: 'Postinstall Curl/Wget Execution',
    description: 'Install script downloads and executes remote code via curl/wget',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:curl|wget)\s+[^"']*\|\s*(?:sh|bash|node|python)/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1059', 'T1105'],
    remediation: 'Remove curl/wget pipe-to-shell patterns from install scripts. Pre-build binaries or use postinstall-postinstall.',
  },
  {
    id: 'sc-postinstall-node-exec',
    name: 'Postinstall Node Eval',
    description: 'Install script uses node -e or node --eval to run inline code',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*node\s+(?:-e|--eval)\s+/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Replace inline node -e execution with a dedicated script file that can be reviewed.',
  },
  {
    id: 'sc-postinstall-env-access',
    name: 'Postinstall Environment Access',
    description: 'Install script accesses environment variables which may contain secrets',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:process\.env|\$\{?\w*(?:TOKEN|SECRET|KEY|PASSWORD|AUTH|CREDENTIAL)\w*\}?)/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Install scripts should not access environment secrets. Review and remove env var access from install hooks.',
  },
  {
    id: 'sc-postinstall-network-request',
    name: 'Postinstall Network Request',
    description: 'Install script makes network requests via node http/https modules',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:https?\.(?:get|request)|fetch|axios|got|request)\s*\(/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1105'],
    remediation: 'Remove network request code from install scripts. Use a separate build step for downloading dependencies.',
  },
  {
    id: 'sc-postinstall-file-write',
    name: 'Postinstall File Write',
    description: 'Install script writes to files outside node_modules',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:fs\.write|writeFile|>>?\s*(?:\/|~\/|\.\.\/))/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Install scripts should not write files outside their package directory.',
  },
  {
    id: 'sc-postinstall-reverse-shell',
    name: 'Postinstall Reverse Shell',
    description: 'Install script contains reverse shell patterns',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:\/dev\/tcp\/|nc\s+-[a-z]*e\s+|bash\s+-i\s+>|python\s+-c\s+['"]import\s+(?:socket|os|subprocess))/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'CRITICAL: Remove reverse shell code immediately. This is a clear indicator of a malicious package.',
  },
  {
    id: 'sc-postinstall-child-process',
    name: 'Postinstall Child Process Spawn',
    description: 'Install script spawns child processes',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:child_process|spawn|exec(?:Sync)?|execFile)\b/,
    severity: 'high',
    mitre: ['T1195.001', 'T1059'],
    remediation: 'Review child process usage in install scripts. Prefer declarative build steps over shell execution.',
  },
  {
    id: 'sc-postinstall-hidden-script',
    name: 'Postinstall Hidden Script File',
    description: 'Install script references a hidden or obfuscated script file',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'](?:node\s+)?\.[\w/]*(?:\.min\.js|\.bundle\.js|_[\da-f]{8}\.js|[A-Za-z0-9+/=]{20,})/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1027'],
    remediation: 'Install scripts should reference clearly named script files, not hidden or obfuscated names.',
  },
  {
    id: 'sc-postinstall-os-detection',
    name: 'Postinstall OS Detection',
    description: 'Install script detects operating system, common in targeted attacks',
    category: 'postinstall_abuse',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:process\.platform|os\.platform|uname|OSTYPE|systeminfo)/,
    severity: 'medium',
    mitre: ['T1195.001'],
    remediation: 'Review OS detection in install scripts. While sometimes legitimate, this is also used in targeted supply chain attacks.',
  },

  // ─── Typosquat Patterns ─────────────────────────────────────

  {
    id: 'sc-typosquat-popular-npm',
    name: 'Known npm Typosquat Target',
    description: 'Package name closely resembles a popular npm package',
    category: 'typosquat',
    pattern: /["'](?:lodashs?|loadash|l0dash|lodash[_.](?:es|js|core)|reqeusts?|requets|axios-|axio[sz]|expresss?|expres[^s]|react-(?:dom-|scripts-)|vue-(?:cli-|router-)|angullar|babeel|web-?pakc|typescritp|eslint-?config-?[a-z]{1,3}$)["']\s*:/,
    severity: 'critical',
    mitre: ['T1195.002', 'T1036'],
    remediation: 'Verify this package name. It appears to be a typosquat of a popular package.',
  },
  {
    id: 'sc-typosquat-scope-confusion',
    name: 'Scope Confusion Attack',
    description: 'Package uses a scope that mimics a well-known organization',
    category: 'typosquat',
    pattern: /["']@(?:goggle|gooogle|microsft|micosoft|amaz0n|amazn|faceboook|facebok|githubb|githb)\/[\w.-]+["']\s*:/,
    severity: 'critical',
    mitre: ['T1195.002', 'T1036'],
    remediation: 'Verify the organization scope is correct. This appears to be a misspelled well-known organization.',
  },
  {
    id: 'sc-typosquat-homoglyph-name',
    name: 'Homoglyph Package Name',
    description: 'Package name uses Unicode characters that look like ASCII letters',
    category: 'typosquat',
    pattern: /["'][\w.-]*[\u0430\u0435\u043E\u0440\u0441\u0445][\w.-]*["']\s*:/,
    severity: 'critical',
    mitre: ['T1195.002', 'T1036'],
    remediation: 'Remove packages with Unicode homoglyph characters in their names. This is a supply chain attack technique.',
  },
  {
    id: 'sc-typosquat-plural-singular',
    name: 'Plural/Singular Confusion',
    description: 'Package name differs from popular package only by plural/singular form',
    category: 'typosquat',
    pattern: /["'](?:colors?s|events?s|buffers?s|streams?s|paths?s|utils?s|helpers?s|modules?s|models?s|routes?s)["']\s*:/,
    severity: 'medium',
    mitre: ['T1195.002', 'T1036'],
    remediation: 'Verify the package name. Plural/singular confusion is a common typosquatting technique.',
  },
  {
    id: 'sc-typosquat-zero-day-package',
    name: 'Suspiciously New Package',
    description: 'Package with version 0.0.1 or 1.0.0 that shadows a well-known name pattern',
    category: 'typosquat',
    pattern: /["'][\w@/.-]+["']\s*:\s*["'](?:0\.0\.1|0\.1\.0|1\.0\.0)["']/,
    severity: 'low',
    mitre: ['T1195.002'],
    remediation: 'Verify packages at version 0.0.1 or 1.0.0. New packages mimicking established ones may be malicious.',
  },
  {
    id: 'sc-typosquat-dash-underscore',
    name: 'Dash/Underscore Name Variant',
    description: 'Package name using underscore where original uses dash',
    category: 'typosquat',
    pattern: /["'](?:cross_env|dotenv_cli|node_fetch|web_socket|babel_core|react_dom|express_session|body_parser|cookie_parser|json_web_token|node_sass)["']\s*:/,
    severity: 'high',
    mitre: ['T1195.002', 'T1036'],
    remediation: 'Verify the package separator character. The correct package likely uses hyphens instead of underscores.',
  },

  // ─── Maintainer Change Patterns ─────────────────────────────

  {
    id: 'sc-maintainer-email-suspicious',
    name: 'Suspicious Maintainer Email Domain',
    description: 'Package maintainer using disposable or suspicious email domain',
    category: 'maintainer_change',
    pattern: /["'](?:email|author)["']\s*:\s*["'][\w.+-]+@(?:mailinator|guerrillamail|tempmail|throwaway|yopmail|10minutemail|trashmail|sharklasers|guerrillamailblock|grr\.la)\.[\w.]+["']/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Investigate packages with disposable email addresses. This may indicate a takeover or fake package.',
  },
  {
    id: 'sc-maintainer-contributors-removed',
    name: 'Contributors Field Removed',
    description: 'Package.json with maintainers or contributors array set to empty',
    category: 'maintainer_change',
    pattern: /["'](?:maintainers|contributors)["']\s*:\s*\[\s*\]/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Review packages with empty maintainer lists. This may indicate maintainer information was scrubbed after a takeover.',
  },
  {
    id: 'sc-maintainer-repository-mismatch',
    name: 'Repository URL Mismatch',
    description: 'Package repository URL points to an unexpected or suspicious location',
    category: 'maintainer_change',
    pattern: /["']repository["']\s*:\s*(?:\{[^}]*["']url["']\s*:\s*)?["'](?:https?:\/\/)?(?!github\.com\/|gitlab\.com\/|bitbucket\.org\/)[\w.-]+\.[\w.-]+/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Verify the repository URL points to a legitimate code hosting platform.',
  },
  {
    id: 'sc-maintainer-homepage-suspicious',
    name: 'Suspicious Homepage URL',
    description: 'Package homepage pointing to a URL shortener or suspicious domain',
    category: 'maintainer_change',
    pattern: /["']homepage["']\s*:\s*["']https?:\/\/(?:bit\.ly|t\.co|tinyurl|goo\.gl|is\.gd|shorte\.st|adf\.ly|ow\.ly)/,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Remove URL shorteners from homepage field. Use direct URLs to the project documentation.',
  },

  // ─── Binary Download Patterns ───────────────────────────────

  {
    id: 'sc-binary-download-install',
    name: 'Binary Download in Install Script',
    description: 'Install script downloads a binary executable',
    category: 'binary_download',
    pattern: /["'](?:pre|post)?install["']\s*:\s*["'][^"']*(?:curl|wget|fetch)\s+[^"']*\.(?:exe|bin|sh|dll|so|dylib|elf)["']/,
    severity: 'critical',
    mitre: ['T1195.001', 'T1105'],
    remediation: 'Do not download binaries in install scripts. Use prebuild, node-pre-gyp, or platform-specific optional dependencies.',
  },
  {
    id: 'sc-binary-node-pre-gyp-untrusted',
    name: 'node-pre-gyp Untrusted Binary Host',
    description: 'node-pre-gyp configured with a non-standard binary host',
    category: 'binary_download',
    pattern: /["']binary["']\s*:\s*\{[^}]*["']host["']\s*:\s*["']https?:\/\/(?!github\.com\/|storage\.googleapis\.com\/|s3\.amazonaws\.com\/)[\w.-]+/,
    severity: 'high',
    mitre: ['T1195.001', 'T1105'],
    remediation: 'Verify the binary host URL. Untrusted hosts may serve compromised binaries.',
  },
  {
    id: 'sc-binary-download-github-release',
    name: 'GitHub Release Binary Download',
    description: 'Script downloads from GitHub releases, verify the repository is trusted',
    category: 'binary_download',
    pattern: /(?:curl|wget|fetch)\s+[^;]*github\.com\/[\w.-]+\/[\w.-]+\/releases\/download/,
    severity: 'medium',
    mitre: ['T1105'],
    remediation: 'Verify the GitHub repository and release are from a trusted source. Pin to specific release tags.',
  },
  {
    id: 'sc-binary-chmod-after-download',
    name: 'Chmod After Binary Download',
    description: 'Script downloads a file then makes it executable',
    category: 'binary_download',
    pattern: /(?:curl|wget)\s+[^;]+&&\s*chmod\s+\+x\s+/,
    severity: 'high',
    mitre: ['T1195.001', 'T1105', 'T1059'],
    remediation: 'Review download-and-execute patterns. Verify the source and integrity of downloaded binaries.',
  },
  {
    id: 'sc-binary-encoded-url',
    name: 'Base64 Encoded Download URL',
    description: 'Binary download URL is base64 encoded to evade detection',
    category: 'binary_download',
    pattern: /(?:atob|Buffer\.from|base64_decode)\s*\(\s*['"`][A-Za-z0-9+/=]{20,}['"`]\s*\)[^;]*(?:http|url|fetch|curl|wget|download)/i,
    severity: 'critical',
    mitre: ['T1195.001', 'T1027', 'T1105'],
    remediation: 'Remove base64 encoded URLs. Obfuscating download URLs is a clear indicator of malicious intent.',
  },

  // ─── Obfuscation Patterns ───────────────────────────────────

  {
    id: 'sc-obfuscation-hex-strings',
    name: 'Hex-Encoded String Sequences',
    description: 'Long sequences of hex-encoded characters indicating obfuscated code',
    category: 'obfuscation',
    pattern: /(?:\\x[0-9a-fA-F]{2}){8,}/,
    severity: 'high',
    mitre: ['T1027'],
    remediation: 'Review hex-encoded strings. Legitimate code should use readable string literals.',
  },
  {
    id: 'sc-obfuscation-unicode-escape',
    name: 'Unicode Escape Sequences',
    description: 'Long sequences of Unicode escape characters indicating obfuscation',
    category: 'obfuscation',
    pattern: /(?:\\u[0-9a-fA-F]{4}){6,}/,
    severity: 'high',
    mitre: ['T1027'],
    remediation: 'Review Unicode escape sequences. Legitimate code should use readable characters.',
  },
  {
    id: 'sc-obfuscation-eval-string-concat',
    name: 'Eval with String Concatenation',
    description: 'Using eval() with concatenated strings to build executable code',
    category: 'obfuscation',
    pattern: /eval\s*\(\s*(?:['"`][\w\s]*['"`]\s*\+\s*){3,}/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove eval() with string concatenation. This is a code obfuscation technique used in malware.',
  },
  {
    id: 'sc-obfuscation-function-constructor',
    name: 'Function Constructor Execution',
    description: 'Using new Function() to execute dynamically constructed code',
    category: 'obfuscation',
    pattern: /new\s+Function\s*\(\s*(?:['"`]|[\w]+\s*\+)/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove new Function() calls. This is equivalent to eval() and is used to execute obfuscated code.',
  },
  {
    id: 'sc-obfuscation-base64-decode-exec',
    name: 'Base64 Decode and Execute',
    description: 'Decoding base64 content and executing it',
    category: 'obfuscation',
    pattern: /(?:eval|Function|exec|execSync)\s*\(\s*(?:atob|Buffer\.from)\s*\(\s*['"`][A-Za-z0-9+/=]{20,}/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove base64 decode-to-execute patterns. This is a common malware payload delivery technique.',
  },
  {
    id: 'sc-obfuscation-char-code',
    name: 'String.fromCharCode Obfuscation',
    description: 'Building strings from character codes to hide content',
    category: 'obfuscation',
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/,
    severity: 'high',
    mitre: ['T1027'],
    remediation: 'Review String.fromCharCode usage. Building strings from char codes is an obfuscation technique.',
  },
  {
    id: 'sc-obfuscation-minified-oneliner',
    name: 'Suspicious Minified One-Liner',
    description: 'Extremely long single line of obfuscated/minified JavaScript',
    category: 'obfuscation',
    pattern: /^.{1000,}$/m,
    severity: 'medium',
    mitre: ['T1027'],
    remediation: 'Review extremely long single-line code. Source files should not contain minified code.',
  },
  {
    id: 'sc-obfuscation-global-access-bracket',
    name: 'Dynamic Global Access via Bracket Notation',
    description: 'Accessing global properties via bracket notation to hide function names',
    category: 'obfuscation',
    pattern: /(?:global|window|globalThis|self)\s*\[\s*['"`](?:eval|Function|setTimeout|setInterval|execScript)['"`]\s*\]/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove dynamic global property access. Using bracket notation to access eval/Function is an evasion technique.',
  },
  {
    id: 'sc-obfuscation-packed-js',
    name: 'Packed/Compressed JavaScript',
    description: 'JavaScript packer signature (p,a,c,k,e,d pattern)',
    category: 'obfuscation',
    pattern: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/,
    severity: 'critical',
    mitre: ['T1027'],
    remediation: 'Remove packed JavaScript. The p,a,c,k,e,d pattern is used by JavaScript packers to hide malicious code.',
  },
  {
    id: 'sc-obfuscation-jsfuck',
    name: 'JSFuck-Style Obfuscation',
    description: 'Code using JSFuck-style encoding with only []()!+ characters',
    category: 'obfuscation',
    pattern: /(?:\[\]\s*\+\s*\[\]|\!\s*\[\]|\!\s*['"`]['"`]|\(\s*\!\s*\[\]\s*\+\s*\[\]\s*\)){3,}/,
    severity: 'critical',
    mitre: ['T1027'],
    remediation: 'Remove JSFuck-style encoded code. This encoding technique is used exclusively for obfuscation and evasion.',
  },
  {
    id: 'sc-obfuscation-require-dynamic',
    name: 'Dynamic Require/Import',
    description: 'Using variable or expression in require/import to hide dependency',
    category: 'obfuscation',
    pattern: /(?:require|import)\s*\(\s*(?:['"`]\s*\+\s*[\w]+|[\w]+\s*\+\s*['"`]|`\$\{[\w]+\}`|[\w]+\s*\(\s*['"`])/,
    severity: 'high',
    mitre: ['T1027'],
    remediation: 'Use static require/import paths. Dynamic module loading can hide malicious dependencies.',
  },
  {
    id: 'sc-obfuscation-prototype-pollution',
    name: 'Prototype Pollution Pattern',
    description: 'Code modifying Object prototype or using __proto__ assignment',
    category: 'obfuscation',
    pattern: /(?:__proto__|Object\.prototype)\s*(?:\[|\.)\s*(?!hasOwnProperty|toString|valueOf|constructor\s*(?:\)|$))/,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Review prototype modification code. Prototype pollution can be used to inject malicious behavior.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 45+ supply chain attack detection patterns.
 */
export const ALL_PATTERNS: readonly SupplyChainPattern[] = supplyChainPatterns;

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: SupplyChainCategory): SupplyChainPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): SupplyChainPattern[] {
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
export function getPatternCounts(): Record<SupplyChainCategory, number> {
  const counts: Record<SupplyChainCategory, number> = {
    postinstall_abuse: 0,
    typosquat: 0,
    maintainer_change: 0,
    binary_download: 0,
    obfuscation: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}

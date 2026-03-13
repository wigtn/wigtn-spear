/**
 * SPEAR-19: Social Engineering Code Analyzer -- Pattern Definitions
 *
 * Defines 30+ patterns that detect social engineering techniques in code:
 *
 *   - deceptive_naming     -- Misleading function/variable names that hide true purpose
 *   - hidden_code          -- Hidden functionality in code (eval, dynamic imports, etc.)
 *   - unicode_tricks       -- Bidirectional text, homoglyphs, zero-width characters
 *   - import_confusion     -- Typosquatting, dependency confusion in imports
 *   - trojan_source        -- Trojan Source attacks using Unicode control characters
 *
 * Each pattern includes a MITRE ATT&CK mapping for enterprise threat classification.
 *
 * MITRE references used:
 *   T1027     -- Obfuscated Files or Information
 *   T1036     -- Masquerading
 *   T1059     -- Command and Scripting Interpreter
 *   T1195.002 -- Supply Chain Compromise: Compromise Software Supply Chain
 *   T1204     -- User Execution
 *   T1564     -- Hide Artifacts
 *   T1574     -- Hijack Execution Flow
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type SocialEngCategory =
  | 'deceptive_naming'
  | 'hidden_code'
  | 'unicode_tricks'
  | 'import_confusion'
  | 'trojan_source';

export interface SocialEngPattern {
  id: string;
  name: string;
  description: string;
  category: SocialEngCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── Deceptive Naming Patterns ─────────────────────────────────

const deceptiveNamingPatterns: SocialEngPattern[] = [
  {
    id: 'soceng-name-safety-check-backdoor',
    name: 'Safety Check Name Masking Backdoor',
    description: 'Function named as safety/security check that contains network calls or exec',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:validateSafety|checkSecurity|sanitizeInput|verifyAuth|ensureSafe)\s*(?:=\s*(?:async\s*)?\(|(?:\s*\(|\s*<))[^}]*(?:fetch|exec|eval|XMLHttpRequest|child_process)/s,
    severity: 'high',
    mitre: ['T1036', 'T1059'],
    remediation: 'Review functions named as safety/security checks. The function body contains suspicious operations (network calls, exec) inconsistent with its name.',
  },
  {
    id: 'soceng-name-logger-exfil',
    name: 'Logger Function Exfiltration',
    description: 'Function named as a logger that sends data externally',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:log(?:Error|Info|Debug|Warning|Event|Metric)|debugLog|traceLog)\s*(?:=\s*(?:async\s*)?\(|(?:\s*\())[^}]*(?:fetch|https?\.request|axios|XMLHttpRequest)/s,
    severity: 'high',
    mitre: ['T1036', 'T1567'],
    remediation: 'Inspect logger functions for hidden network calls. A logging function should not make outbound HTTP requests.',
  },
  {
    id: 'soceng-name-cleanup-destructive',
    name: 'Cleanup Function Destructive Action',
    description: 'Function named cleanup/teardown that performs destructive operations',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:cleanup|teardown|dispose|reset|clear(?:Cache|Temp|Data))\s*(?:=\s*(?:async\s*)?\(|(?:\s*\())[^}]*(?:rm\s+-rf|rimraf|unlink(?:Sync)?|rmdir(?:Sync)?|dropDatabase|DROP\s+TABLE)/s,
    severity: 'high',
    mitre: ['T1036', 'T1485'],
    remediation: 'Verify cleanup functions do not perform destructive operations beyond their expected scope.',
  },
  {
    id: 'soceng-name-test-helper-exec',
    name: 'Test Helper with Command Execution',
    description: 'Function named as test utility that executes system commands',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:testHelper|mockSetup|setupFixture|createTestData|initTestEnv)\s*(?:=\s*(?:async\s*)?\(|(?:\s*\())[^}]*(?:execSync|spawnSync|child_process|shelljs)/s,
    severity: 'high',
    mitre: ['T1036', 'T1059'],
    remediation: 'Examine test helper functions for hidden command execution. Test utilities should not run arbitrary shell commands.',
  },
  {
    id: 'soceng-name-noop-with-side-effects',
    name: 'Noop Function with Side Effects',
    description: 'Function named as no-op or placeholder that performs actual operations',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:noop|NOOP|noOp|placeholder|stub|dummy|unused|_unused)\s*(?:=\s*(?:async\s*)?\(|(?:\s*\())[^}]*(?:fetch|exec|eval|require|import|write(?:File)?|send|post)/s,
    severity: 'critical',
    mitre: ['T1036', 'T1059'],
    remediation: 'Remove side effects from no-op/placeholder functions. A function named noop should truly do nothing.',
  },
  {
    id: 'soceng-name-config-loader-write',
    name: 'Config Loader with Write Operations',
    description: 'Function named as config reader that also writes or modifies files',
    category: 'deceptive_naming',
    pattern: /(?:function|const|let|var)\s+(?:loadConfig|readConfig|getConfig|parseConfig|getSettings)\s*(?:=\s*(?:async\s*)?\(|(?:\s*\())[^}]*(?:writeFile|appendFile|createWriteStream|fs\.write)/s,
    severity: 'high',
    mitre: ['T1036', 'T1565'],
    remediation: 'Config loader functions should not write files. Separate read and write concerns.',
  },
  {
    id: 'soceng-name-deprecated-active',
    name: 'Deprecated Tag on Active Function',
    description: 'Function marked deprecated that is still called in production paths',
    category: 'deceptive_naming',
    pattern: /@deprecated[\s\S]{0,200}(?:export\s+(?:default\s+)?(?:function|class|const))\s+\w+/,
    severity: 'low',
    mitre: ['T1036'],
    remediation: 'Review exported functions marked as deprecated. Attackers may use the deprecated tag to discourage code review of active malicious code.',
  },
];

// ─── Hidden Code Patterns ──────────────────────────────────────

const hiddenCodePatterns: SocialEngPattern[] = [
  {
    id: 'soceng-hidden-eval-construct',
    name: 'Constructed eval() Call',
    description: 'Dynamic construction of eval call to evade static analysis',
    category: 'hidden_code',
    pattern: /(?:global|window|self|globalThis)\s*\[\s*['"`]eval['"`]\s*\]|(?:Function|constructor)\s*\(\s*['"`]return\s+this['"`]\s*\)\s*\(\)\s*\[\s*['"`]eval['"`]\s*\]/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove dynamic eval construction. Accessing eval through bracket notation or Function constructor is a code hiding technique.',
  },
  {
    id: 'soceng-hidden-dynamic-import',
    name: 'Obfuscated Dynamic Import',
    description: 'Dynamic import with computed or concatenated module specifier',
    category: 'hidden_code',
    pattern: /import\s*\(\s*(?:[`'"][\s\S]*?\$\{|[\w.]+\s*\+\s*['"`]|atob\s*\(|Buffer\.from\s*\(|decodeURI(?:Component)?\s*\()/,
    severity: 'high',
    mitre: ['T1027', 'T1059'],
    remediation: 'Replace dynamic imports with static module specifiers. Computed import paths can load malicious modules.',
  },
  {
    id: 'soceng-hidden-settimeout-string',
    name: 'setTimeout/setInterval String Execution',
    description: 'setTimeout or setInterval called with a string argument (implicit eval)',
    category: 'hidden_code',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*['"`][^'"`]{10,}['"`]/,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Replace string arguments to setTimeout/setInterval with function references. String arguments are evaluated as code.',
  },
  {
    id: 'soceng-hidden-new-function',
    name: 'new Function() Code Generation',
    description: 'Runtime code generation using the Function constructor',
    category: 'hidden_code',
    pattern: /new\s+Function\s*\(\s*(?:['"`][\s\S]*?['"`]|[\w.]+(?:\s*\+\s*[\w.]+)*)\s*\)/,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove new Function() calls. The Function constructor enables runtime code generation and is equivalent to eval.',
  },
  {
    id: 'soceng-hidden-prototype-pollution',
    name: 'Prototype Pollution Setup',
    description: 'Assignment to __proto__ or Object.prototype to inject properties',
    category: 'hidden_code',
    pattern: /(?:__proto__|Object\.prototype|constructor\.prototype)\s*(?:\[['"`]\w+['"`]\]|\.[\w$]+)\s*=/,
    severity: 'critical',
    mitre: ['T1574'],
    remediation: 'Remove prototype pollution. Assignments to __proto__ or Object.prototype can modify all objects in the runtime.',
  },
  {
    id: 'soceng-hidden-hex-string-exec',
    name: 'Hex-Encoded String Execution',
    description: 'Execution of hex-encoded or char-code-constructed strings',
    category: 'hidden_code',
    pattern: /(?:String\.fromCharCode|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}|\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,})/,
    severity: 'high',
    mitre: ['T1027', 'T1059'],
    remediation: 'Replace hex-encoded or charCode-constructed strings with readable text. Long sequences of encoded characters often hide malicious payloads.',
  },
  {
    id: 'soceng-hidden-proxy-trap',
    name: 'Proxy Handler Trap',
    description: 'Proxy object that intercepts property access to inject behavior',
    category: 'hidden_code',
    pattern: /new\s+Proxy\s*\(\s*[\w.]+\s*,\s*\{[\s\S]*?(?:get|set|apply|construct)\s*(?:\(|:)/,
    severity: 'medium',
    mitre: ['T1574'],
    remediation: 'Review Proxy handler traps. Proxy objects can silently intercept and modify object operations.',
  },
  {
    id: 'soceng-hidden-comment-encoded',
    name: 'Encoded Payload in Comments',
    description: 'Base64 or hex encoded data hidden in code comments',
    category: 'hidden_code',
    pattern: /(?:\/\/|\/\*|#)\s*(?:[A-Za-z0-9+/]{40,}={0,2}|(?:0x)?[0-9a-fA-F]{40,})/,
    severity: 'medium',
    mitre: ['T1027', 'T1564'],
    remediation: 'Inspect long encoded strings in comments. Comments should not contain base64 or hex payloads.',
  },
];

// ─── Unicode Tricks Patterns ───────────────────────────────────

const unicodeTricksPatterns: SocialEngPattern[] = [
  {
    id: 'soceng-unicode-bidi-override',
    name: 'Bidirectional Text Override',
    description: 'Unicode bidirectional override characters that reverse text display',
    category: 'unicode_tricks',
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/,
    severity: 'critical',
    mitre: ['T1036'],
    remediation: 'Remove Unicode bidirectional override characters. These can make code appear different from what is actually executed.',
  },
  {
    id: 'soceng-unicode-zero-width-sequence',
    name: 'Zero-Width Character Sequence',
    description: 'Sequences of invisible zero-width Unicode characters in code',
    category: 'unicode_tricks',
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/,
    severity: 'high',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove zero-width character sequences. These invisible characters can hide data or alter string comparisons.',
  },
  {
    id: 'soceng-unicode-homoglyph-latin',
    name: 'Cyrillic-Latin Homoglyph',
    description: 'Cyrillic characters used as visual lookalikes for Latin characters',
    category: 'unicode_tricks',
    pattern: /[\u0430\u0435\u043E\u0440\u0441\u0445\u0410\u0415\u041E\u0420\u0421\u0425][\w]*[\u0430\u0435\u043E\u0440\u0441\u0445\u0410\u0415\u041E\u0420\u0421\u0425]/,
    severity: 'high',
    mitre: ['T1036'],
    remediation: 'Replace Cyrillic homoglyphs with ASCII Latin equivalents. Mixed-script identifiers can disguise malicious code.',
  },
  {
    id: 'soceng-unicode-confusable-symbols',
    name: 'Confusable Math/Symbol Characters',
    description: 'Mathematical or symbol Unicode characters that look like ASCII operators',
    category: 'unicode_tricks',
    pattern: /[\uFF01-\uFF5E]|[\u2212\u2215\u2217\u2218\u2219\u2223\u2227\u2228\u2229\u222A]/,
    severity: 'medium',
    mitre: ['T1036'],
    remediation: 'Replace fullwidth or mathematical Unicode symbols with standard ASCII equivalents.',
  },
  {
    id: 'soceng-unicode-soft-hyphen',
    name: 'Soft Hyphen Injection',
    description: 'Soft hyphens (U+00AD) inserted into identifiers to evade pattern matching',
    category: 'unicode_tricks',
    pattern: /\w\u00AD\w/,
    severity: 'high',
    mitre: ['T1027', 'T1036'],
    remediation: 'Remove soft hyphens from identifiers. Soft hyphens are invisible in most renderers but alter string matching.',
  },
  {
    id: 'soceng-unicode-tag-chars',
    name: 'Unicode Tag Character Encoding',
    description: 'Unicode Tag block (U+E0001-E007F) used to encode hidden ASCII text',
    category: 'unicode_tricks',
    pattern: /[\uDB40][\uDC01-\uDC7F]/,
    severity: 'critical',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove Unicode Tag characters. This block can encode invisible ASCII text in supplementary plane characters.',
  },
];

// ─── Import Confusion Patterns ─────────────────────────────────

const importConfusionPatterns: SocialEngPattern[] = [
  {
    id: 'soceng-import-typosquat-common',
    name: 'Common Package Typosquat',
    description: 'Import of package with name similar to popular npm packages (transposition, missing char)',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`](?:loadsh|lodsah|loadash|lod-ash|requets|reqeust|axois|axos|axious|cryto|crpyto|crytpo|ract|raect|expresss|exprss|momnet|moemnt)['"`]/,
    severity: 'critical',
    mitre: ['T1195.002', 'T1204'],
    remediation: 'Verify this package name is correct. It closely resembles a popular package and may be a typosquatting attack.',
  },
  {
    id: 'soceng-import-scope-confusion',
    name: 'Scope Confusion Import',
    description: 'Import from a scope that mimics an official package scope',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`]@(?:angularjs|reactjs|vuejs|typscript|goggle|gooogle|mircosoft|microsft|amzon|awss|amazn)\//,
    severity: 'high',
    mitre: ['T1195.002'],
    remediation: 'Verify the package scope is correct. This scope closely resembles an official scope and may be dependency confusion.',
  },
  {
    id: 'soceng-import-internal-name-public',
    name: 'Internal Package Name on Public Registry',
    description: 'Import name following internal naming convention that could be claimed on public registry',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`](?:@internal\/|@private\/|@corp\/|@company\/|internal-|private-)[a-z0-9-]+['"`]/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Verify this internal-scoped package resolves to your private registry and not the public npm registry.',
  },
  {
    id: 'soceng-import-postinstall-url',
    name: 'Install Script URL Import',
    description: 'Import from URL or path suggesting post-install script execution',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`](?:https?:\/\/|ftp:\/\/|data:|blob:)/,
    severity: 'critical',
    mitre: ['T1059', 'T1195.002'],
    remediation: 'Remove URL-based imports. Code should be imported from local packages or verified registries, not raw URLs.',
  },
  {
    id: 'soceng-import-hyphen-underscore-swap',
    name: 'Hyphen-Underscore Package Swap',
    description: 'Import using hyphen/underscore variant of a popular package name',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`](?:child_process|child-process|node_fetch|node-fetch|cross_env|cross-env|dot_env|dot-env|type_script|type-script)['"`]/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Verify the exact package name. Hyphen/underscore variants may resolve to different (potentially malicious) packages.',
  },
  {
    id: 'soceng-import-version-suffix',
    name: 'Version Suffix Package',
    description: 'Import of package with version suffix that may be a different package entirely',
    category: 'import_confusion',
    pattern: /(?:import|require)\s*\(?['"`][a-z][a-z0-9-]*(?:-v\d+|-(?:latest|beta|alpha|next|canary|rc|nightly|dev|experimental))['"`]/,
    severity: 'medium',
    mitre: ['T1195.002'],
    remediation: 'Verify version-suffixed package names. Legitimate version selection should be in package.json, not in the import path.',
  },
];

// ─── Trojan Source Patterns ────────────────────────────────────

const trojanSourcePatterns: SocialEngPattern[] = [
  {
    id: 'soceng-trojan-bidi-in-string',
    name: 'Bidi Character in String Literal',
    description: 'Bidirectional control character inside a string literal (Trojan Source CVE-2021-42574)',
    category: 'trojan_source',
    pattern: /['"`][\s\S]*?[\u202A\u202B\u202D\u202E\u2066\u2067\u2068][\s\S]*?['"`]/,
    severity: 'critical',
    mitre: ['T1036'],
    remediation: 'Remove bidirectional control characters from string literals. This is a Trojan Source attack (CVE-2021-42574).',
  },
  {
    id: 'soceng-trojan-bidi-in-comment',
    name: 'Bidi Character in Comment',
    description: 'Bidirectional control character inside a code comment to reorder visible code',
    category: 'trojan_source',
    pattern: /(?:\/\/|\/\*|#)[\s\S]*?[\u202A\u202B\u202D\u202E\u2066\u2067\u2068]/,
    severity: 'critical',
    mitre: ['T1036'],
    remediation: 'Remove bidirectional control characters from comments. These can make code appear different from what is compiled.',
  },
  {
    id: 'soceng-trojan-homoglyph-identifier',
    name: 'Homoglyph in Identifier',
    description: 'Source code identifier containing mixed Latin and Cyrillic/Greek characters',
    category: 'trojan_source',
    pattern: /(?:function|class|const|let|var|type|interface)\s+[\w]*[\u0400-\u04FF\u0370-\u03FF][\w]*[\u0041-\u005A\u0061-\u007A]/,
    severity: 'critical',
    mitre: ['T1036'],
    remediation: 'Replace mixed-script identifiers with pure ASCII names. Homoglyph identifiers can shadow legitimate variables.',
  },
  {
    id: 'soceng-trojan-invisible-function-call',
    name: 'Invisible Function Call',
    description: 'Zero-width characters used between function name and parentheses',
    category: 'trojan_source',
    pattern: /\w[\u200B\u200C\u200D\u2060\uFEFF]+\(/,
    severity: 'critical',
    mitre: ['T1036', 'T1564'],
    remediation: 'Remove zero-width characters near function calls. These can create invisible function call redirections.',
  },
  {
    id: 'soceng-trojan-rtl-override-filename',
    name: 'RTL Override in Filename Reference',
    description: 'Right-to-left override in string that reverses displayed filename extension',
    category: 'trojan_source',
    pattern: /['"`][^'"`]*\u202E[^'"`]*\.(?:js|ts|py|rb|sh|exe|bat|cmd|ps1|vbs)[^'"`]*['"`]/,
    severity: 'critical',
    mitre: ['T1036'],
    remediation: 'Remove RTL override characters from file references. This can make a file appear to have a different extension.',
  },
  {
    id: 'soceng-trojan-combining-chars',
    name: 'Combining Character Abuse',
    description: 'Excessive combining diacritical marks used to obscure text',
    category: 'trojan_source',
    pattern: /[\u0300-\u036F]{3,}/,
    severity: 'medium',
    mitre: ['T1027'],
    remediation: 'Remove excessive combining diacritical marks. Stacked combining characters can obscure underlying text.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 30+ social engineering code patterns.
 *
 * Patterns are grouped by category for scanning. Each scanner module
 * filters patterns relevant to its detection scope.
 */
export const ALL_PATTERNS: readonly SocialEngPattern[] = [
  ...deceptiveNamingPatterns,
  ...hiddenCodePatterns,
  ...unicodeTricksPatterns,
  ...importConfusionPatterns,
  ...trojanSourcePatterns,
];

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: SocialEngCategory): SocialEngPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): SocialEngPattern[] {
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
export function getPatternCounts(): Record<SocialEngCategory, number> {
  const counts: Record<SocialEngCategory, number> = {
    deceptive_naming: 0,
    hidden_code: 0,
    unicode_tricks: 0,
    import_confusion: 0,
    trojan_source: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}

/**
 * SPEAR-03: Environment Variable Exfiltration -- Pattern Definitions
 *
 * Defines 35+ detection patterns across five categories:
 *
 *   - env_access        -- Dangerous process.env access and enumeration patterns
 *   - env_dump          -- Commands and code that dump all environment variables
 *   - exfil_url         -- Exfiltration of env data via HTTP URLs and webhooks
 *   - exfil_command     -- Exfiltration via shell commands (curl, wget, nc, etc.)
 *   - dotenv_exposure   -- .env file mishandling, accidental exposure, insecure loading
 *
 * MITRE ATT&CK references:
 *   T1552.001 -- Unsecured Credentials: Credentials In Files
 *   T1059     -- Command and Scripting Interpreter
 *   T1071     -- Application Layer Protocol
 *   T1567     -- Exfiltration Over Web Service
 *   T1082     -- System Information Discovery
 *   T1005     -- Data from Local System
 *   T1041     -- Exfiltration Over C2 Channel
 *   T1132     -- Data Encoding
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type EnvExfilCategory =
  | 'env_access'
  | 'env_dump'
  | 'exfil_url'
  | 'exfil_command'
  | 'dotenv_exposure';

export interface EnvExfilPattern {
  id: string;
  name: string;
  description: string;
  category: EnvExfilCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── Environment Access Patterns ────────────────────────────────

const envAccessPatterns: EnvExfilPattern[] = [
  {
    id: 'env-access-process-env-spread',
    name: 'Process.env Spread Operator',
    description: 'Spreading all of process.env into an object or function call',
    category: 'env_access',
    pattern: /\.\.\.process\.env\b/,
    severity: 'high',
    mitre: ['T1082', 'T1005'],
    remediation: 'Never spread process.env into objects. Access only specific, known environment variables.',
  },
  {
    id: 'env-access-process-env-keys',
    name: 'Process.env Key Enumeration',
    description: 'Enumerating all keys from process.env using Object.keys or Object.entries',
    category: 'env_access',
    pattern: /Object\.(?:keys|entries|values|getOwnPropertyNames)\s*\(\s*process\.env\s*\)/,
    severity: 'high',
    mitre: ['T1082', 'T1005'],
    remediation: 'Do not enumerate all environment variable keys. Access only specific variables by name.',
  },
  {
    id: 'env-access-process-env-json',
    name: 'Process.env JSON Serialization',
    description: 'Serializing the entire process.env to JSON',
    category: 'env_access',
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)/,
    severity: 'critical',
    mitre: ['T1005', 'T1567'],
    remediation: 'Never serialize the entire process.env object. This captures all secrets and credentials in a single string.',
  },
  {
    id: 'env-access-for-in-env',
    name: 'For-In Loop Over process.env',
    description: 'Iterating over all environment variables with a for-in loop',
    category: 'env_access',
    pattern: /for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+process\.env\s*\)/,
    severity: 'high',
    mitre: ['T1082'],
    remediation: 'Do not iterate over process.env. Access only the specific variables your application needs.',
  },
  {
    id: 'env-access-sensitive-var-pattern',
    name: 'Sensitive Environment Variable Access',
    description: 'Direct access to commonly sensitive environment variable names',
    category: 'env_access',
    pattern: /process\.env\s*\[\s*['"`](?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|DATABASE_URL|DB_PASSWORD|GITHUB_TOKEN|GH_TOKEN|SLACK_TOKEN|STRIPE_SECRET|PRIVATE_KEY|JWT_SECRET|ENCRYPTION_KEY|API_SECRET|MASTER_KEY|AUTH_SECRET)['"`]\s*\]/,
    severity: 'medium',
    mitre: ['T1552.001'],
    remediation: 'Ensure sensitive environment variables are accessed securely and never logged or exposed.',
  },
  {
    id: 'env-access-python-os-environ',
    name: 'Python os.environ Full Access',
    description: 'Accessing the entire os.environ dictionary in Python',
    category: 'env_access',
    pattern: /(?:dict\s*\(\s*os\.environ\s*\)|json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|os\.environ\.copy\s*\(\s*\))/,
    severity: 'high',
    mitre: ['T1082', 'T1005'],
    remediation: 'Do not copy or serialize the entire os.environ dictionary. Access only specific environment variables.',
  },
  {
    id: 'env-access-ruby-env-to-hash',
    name: 'Ruby ENV Full Dump',
    description: 'Converting the Ruby ENV object to a full hash or inspecting it',
    category: 'env_access',
    pattern: /ENV\.(?:to_h|to_a|inspect|each|map|select|reject)\b/,
    severity: 'high',
    mitre: ['T1082', 'T1005'],
    remediation: 'Do not enumerate or dump the full Ruby ENV. Access only specific variables by key.',
  },

  // ─── Environment Dump Patterns ──────────────────────────────────

  {
    id: 'env-dump-printenv',
    name: 'printenv/env Command',
    description: 'Shell command to dump all environment variables',
    category: 'env_dump',
    pattern: /(?:^|\s|[;|&`])(?:printenv|\/usr\/bin\/env\b|(?:^|\s)env\s*$|set\s*$|export\s+-p)\b/m,
    severity: 'high',
    mitre: ['T1082'],
    remediation: 'Remove commands that dump all environment variables. Use specific variable references instead.',
  },
  {
    id: 'env-dump-shell-env-vars',
    name: 'Shell Environment Dump via Subshell',
    description: 'Using subshell or backtick execution to capture environment variables',
    category: 'env_dump',
    pattern: /\$\((?:printenv|env|set)\)|`(?:printenv|env|set)`/,
    severity: 'high',
    mitre: ['T1082', 'T1059'],
    remediation: 'Remove subshell commands that capture all environment variables.',
  },
  {
    id: 'env-dump-proc-environ',
    name: '/proc/self/environ Access',
    description: 'Reading environment from /proc filesystem (Linux)',
    category: 'env_dump',
    pattern: /\/proc\/(?:self|\d+)\/environ/,
    severity: 'critical',
    mitre: ['T1005', 'T1082'],
    remediation: 'Do not read /proc/*/environ. This file contains all environment variables including secrets.',
  },
  {
    id: 'env-dump-child-process-env',
    name: 'Child Process Env Inheritance',
    description: 'Passing full process.env to child_process spawn/exec',
    category: 'env_dump',
    pattern: /(?:spawn|exec|execFile|fork|execSync|spawnSync)\s*\([^)]*\{\s*(?:env\s*:\s*(?:process\.env|\.\.\.process\.env|\{\s*\.\.\.process\.env))/,
    severity: 'medium',
    mitre: ['T1082'],
    remediation: 'Do not pass the entire process.env to child processes. Provide only required variables.',
  },
  {
    id: 'env-dump-docker-env-file',
    name: 'Docker --env-file with Secrets',
    description: 'Docker run command using --env-file that may expose all env vars',
    category: 'env_dump',
    pattern: /docker\s+run\s+[^;]*--env-file\s+(?:\.env|\.secret|credentials)/i,
    severity: 'high',
    mitre: ['T1552.001'],
    remediation: 'Do not pass full .env files to Docker containers. Use specific -e flags for required variables only.',
  },
  {
    id: 'env-dump-console-log-env',
    name: 'Console Log of Environment',
    description: 'Logging the entire process.env or os.environ to console/stdout',
    category: 'env_dump',
    pattern: /(?:console\.(?:log|info|debug|warn|error)|print(?:ln)?|puts|echo|logger\.(?:info|debug|warn|error))\s*\(\s*(?:process\.env|os\.environ|ENV)\s*\)/,
    severity: 'critical',
    mitre: ['T1005', 'T1082'],
    remediation: 'Never log the entire environment to console. This exposes all secrets in logs.',
  },

  // ─── Exfiltration via URL Patterns ──────────────────────────────

  {
    id: 'env-exfil-url-fetch-env',
    name: 'Fetch with Env Data in URL',
    description: 'HTTP fetch/request embedding environment variable data in URL parameters',
    category: 'exfil_url',
    pattern: /(?:fetch|axios\.(?:get|post)|http\.(?:get|request)|request\.(?:get|post)|got(?:\.(?:get|post))?)\s*\(\s*[`'"].*\$\{?\s*process\.env/,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Never embed environment variables in HTTP request URLs. This exfiltrates secrets to external servers.',
  },
  {
    id: 'env-exfil-url-query-param-leak',
    name: 'Env Data in Query Parameters',
    description: 'Environment variable values appended as URL query parameters',
    category: 'exfil_url',
    pattern: /(?:url|endpoint|href|src)\s*[=:]\s*[`'"]https?:\/\/[^`'"]*(?:\?|&)(?:key|token|secret|password|auth|api_key|access_token)\s*=\s*[`'"]\s*\+\s*(?:process\.env|os\.environ)/,
    severity: 'critical',
    mitre: ['T1567'],
    remediation: 'Never include secrets in URL query parameters. Use request headers or body for sensitive data.',
  },
  {
    id: 'env-exfil-url-webhook-post',
    name: 'Webhook POST with Env Data',
    description: 'Sending environment data to a webhook endpoint',
    category: 'exfil_url',
    pattern: /(?:webhook|callback|notify|slack|discord|teams)\s*(?:url|endpoint)?\s*[^;]*(?:process\.env|os\.environ|ENV\[)/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Never send environment variable data to webhook endpoints. This exfiltrates secrets to third-party services.',
  },
  {
    id: 'env-exfil-url-img-beacon',
    name: 'Image Beacon Exfiltration',
    description: 'Using image tags or pixel beacons to exfiltrate env data via URL',
    category: 'exfil_url',
    pattern: /(?:<img[^>]+src|new\s+Image\s*\(\s*\)\.src|document\.createElement\s*\(\s*['"`]img['"`]\s*\))\s*[=:]\s*[`'"].*(?:process\.env|\$\{.*(?:KEY|TOKEN|SECRET|PASSWORD))/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove image beacon exfiltration code. Embedding secrets in image src URLs leaks data via HTTP requests.',
  },
  {
    id: 'env-exfil-url-form-submit',
    name: 'Form Submission Exfiltration',
    description: 'Submitting env data via HTML form or FormData',
    category: 'exfil_url',
    pattern: /(?:FormData|URLSearchParams)\s*\([^)]*\)[\s\S]{0,200}(?:process\.env|\.env|secret|token|password)/i,
    severity: 'high',
    mitre: ['T1567'],
    remediation: 'Remove code that embeds environment secrets in form data submissions.',
  },
  {
    id: 'env-exfil-url-dns-exfil',
    name: 'DNS Exfiltration of Env Data',
    description: 'Encoding env data into DNS lookups for exfiltration',
    category: 'exfil_url',
    pattern: /(?:dns\.(?:resolve|lookup)|nslookup|dig)\s*[^;]*(?:process\.env|os\.environ|\$\{?\w*(?:SECRET|TOKEN|KEY|PASSWORD)\w*\}?)/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove DNS exfiltration code. Encoding secrets in DNS queries exfiltrates data through DNS lookups.',
  },

  // ─── Exfiltration via Command Patterns ──────────────────────────

  {
    id: 'env-exfil-cmd-curl-env',
    name: 'Curl with Env Data',
    description: 'Using curl to send environment variables to external servers',
    category: 'exfil_command',
    pattern: /curl\s+[^;]*(?:-d\s+[`'"]\$\{?(?:process\.env|ENV)|--data\s+[^;]*(?:process\.env|os\.environ)|[`'"].*process\.env)/,
    severity: 'critical',
    mitre: ['T1567', 'T1059'],
    remediation: 'Remove curl commands that send environment data externally. Secrets must not be exfiltrated via command-line tools.',
  },
  {
    id: 'env-exfil-cmd-wget-env',
    name: 'Wget with Env Data',
    description: 'Using wget to exfiltrate environment variables via URL',
    category: 'exfil_command',
    pattern: /wget\s+[^;]*(?:process\.env|\$\{?\w*(?:SECRET|TOKEN|KEY|PASSWORD)\w*\}?|os\.environ)/,
    severity: 'critical',
    mitre: ['T1567', 'T1059'],
    remediation: 'Remove wget commands that exfiltrate environment data.',
  },
  {
    id: 'env-exfil-cmd-netcat',
    name: 'Netcat Env Exfiltration',
    description: 'Using netcat/nc to pipe environment variables to a remote host',
    category: 'exfil_command',
    pattern: /(?:printenv|env|echo\s+\$\w+)\s*\|\s*(?:nc|ncat|netcat)\s+/,
    severity: 'critical',
    mitre: ['T1041', 'T1059'],
    remediation: 'Remove netcat commands that pipe environment data to remote hosts.',
  },
  {
    id: 'env-exfil-cmd-base64-pipe',
    name: 'Base64 Encoded Env Pipe',
    description: 'Encoding environment variables with base64 before transmitting',
    category: 'exfil_command',
    pattern: /(?:printenv|env|echo\s+\$\w+|process\.env)\s*\|\s*base64/,
    severity: 'high',
    mitre: ['T1132', 'T1567'],
    remediation: 'Remove base64 encoding pipelines for environment data. Base64 encoding before transmission is an exfiltration technique.',
  },
  {
    id: 'env-exfil-cmd-ssh-exfil',
    name: 'SSH Environment Exfiltration',
    description: 'Using SSH to send environment data to a remote server',
    category: 'exfil_command',
    pattern: /(?:printenv|env)\s*\|\s*ssh\s+|ssh\s+[^;]*[`'"]\s*(?:printenv|env|echo\s+\$)/,
    severity: 'critical',
    mitre: ['T1041', 'T1059'],
    remediation: 'Remove SSH commands that send environment data to remote hosts.',
  },
  {
    id: 'env-exfil-cmd-exec-env-in-script',
    name: 'Exec/Eval with Env Data',
    description: 'Using eval/exec to dynamically execute code containing env vars',
    category: 'exfil_command',
    pattern: /(?:eval|exec|execSync|Function)\s*\(\s*[`'"].*(?:process\.env|os\.environ|\$\{?\w*(?:SECRET|TOKEN|KEY)\w*\}?)/,
    severity: 'critical',
    mitre: ['T1059'],
    remediation: 'Never use eval/exec with environment variable data. This enables arbitrary code execution with secret values.',
  },
  {
    id: 'env-exfil-cmd-write-env-to-file',
    name: 'Write Env to File',
    description: 'Writing environment variables to a file that may be publicly accessible',
    category: 'exfil_command',
    pattern: /(?:writeFile(?:Sync)?|fs\.write|open\s*\([^)]*['"`]w['"`])\s*[^;]*(?:process\.env|JSON\.stringify\s*\(\s*process\.env|os\.environ)/,
    severity: 'high',
    mitre: ['T1005', 'T1552.001'],
    remediation: 'Do not write environment variables to files. Secrets should remain in memory and never be persisted to disk.',
  },

  // ─── Dotenv Exposure Patterns ───────────────────────────────────

  {
    id: 'env-dotenv-committed',
    name: '.env File in Version Control',
    description: 'Reference to .env file that may indicate it is committed to version control',
    category: 'dotenv_exposure',
    pattern: /(?:COPY|ADD)\s+\.env\b|\.env\s+\.env/,
    severity: 'critical',
    mitre: ['T1552.001'],
    remediation: 'Never commit .env files to version control or copy them into Docker images. Use Docker secrets or build args instead.',
  },
  {
    id: 'env-dotenv-public-dir',
    name: '.env in Public Directory',
    description: '.env file referenced in public/static directory',
    category: 'dotenv_exposure',
    pattern: /(?:public|static|www|htdocs|webroot|dist|build)\/\.env/,
    severity: 'critical',
    mitre: ['T1552.001'],
    remediation: 'Never place .env files in public-facing directories. They will be served to anyone who requests them.',
  },
  {
    id: 'env-dotenv-no-gitignore',
    name: 'Missing .env in .gitignore',
    description: 'Dockerfile or config referencing .env without ensuring .gitignore exclusion',
    category: 'dotenv_exposure',
    pattern: /dotenv\.config\s*\(\s*\{\s*path\s*:\s*['"`](?:\.\/)?\.env(?:\.(?:local|production|staging|development))?['"`]/,
    severity: 'medium',
    mitre: ['T1552.001'],
    remediation: 'Ensure .env files are in .gitignore and never committed. Verify dotenv config paths are gitignored.',
  },
  {
    id: 'env-dotenv-debug-mode',
    name: 'Dotenv Debug Mode',
    description: 'Dotenv loaded with debug mode enabled which logs all env values',
    category: 'dotenv_exposure',
    pattern: /dotenv\.config\s*\(\s*\{[^}]*debug\s*:\s*true/,
    severity: 'high',
    mitre: ['T1552.001'],
    remediation: 'Disable dotenv debug mode in production. Debug mode logs all environment variable values.',
  },
  {
    id: 'env-dotenv-hardcoded-secrets',
    name: 'Hardcoded Secrets in .env Template',
    description: 'Non-placeholder values for secrets in .env.example or .env.template',
    category: 'dotenv_exposure',
    pattern: /(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL)\s*=\s*['"`]?(?!(?:your_|changeme|xxx|placeholder|REPLACE_ME|TODO|<))[A-Za-z0-9+/=_-]{16,}/,
    severity: 'high',
    mitre: ['T1552.001'],
    remediation: 'Replace hardcoded secrets with placeholder values. Use "changeme" or "your_xxx_here" as placeholders.',
  },
  {
    id: 'env-dotenv-server-response',
    name: 'Env Vars in Server Response',
    description: 'Sending environment variables in HTTP response body',
    category: 'dotenv_exposure',
    pattern: /(?:res\.(?:json|send|write|end)|response\.(?:json|send|write))\s*\(\s*(?:process\.env|req\.env|\{\s*(?:\.\.\.process\.env|env\s*:\s*process\.env))/,
    severity: 'critical',
    mitre: ['T1005', 'T1567'],
    remediation: 'Never send environment variables in HTTP responses. This exposes all secrets to API consumers.',
  },
  {
    id: 'env-dotenv-template-exposure',
    name: 'Env Vars in Template/View',
    description: 'Environment variables passed to frontend templates or views',
    category: 'dotenv_exposure',
    pattern: /(?:window\.__ENV__|window\.ENV|globalThis\.env)\s*=\s*(?:process\.env|JSON\.parse)/,
    severity: 'high',
    mitre: ['T1005'],
    remediation: 'Do not expose process.env to frontend code. Only pass specific, non-sensitive configuration values.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 35+ environment variable exfiltration detection patterns.
 */
export const ALL_PATTERNS: readonly EnvExfilPattern[] = envAccessPatterns;

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: EnvExfilCategory): EnvExfilPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): EnvExfilPattern[] {
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
export function getPatternCounts(): Record<EnvExfilCategory, number> {
  const counts: Record<EnvExfilCategory, number> = {
    env_access: 0,
    env_dump: 0,
    exfil_url: 0,
    exfil_command: 0,
    dotenv_exposure: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}

/**
 * SPEAR-14: Network Recon & SSRF Tester Plugin
 *
 * Scans source code for Server-Side Request Forgery (SSRF) vulnerabilities
 * and network reconnaissance patterns that could allow attackers to access
 * internal services, cloud metadata endpoints, or exfiltrate data.
 *
 * Target files:
 *   - JavaScript/TypeScript: *.js, *.ts, *.jsx, *.tsx, *.mjs, *.cjs
 *   - Python: *.py
 *   - PHP: *.php
 *   - Ruby: *.rb
 *   - Go: *.go
 *   - Java: *.java
 *   - Configuration: *.yml, *.yaml, *.json, *.env
 *
 * Attack categories detected:
 *   - SSRF Sinks           -- Unvalidated URL inputs passed to HTTP clients
 *   - Internal IP Access   -- Hardcoded private/internal IP addresses
 *   - Metadata Access      -- Cloud provider metadata endpoint calls (AWS, GCP, Azure)
 *   - DNS Rebinding        -- DNS rebinding vulnerability patterns
 *   - URL Parsing          -- URL parsing flaws that enable SSRF bypass
 *
 * MITRE ATT&CK Techniques:
 *   - T1090     Proxy
 *   - T1190     Exploit Public-Facing Application
 *   - T1552     Unsecured Credentials
 *   - T1557     Adversary-in-the-Middle
 *   - T1567     Exfiltration Over Web Service
 *
 * This plugin requires only `fs:read` permission and no network access.
 * It is safe to run in both `safe` and `aggressive` modes.
 */

import { readFile } from 'node:fs/promises';
import { readdir, lstat } from 'node:fs/promises';
import { join, relative, resolve, extname } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';

import { ALL_SSRF_PATTERNS, getPatternCounts } from './patterns.js';
import type { SsrfPattern } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (2 MB). */
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

/** File extensions to scan for SSRF patterns. */
const TARGET_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.php', '.rb', '.go', '.java',
  '.yml', '.yaml', '.json', '.env',
]);

/** Directories to always skip during directory traversal. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.output',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  'target',
  '.turbo',
  'coverage',
  '.nyc_output',
]);

// ─── File Classification ───────────────────────────────────────

/**
 * Check if a file should be scanned for SSRF patterns based on extension.
 */
function isTargetFile(relativePath: string): boolean {
  const ext = extname(relativePath).toLowerCase();
  return TARGET_EXTENSIONS.has(ext);
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * SsrfTesterPlugin -- SPEAR-14 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects SSRF vulnerabilities and network recon patterns in source code.
 */
export class SsrfTesterPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'ssrf-tester',
    name: 'Network Recon & SSRF Tester',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans source code for SSRF vulnerabilities including unvalidated URL inputs, ' +
      'internal IP access, cloud metadata endpoint calls, DNS rebinding patterns, ' +
      'and URL parsing flaws that enable SSRF bypass.',
    severity: 'critical',
    tags: [
      'ssrf', 'network', 'recon', 'metadata', 'cloud',
      'dns-rebinding', 'url-parsing', 'internal-ip',
    ],
    references: [
      'CWE-918', 'CWE-441', 'CWE-611',
      'OWASP-A10', 'OWASP-SSRF',
    ],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log pattern statistics.
   */
  async setup(context: PluginContext): Promise<void> {
    const counts = getPatternCounts();
    const total = ALL_SSRF_PATTERNS.length;

    context.logger.info('SSRF tester initialized', {
      totalPatterns: total,
      ssrfSink: counts.ssrf_sink,
      internalIp: counts.internal_ip,
      metadataAccess: counts.metadata_access,
      dnsRebinding: counts.dns_rebinding,
      urlParsing: counts.url_parsing,
    });
  }

  /**
   * Scan: Walk directory for source code files, scan each for SSRF patterns.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;

    context.logger.info('Starting SSRF vulnerability scan', { rootDir });

    for await (const { absolutePath, relativePath } of walkSourceFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) {
          continue;
        }

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { file: relativePath });
          continue;
        }

        filesScanned++;

        for (const finding of this.scanContent(content, relativePath)) {
          findingsCount++;
          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('SSRF vulnerability scan complete', {
      filesScanned,
      findingsCount,
    });
  }

  /**
   * Scan file content against all SSRF patterns.
   */
  private *scanContent(
    content: string,
    filePath: string,
  ): Generator<Finding> {
    const lines = content.split('\n');

    for (const pattern of ALL_SSRF_PATTERNS) {
      if (pattern.pattern.test(content)) {
        let matchFound = false;

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
          const line = lines[lineIndex]!;
          if (pattern.pattern.test(line)) {
            matchFound = true;
            yield this.createFinding(pattern, filePath, lineIndex + 1);
          }
        }

        if (!matchFound) {
          yield this.createFinding(pattern, filePath, 1);
        }
      }
    }
  }

  /**
   * Create a Finding object from a matched pattern.
   */
  private createFinding(
    pattern: SsrfPattern,
    filePath: string,
    line: number,
  ): Finding {
    return {
      ruleId: pattern.id,
      severity: pattern.severity,
      message: `[SSRF/Network] ${pattern.name}: ${pattern.description}`,
      file: filePath,
      line,
      mitreTechniques: pattern.mitre,
      remediation: pattern.remediation,
      metadata: {
        pluginId: this.metadata.id,
        category: pattern.category,
        scanner: 'ssrf',
        patternName: pattern.name,
      },
    };
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up -- all patterns are stateless.
  }
}

// ─── Directory Walker ──────────────────────────────────────────

interface SourceFileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree and yield source code files.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 */
async function* walkSourceFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<SourceFileEntry> {
  const stack: string[] = [rootDir];

  while (stack.length > 0) {
    const currentDir = stack.pop()!;

    let entries: string[];
    try {
      entries = await readdir(currentDir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relativePath = relative(rootDir, fullPath);

      if (target.exclude && target.exclude.length > 0) {
        const matchesExclude = target.exclude.some((pattern) =>
          relativePath.includes(pattern) || entry === pattern,
        );
        if (matchesExclude) {
          continue;
        }
      }

      let entryStat;
      try {
        entryStat = await lstat(fullPath);
      } catch {
        continue;
      }

      if (entryStat.isSymbolicLink()) {
        continue;
      }

      if (entryStat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        if (isTargetFile(relativePath)) {
          yield {
            absolutePath: fullPath,
            relativePath,
          };
        }
      }
    }
  }
}

// ─── Utilities ─────────────────────────────────────────────────

/**
 * Read file content as UTF-8 string.
 * Returns null on any error (permissions, encoding, etc.).
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    return null;
  }
}

// ─── Default Export ────────────────────────────────────────────

export default new SsrfTesterPlugin();

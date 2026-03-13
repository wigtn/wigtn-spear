/**
 * SPEAR-03: Environment Variable Exfiltration Simulator
 *
 * Scans project files for patterns that indicate environment variable
 * exfiltration risks. Detects dangerous access patterns, env dumps,
 * exfiltration via URLs/webhooks, exfiltration via shell commands,
 * and .env file mishandling.
 *
 * Target files:
 *   - JavaScript/TypeScript source files
 *   - Python source files
 *   - Ruby source files
 *   - Shell scripts
 *   - Dockerfiles
 *   - Configuration files (.env, .env.example, docker-compose.yml)
 *
 * Attack categories detected:
 *   - env_access       -- Dangerous process.env access patterns
 *   - env_dump         -- Commands that dump all environment variables
 *   - exfil_url        -- Exfiltration via HTTP URLs and webhooks
 *   - exfil_command    -- Exfiltration via shell commands (curl, nc, etc.)
 *   - dotenv_exposure  -- .env file mishandling and exposure
 *
 * This plugin requires only `fs:read` permission and no network access.
 */

import { readFile } from 'node:fs/promises';
import { readdir, lstat } from 'node:fs/promises';
import { join, relative, resolve, extname, basename } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';

import { ALL_PATTERNS, getPatternCounts } from './patterns.js';
import type { EnvExfilPattern } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (512 KB). */
const MAX_FILE_SIZE_BYTES = 512 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

/** Directories to always skip during traversal. */
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

/** File extensions and names to scan. */
const SCANNABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js',
  '.ts',
  '.mjs',
  '.cjs',
  '.jsx',
  '.tsx',
  '.py',
  '.rb',
  '.sh',
  '.bash',
  '.zsh',
  '.yml',
  '.yaml',
  '.toml',
  '.json',
]);

/** Exact filenames to scan regardless of extension. */
const SCANNABLE_FILENAMES: ReadonlySet<string> = new Set([
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.env',
  '.env.local',
  '.env.example',
  '.env.template',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
  'Makefile',
  'Rakefile',
  'Gemfile',
]);

// ─── File Classification ──────────────────────────────────────

/**
 * Determine if a file should be scanned for env exfiltration patterns.
 */
function isScannableFile(relativePath: string): boolean {
  const ext = extname(relativePath).toLowerCase();
  const name = basename(relativePath);

  if (SCANNABLE_FILENAMES.has(name)) return true;
  if (SCANNABLE_EXTENSIONS.has(ext)) return true;
  if (name.startsWith('.env')) return true;

  return false;
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * EnvExfilPlugin -- SPEAR-03 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects environment variable exfiltration patterns in project source files.
 */
export class EnvExfilPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'env-exfil',
    name: 'Environment Variable Exfiltration Scanner',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans for environment variable exfiltration patterns including process.env access, env dumps, URL-based exfiltration, command-based exfiltration, and .env file exposure.',
    severity: 'high',
    tags: ['env', 'exfiltration', 'secrets', 'dotenv', 'credentials', 'process.env'],
    references: ['CWE-200', 'CWE-532', 'CWE-312', 'OWASP-A01'],
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
    const total = ALL_PATTERNS.length;

    context.logger.info('Env exfiltration scanner initialized', {
      totalPatterns: total,
      envAccess: counts.env_access,
      envDump: counts.env_dump,
      exfilUrl: counts.exfil_url,
      exfilCommand: counts.exfil_command,
      dotenvExposure: counts.dotenv_exposure,
    });
  }

  /**
   * Scan: Walk directory for source files, scan each for env exfiltration patterns.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;

    context.logger.info('Starting env exfiltration scan', { rootDir });

    for await (const { absolutePath, relativePath } of walkFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) continue;

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { file: relativePath });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning file for env exfiltration', { file: relativePath });

        for (const finding of scanContent(content, relativePath, this.metadata.id)) {
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

    context.logger.info('Env exfiltration scan complete', {
      filesScanned,
      findingsCount,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up.
  }
}

// ─── Content Scanner ──────────────────────────────────────────

/**
 * Scan file content against all env exfiltration patterns.
 */
function* scanContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of ALL_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield createFinding(pattern, filePath, lineIndex + 1, pluginId);
        }
      }

      if (!matchFound) {
        yield createFinding(pattern, filePath, 1, pluginId);
      }
    }
  }
}

/**
 * Create a Finding from a matched pattern.
 */
function createFinding(
  pattern: EnvExfilPattern,
  filePath: string,
  line: number,
  pluginId: string,
): Finding {
  return {
    ruleId: pattern.id,
    severity: pattern.severity,
    message: `[Env Exfil] ${pattern.name}: ${pattern.description}`,
    file: filePath,
    line,
    mitreTechniques: pattern.mitre,
    remediation: pattern.remediation,
    metadata: {
      pluginId,
      category: pattern.category,
      scanner: 'env-exfil',
      patternName: pattern.name,
    },
  };
}

// ─── Directory Walker ──────────────────────────────────────────

interface FileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree and yield scannable files.
 */
async function* walkFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<FileEntry> {
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
        const matchesExclude = target.exclude.some(
          (pattern) => relativePath.includes(pattern) || entry === pattern,
        );
        if (matchesExclude) continue;
      }

      let entryStat;
      try {
        entryStat = await lstat(fullPath);
      } catch {
        continue;
      }

      if (entryStat.isSymbolicLink()) continue;

      if (entryStat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        if (isScannableFile(relativePath)) {
          yield { absolutePath: fullPath, relativePath };
        }
      }
    }
  }
}

// ─── Utilities ─────────────────────────────────────────────────

/**
 * Read file content as UTF-8 string.
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    return null;
  }
}

// ─── Default Export ────────────────────────────────────────────

export default new EnvExfilPlugin();

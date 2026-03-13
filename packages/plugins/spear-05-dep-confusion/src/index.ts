/**
 * SPEAR-05: Dependency Confusion Checker
 *
 * Scans project dependency manifests for dependency confusion vulnerabilities.
 * Supports npm/yarn/pnpm (JavaScript) and pip (Python) ecosystems.
 *
 * Target files:
 *   - package.json, .npmrc, .yarnrc.yml      -- npm ecosystem
 *   - requirements.txt, setup.py, pyproject.toml -- Python ecosystem
 *   - Gemfile                                  -- Ruby ecosystem (basic)
 *
 * Attack categories detected:
 *   - missing_scope    -- Internal packages without organization scope
 *   - registry_config  -- Misconfigured or missing private registry settings
 *   - version_pinning  -- Risky version ranges that allow hijacking
 *   - name_squattable  -- Package names vulnerable to public registry squatting
 *   - manifest_risk    -- Dangerous patterns in dependency manifests
 *
 * This plugin requires only `fs:read` permission and no network access.
 */

import { readFile } from 'node:fs/promises';
import { readdir, lstat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';

import { ALL_PATTERNS, getPatternCounts } from './patterns.js';
import { isNpmFile, scanNpmContent } from './scanners/npm-scanner.js';
import { isPipFile, scanPipContent } from './scanners/pip-scanner.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (1 MB). */
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024;

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

// ─── File Classification ──────────────────────────────────────

type ScannerType = 'npm' | 'pip';

/**
 * Determine which scanner should process a given file.
 */
function classifyFile(relativePath: string): ScannerType | null {
  if (isNpmFile(relativePath)) return 'npm';
  if (isPipFile(relativePath)) return 'pip';
  return null;
}

/**
 * Dispatch file content to the appropriate scanner.
 */
function* dispatchScan(
  scannerType: ScannerType,
  content: string,
  relativePath: string,
  pluginId: string,
): Generator<Finding> {
  switch (scannerType) {
    case 'npm':
      yield* scanNpmContent(content, relativePath, pluginId);
      break;
    case 'pip':
      yield* scanPipContent(content, relativePath, pluginId);
      break;
  }
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * DepConfusionPlugin -- SPEAR-05 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects dependency confusion vulnerabilities in project manifest files.
 */
export class DepConfusionPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'dep-confusion',
    name: 'Dependency Confusion Checker',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans package manifests for dependency confusion risks including unscoped internal packages, registry misconfigurations, version pinning issues, and name squatting vulnerabilities.',
    severity: 'critical',
    tags: ['dependency', 'confusion', 'supply-chain', 'npm', 'pip', 'registry', 'squatting'],
    references: ['CWE-427', 'CWE-829', 'OWASP-A06'],
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

    context.logger.info('Dependency confusion checker initialized', {
      totalPatterns: total,
      missingScope: counts.missing_scope,
      registryConfig: counts.registry_config,
      versionPinning: counts.version_pinning,
      nameSquattable: counts.name_squattable,
      manifestRisk: counts.manifest_risk,
    });
  }

  /**
   * Scan: Walk directory for dependency manifests, scan each for confusion risks.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<ScannerType, number> = {
      npm: 0,
      pip: 0,
    };

    context.logger.info('Starting dependency confusion scan', { rootDir });

    for await (const { absolutePath, relativePath, scannerType } of walkDepFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) continue;

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large manifest file', { file: relativePath });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning dependency file', {
          file: relativePath,
          scanner: scannerType,
        });

        for (const finding of dispatchScan(scannerType, content, relativePath, this.metadata.id)) {
          findingsCount++;
          scannerHits[scannerType]++;
          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing dependency file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Dependency confusion scan complete', {
      filesScanned,
      findingsCount,
      scannerHits,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up.
  }
}

// ─── Directory Walker ──────────────────────────────────────────

interface DepFileEntry {
  absolutePath: string;
  relativePath: string;
  scannerType: ScannerType;
}

/**
 * Walk the directory tree and yield dependency manifest files.
 */
async function* walkDepFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<DepFileEntry> {
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
        const scannerType = classifyFile(relativePath);
        if (scannerType !== null) {
          yield { absolutePath: fullPath, relativePath, scannerType };
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

export default new DepConfusionPlugin();

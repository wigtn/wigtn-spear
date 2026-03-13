/**
 * SPEAR-08: Supply Chain Analyzer
 *
 * Scans project files for supply chain attack indicators in dependencies,
 * install scripts, lockfiles, and package metadata.
 *
 * Target files:
 *   - package.json           -- Scripts, dependencies, metadata analysis
 *   - package-lock.json      -- npm lockfile integrity checks
 *   - yarn.lock              -- Yarn lockfile integrity checks
 *   - pnpm-lock.yaml         -- pnpm lockfile integrity checks
 *   - JavaScript source files -- Obfuscation and malicious code patterns
 *
 * Attack categories detected:
 *   - postinstall_abuse  -- Dangerous install/postinstall script patterns
 *   - typosquat          -- Known typosquatting indicators and name patterns
 *   - maintainer_change  -- Indicators of suspicious maintainer/ownership changes
 *   - binary_download    -- Packages that download binaries at install time
 *   - obfuscation        -- Obfuscated code in package scripts or source
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
import { isScriptFile, scanScriptContent } from './scanners/script-analyzer.js';
import { isLockfile, scanLockfileContent } from './scanners/lockfile-scanner.js';
import type { SupplyChainPattern } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (2 MB -- lockfiles can be large). */
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

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

/** Source file extensions to scan for obfuscation patterns. */
const SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js',
  '.mjs',
  '.cjs',
]);

// ─── File Classification ──────────────────────────────────────

type ScannerType = 'script' | 'lockfile' | 'source';

/**
 * Determine which scanner should process a given file.
 */
function classifyFile(relativePath: string): ScannerType | null {
  if (isScriptFile(relativePath)) return 'script';
  if (isLockfile(relativePath)) return 'lockfile';

  const ext = extname(relativePath).toLowerCase();
  if (SOURCE_EXTENSIONS.has(ext)) return 'source';

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
    case 'script':
      yield* scanScriptContent(content, relativePath, pluginId);
      break;
    case 'lockfile':
      yield* scanLockfileContent(content, relativePath, pluginId);
      break;
    case 'source':
      yield* scanSourceContent(content, relativePath, pluginId);
      break;
  }
}

// ─── Source Content Scanner ───────────────────────────────────

/**
 * Scan JavaScript source files for obfuscation and supply chain patterns.
 */
function* scanSourceContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  // Apply all patterns (typosquat, obfuscation, binary download)
  for (const pattern of ALL_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield createFinding(pattern, filePath, lineIndex + 1, pluginId, 'source');
        }
      }

      if (!matchFound) {
        yield createFinding(pattern, filePath, 1, pluginId, 'source');
      }
    }
  }
}

/**
 * Create a Finding from a matched pattern.
 */
function createFinding(
  pattern: SupplyChainPattern,
  filePath: string,
  line: number,
  pluginId: string,
  scanner: string,
): Finding {
  return {
    ruleId: pattern.id,
    severity: pattern.severity,
    message: `[Supply Chain] ${pattern.name}: ${pattern.description}`,
    file: filePath,
    line,
    mitreTechniques: pattern.mitre,
    remediation: pattern.remediation,
    metadata: {
      pluginId,
      category: pattern.category,
      scanner,
      patternName: pattern.name,
    },
  };
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * SupplyChainPlugin -- SPEAR-08 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects supply chain attack indicators in dependencies and scripts.
 */
export class SupplyChainPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'supply-chain',
    name: 'Supply Chain Analyzer',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans for supply chain attack indicators including postinstall script abuse, typosquatting patterns, suspicious package characteristics, obfuscation, and binary downloads.',
    severity: 'critical',
    tags: ['supply-chain', 'postinstall', 'typosquat', 'obfuscation', 'lockfile', 'dependency'],
    references: ['CWE-829', 'CWE-506', 'CWE-494', 'OWASP-A06'],
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

    context.logger.info('Supply chain analyzer initialized', {
      totalPatterns: total,
      postinstallAbuse: counts.postinstall_abuse,
      typosquat: counts.typosquat,
      maintainerChange: counts.maintainer_change,
      binaryDownload: counts.binary_download,
      obfuscation: counts.obfuscation,
    });
  }

  /**
   * Scan: Walk directory for dependency and source files, scan for supply chain attacks.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<ScannerType, number> = {
      script: 0,
      lockfile: 0,
      source: 0,
    };

    context.logger.info('Starting supply chain analysis', { rootDir });

    for await (const { absolutePath, relativePath, scannerType } of walkFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) continue;

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { file: relativePath });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning file for supply chain indicators', {
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
        context.logger.warn('Error processing file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Supply chain analysis complete', {
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

interface FileEntry {
  absolutePath: string;
  relativePath: string;
  scannerType: ScannerType;
}

/**
 * Walk the directory tree and yield files relevant to supply chain analysis.
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

export default new SupplyChainPlugin();

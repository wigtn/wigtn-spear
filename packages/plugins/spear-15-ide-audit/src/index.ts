/**
 * SPEAR-15: IDE Extension Auditor Plugin
 *
 * Scans project directories for IDE extension configuration files and detects
 * security issues in VS Code extensions and JetBrains plugins that could
 * lead to code execution, data exfiltration, or privilege escalation.
 *
 * Target files:
 *   - .vscode/extensions.json          -- Recommended extensions list
 *   - package.json (with VS Code ext)  -- Extension manifest with permissions
 *   - plugin.xml                       -- JetBrains plugin descriptor
 *   - Extension source files           -- JS/TS files with suspicious patterns
 *
 * Attack categories detected:
 *   - Excessive permissions   -- Overly broad permission requests
 *   - Network access          -- Suspicious outbound network connections
 *   - Filesystem access       -- Reading credentials or system files
 *   - Code execution          -- Child process spawning, eval, dynamic loading
 *   - Data exfiltration       -- Reading workspace data and sending externally
 *
 * Architecture:
 *   - Uses an iterative directory walker (no recursion, no symlink following)
 *   - Each discovered file is dispatched to the VS Code scanner
 *   - Scanners check content against category-specific regex patterns
 *   - Findings are yielded via AsyncGenerator for streaming output
 *
 * This plugin requires only `fs:read` permission and no network access.
 * It is safe to run in both `safe` and `aggressive` modes.
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

import { isVscodeFile, scanVscodeContent } from './scanners/vscode-scanner.js';
import { ALL_IDE_PATTERNS, getPatternCounts, getPatternsForPlatform } from './patterns.js';
import type { IdePattern } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (2 MB). */
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

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

// ─── Scanner Type Dispatch ─────────────────────────────────────

type ScannerType = 'vscode' | 'jetbrains';

/**
 * Determine which scanner should process a given file.
 * Returns null if the file is not an IDE extension file.
 */
function classifyFile(relativePath: string): ScannerType | null {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = basename(normalized);

  // JetBrains plugin descriptor
  if (filename === 'plugin.xml') {
    return 'jetbrains';
  }

  // VS Code extension files
  if (isVscodeFile(relativePath)) {
    return 'vscode';
  }

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
    case 'vscode':
      yield* scanVscodeContent(content, relativePath, pluginId);
      break;
    case 'jetbrains':
      yield* scanJetBrainsContent(content, relativePath, pluginId);
      break;
  }
}

// ─── JetBrains Scanner (inline) ────────────────────────────────

/**
 * All patterns applicable to JetBrains plugins.
 */
const JETBRAINS_PATTERNS: readonly IdePattern[] = getPatternsForPlatform('jetbrains');

/**
 * Scan JetBrains plugin descriptor for security issues.
 */
function* scanJetBrainsContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of JETBRAINS_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[JetBrains Plugin] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'jetbrains',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[JetBrains Plugin] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'jetbrains',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * IdeAuditPlugin -- SPEAR-15 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects security issues in IDE extensions and plugins.
 */
export class IdeAuditPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'ide-audit',
    name: 'IDE Extension Auditor',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans VS Code extensions and JetBrains plugins for security issues including ' +
      'excessive permissions, suspicious network access, filesystem access to credentials, ' +
      'arbitrary code execution, and workspace data exfiltration.',
    severity: 'high',
    tags: [
      'ide', 'vscode', 'jetbrains', 'extension', 'plugin',
      'permission', 'exfiltration', 'code-execution',
    ],
    references: [
      'CWE-269', 'CWE-272', 'CWE-94',
      'OWASP-A01', 'OWASP-A06',
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
    const total = ALL_IDE_PATTERNS.length;

    context.logger.info('IDE extension auditor initialized', {
      totalPatterns: total,
      excessivePermission: counts.excessive_permission,
      networkAccess: counts.network_access,
      filesystemAccess: counts.filesystem_access,
      codeExecution: counts.code_execution,
      dataExfiltration: counts.data_exfiltration,
    });
  }

  /**
   * Scan: Walk directory for IDE extension files, scan each for security issues.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<ScannerType, number> = {
      vscode: 0,
      jetbrains: 0,
    };

    context.logger.info('Starting IDE extension security audit', { rootDir });

    for await (const { absolutePath, relativePath, scannerType } of walkIdeFiles(rootDir, target)) {
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
        context.logger.debug('Scanning IDE extension file', {
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
        context.logger.warn('Error processing IDE extension file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('IDE extension security audit complete', {
      filesScanned,
      findingsCount,
      scannerHits,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up -- all patterns are stateless.
  }
}

// ─── Directory Walker ──────────────────────────────────────────

interface IdeFileEntry {
  absolutePath: string;
  relativePath: string;
  scannerType: ScannerType;
}

/**
 * Walk the directory tree and yield IDE extension configuration files.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 */
async function* walkIdeFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<IdeFileEntry> {
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
        const scannerType = classifyFile(relativePath);

        if (scannerType !== null) {
          yield {
            absolutePath: fullPath,
            relativePath,
            scannerType,
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

export default new IdeAuditPlugin();

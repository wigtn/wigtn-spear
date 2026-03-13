/**
 * SPEAR-19: Social Engineering Code Analyzer
 *
 * Scans source code for social engineering patterns that trick developers
 * into trusting malicious code. Detects techniques that exploit human
 * cognitive biases in code review:
 *
 *   - Deceptive Naming     -- Functions named to disguise malicious intent
 *   - Hidden Code          -- Obfuscated eval, dynamic imports, prototype pollution
 *   - Unicode Tricks       -- Bidirectional text, homoglyphs, zero-width chars
 *   - Import Confusion     -- Typosquatting, dependency confusion in imports
 *   - Trojan Source        -- CVE-2021-42574 bidi attacks in source code
 *
 * Architecture:
 *   - Iterative directory walker (no recursion, no symlink following)
 *   - Regex-based pattern matching against 30+ social engineering indicators
 *   - Dedicated Unicode scanner for character-level inspection
 *   - Findings yielded via AsyncGenerator for streaming output
 *
 * This plugin requires only `fs:read` permission and no network access.
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

import {
  ALL_PATTERNS,
  getPatternCounts,
} from './patterns.js';

import {
  scanBidiCharacters,
  scanHomoglyphs,
  scanZeroWidthCharacters,
  unicodeFindingsToFindings,
} from './scanners/unicode-scanner.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (2 MB). */
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

/** Source code file extensions to scan. */
const SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.rb',
  '.go',
  '.rs',
  '.java', '.kt', '.kts',
  '.cs',
  '.php',
  '.sh', '.bash', '.zsh',
  '.c', '.cpp', '.cc', '.h', '.hpp',
  '.swift',
  '.scala',
  '.lua',
  '.pl', '.pm',
  '.r', '.R',
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
  '.tox',
  '.eggs',
  '.cache',
  '.parcel-cache',
]);

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * SocialEngPlugin -- SPEAR-19 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects social engineering patterns in source code files.
 */
export class SocialEngPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'social-eng',
    name: 'Social Engineering Code Analyzer',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans code for social engineering patterns: deceptive naming, hidden functionality, Unicode tricks, typosquatting imports, and Trojan Source attacks.',
    severity: 'high',
    tags: [
      'social-engineering', 'trojan-source', 'homoglyph', 'typosquatting',
      'unicode', 'obfuscation', 'supply-chain', 'code-review',
    ],
    references: [
      'CVE-2021-42574',
      'CVE-2021-42694',
      'CWE-1007',
      'CWE-176',
      'OWASP-LLM05',
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
    const total = ALL_PATTERNS.length;

    context.logger.info('Social engineering code analyzer initialized', {
      totalPatterns: total,
      deceptiveNaming: counts.deceptive_naming,
      hiddenCode: counts.hidden_code,
      unicodeTricks: counts.unicode_tricks,
      importConfusion: counts.import_confusion,
      trojanSource: counts.trojan_source,
    });
  }

  /**
   * Scan: Walk directory for source files, scan each for social engineering patterns.
   *
   * The scan process:
   *   1. Walk the project directory tree (iterative DFS)
   *   2. For each source file, read content
   *   3. Run regex-based pattern matching for all categories
   *   4. Run Unicode character-level scanner for bidi, homoglyph, zero-width
   *   5. Yield findings as they are discovered
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const categoryHits: Record<string, number> = {
      deceptive_naming: 0,
      hidden_code: 0,
      unicode_tricks: 0,
      import_confusion: 0,
      trojan_source: 0,
    };

    context.logger.info('Starting social engineering code scan', { rootDir });

    for await (const { absolutePath, relativePath } of walkSourceFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) {
          continue;
        }

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large source file', { file: relativePath });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning source file for social engineering patterns', {
          file: relativePath,
        });

        // Phase 1: Regex-based pattern matching
        for (const finding of scanWithPatterns(content, relativePath, this.metadata.id)) {
          findingsCount++;
          const cat = (finding.metadata?.['category'] as string) ?? 'unknown';
          if (cat in categoryHits) {
            categoryHits[cat]!++;
          }
          yield finding;
        }

        // Phase 2: Unicode character-level scanning
        for (const finding of scanUnicode(content, relativePath, this.metadata.id)) {
          findingsCount++;
          categoryHits['unicode_tricks']!++;
          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing source file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Social engineering code scan complete', {
      filesScanned,
      findingsCount,
      categoryHits,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // Stateless -- nothing to clean up.
  }
}

// ─── Pattern Scanner ───────────────────────────────────────────

/**
 * Scan file content against all social engineering regex patterns.
 */
function* scanWithPatterns(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of ALL_PATTERNS) {
    if (pattern.pattern.test(content)) {
      // Reset regex lastIndex for global regexes
      pattern.pattern.lastIndex = 0;

      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          pattern.pattern.lastIndex = 0;
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Social Eng] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'pattern-matcher',
              patternName: pattern.name,
            },
          };
        }
      }

      // Multi-line pattern matched full content but no individual line
      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Social Eng] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'pattern-matcher',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── Unicode Scanner Integration ───────────────────────────────

/**
 * Run the Unicode character-level scanner and yield findings.
 */
function* scanUnicode(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const bidiFindings = scanBidiCharacters(content);
  const homoglyphFindings = scanHomoglyphs(content);
  const zeroWidthFindings = scanZeroWidthCharacters(content);

  const allUnicodeFindings = [
    ...bidiFindings,
    ...homoglyphFindings,
    ...zeroWidthFindings,
  ];

  const converted = unicodeFindingsToFindings(allUnicodeFindings, filePath, pluginId);
  for (const finding of converted) {
    yield finding;
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

      // Check exclude patterns
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

      // Skip symlinks
      if (entryStat.isSymbolicLink()) {
        continue;
      }

      if (entryStat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        const ext = extname(entry).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext)) {
          yield { absolutePath: fullPath, relativePath };
        }
      }
    }
  }
}

// ─── Utilities ─────────────────────────────────────────────────

/**
 * Read file content as UTF-8 string.
 * Returns null on any error.
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    return null;
  }
}

// ─── Default Export ────────────────────────────────────────────

export default new SocialEngPlugin();

/**
 * .spearignore File Parser
 *
 * Loads and manages ignore patterns for the WIGTN-SPEAR scanner.
 * Uses the `ignore` package (gitignore-compatible pattern matching)
 * to determine which files and directories should be skipped during scans.
 *
 * Default ignores are always applied (node_modules, .git, dist, etc.).
 * Additional patterns can be loaded from a `.spearignore` file in the
 * project root.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Ignore } from 'ignore';
// Node16 CJS interop: ignore@5 has module.exports = function
// eslint-disable-next-line @typescript-eslint/no-require-imports
import ignoreDefault from 'ignore';
const ignore = ignoreDefault as unknown as (options?: { ignorecase?: boolean }) => Ignore;

/** The filename to look for in the project root */
const SPEARIGNORE_FILENAME = '.spearignore';

/**
 * Default ignore patterns that are always applied.
 *
 * These cover common directories and files that should never be scanned:
 * - Version control directories
 * - Package manager directories and lock files
 * - Build output directories
 * - Minified files (likely not containing real secrets)
 * - Binary-like asset directories
 * - IDE and editor directories
 * - OS-specific files
 */
const DEFAULT_IGNORES: readonly string[] = [
  // Version control
  '.git',
  '.svn',
  '.hg',

  // Package managers
  'node_modules',
  '.pnpm-store',
  'vendor',
  'bower_components',

  // Build output
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.output',
  '.turbo',
  '.vercel',

  // Minified files
  '*.min.js',
  '*.min.css',
  '*.bundle.js',
  '*.chunk.js',

  // Source maps
  '*.map',

  // Lock files (not secrets, just noise)
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'Gemfile.lock',
  'Cargo.lock',
  'poetry.lock',
  'composer.lock',

  // Binary / media assets
  '*.png',
  '*.jpg',
  '*.jpeg',
  '*.gif',
  '*.ico',
  '*.svg',
  '*.webp',
  '*.avif',
  '*.mp4',
  '*.mp3',
  '*.woff',
  '*.woff2',
  '*.ttf',
  '*.eot',
  '*.otf',
  '*.pdf',
  '*.zip',
  '*.tar',
  '*.gz',
  '*.bz2',
  '*.xz',
  '*.7z',
  '*.rar',

  // IDE and editor
  '.idea',
  '.vscode',
  '*.swp',
  '*.swo',
  '*~',
  '.DS_Store',

  // Coverage and test output
  'coverage',
  '.nyc_output',
  '__snapshots__',

  // Database files (scanned separately if needed)
  '*.db',
  '*.db-journal',
  '*.db-wal',
  '*.sqlite',
  '*.sqlite3',

  // SPEAR's own data directory
  '.spear',
];

/**
 * Load a spearignore instance configured with default and project-specific
 * ignore patterns.
 *
 * @param rootDir - The project root directory to search for .spearignore.
 * @returns An Ignore instance that can test file paths against patterns.
 *
 * @example
 * ```ts
 * const ig = loadSpearignore('/path/to/project');
 *
 * ig.ignores('node_modules/foo/bar.js')  // true (default ignore)
 * ig.ignores('src/app.ts')               // false (not ignored)
 * ig.ignores('secrets/test.txt')          // depends on .spearignore
 * ```
 */
export function loadSpearignore(rootDir: string): Ignore {
  const ig = ignore();

  // Always apply default ignores
  ig.add(DEFAULT_IGNORES as string[]);

  // Load project-specific .spearignore if it exists
  const spearignorePath = resolve(rootDir, SPEARIGNORE_FILENAME);

  if (existsSync(spearignorePath)) {
    try {
      const content = readFileSync(spearignorePath, 'utf-8');
      const lines = parseSpearignoreContent(content);
      if (lines.length > 0) {
        ig.add(lines);
      }
    } catch {
      // If we can't read the file, continue with defaults only.
      // This is non-fatal: we just won't have custom ignores.
    }
  }

  return ig;
}

/**
 * Parse the content of a .spearignore file into an array of patterns.
 *
 * Handles:
 * - Empty lines (skipped)
 * - Comment lines starting with # (skipped)
 * - Leading/trailing whitespace (trimmed)
 * - Inline comments are NOT supported (consistent with .gitignore)
 *
 * @param content - Raw file content of .spearignore.
 * @returns Array of non-empty, non-comment patterns.
 */
function parseSpearignoreContent(content: string): string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

/**
 * Get the list of default ignore patterns.
 * Useful for debugging or displaying the effective ignore list.
 */
export function getDefaultIgnores(): readonly string[] {
  return DEFAULT_IGNORES;
}

/**
 * Create a spearignore instance from explicit pattern arrays.
 * Useful for programmatic usage and testing.
 *
 * @param patterns - Additional patterns to add on top of defaults.
 * @param includeDefaults - Whether to include default ignores (default: true).
 * @returns An Ignore instance.
 */
export function createSpearignore(
  patterns: string[] = [],
  includeDefaults: boolean = true,
): Ignore {
  const ig = ignore();

  if (includeDefaults) {
    ig.add(DEFAULT_IGNORES as string[]);
  }

  if (patterns.length > 0) {
    ig.add(patterns);
  }

  return ig;
}

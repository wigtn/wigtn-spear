/**
 * File Walker -- Async directory traversal for the Secret Scanner plugin.
 *
 * Walks a directory tree yielding file paths that are eligible for scanning.
 * Respects ScanTarget include/exclude filters and skips binary files.
 *
 * Design decisions:
 *   - Uses an explicit stack (iterative DFS) instead of recursion to
 *     avoid stack overflow on deeply nested trees.
 *   - Symlinks are NOT followed to prevent infinite loops and directory
 *     escape attacks (CWE-59: Improper Link Resolution Before File Access).
 *   - Binary detection uses a fast heuristic: known binary extensions +
 *     null-byte probe in the first 8KB of the file.
 *   - File read errors are silently skipped (non-fatal).
 */

import { readdir, stat, lstat, open } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import type { ScanTarget } from '@wigtn/shared';
import type { Ignore } from 'ignore';

/**
 * Known binary file extensions.
 *
 * Files with these extensions are skipped without reading content.
 * This is a performance optimization to avoid unnecessary I/O for
 * files that will never contain text-based secrets.
 */
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  // Compiled / executables
  '.exe', '.dll', '.so', '.dylib', '.o', '.obj', '.a', '.lib',
  '.class', '.pyc', '.pyo', '.wasm',
  // Archives
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.zst',
  '.jar', '.war', '.ear', '.apk', '.ipa', '.deb', '.rpm',
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.avif', '.tiff', '.tif', '.psd', '.heic', '.heif',
  // Audio / Video
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
  '.wav', '.flac', '.aac', '.ogg', '.m4a',
  // Fonts
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  // Documents (binary)
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  // Database files
  '.db', '.sqlite', '.sqlite3', '.db-journal', '.db-wal',
  // Other binary
  '.bin', '.dat', '.img', '.iso', '.dmg',
]);

/**
 * Maximum file size to read for binary detection probe (8 KB).
 * Reading only the head avoids loading large files into memory.
 */
const BINARY_PROBE_SIZE = 8192;

/**
 * Walk a directory tree, yielding absolute file paths eligible for scanning.
 *
 * @param rootDir - The root directory to start walking from.
 * @param spearignore - An Ignore instance for .spearignore pattern matching.
 * @param target - The ScanTarget containing include/exclude patterns.
 * @yields Absolute file paths that pass all filters.
 */
export async function* walkFiles(
  rootDir: string,
  spearignore: Ignore,
  target: ScanTarget,
): AsyncGenerator<string> {
  const stack: string[] = [rootDir];

  while (stack.length > 0) {
    const currentDir = stack.pop()!;

    let entries: string[];
    try {
      entries = await readdir(currentDir);
    } catch {
      // Permission denied or directory disappeared; skip silently
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relativePath = relative(rootDir, fullPath);

      // Check spearignore before stat to skip entire ignored subtrees
      if (spearignore.ignores(relativePath)) {
        continue;
      }

      // Use lstat (not stat) to detect symlinks without following them
      let entryStat;
      try {
        entryStat = await lstat(fullPath);
      } catch {
        // Broken path or permission denied; skip
        continue;
      }

      // Skip symlinks entirely to prevent traversal attacks and infinite loops
      if (entryStat.isSymbolicLink()) {
        continue;
      }

      if (entryStat.isDirectory()) {
        // Also check directory with trailing slash convention
        if (spearignore.ignores(relativePath + '/')) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        // Apply include filter: if specified, file must match at least one pattern
        if (target.include && target.include.length > 0) {
          const matchesInclude = target.include.some((pattern) =>
            matchSimpleGlob(relativePath, pattern),
          );
          if (!matchesInclude) {
            continue;
          }
        }

        // Apply exclude filter
        if (target.exclude && target.exclude.length > 0) {
          const matchesExclude = target.exclude.some((pattern) =>
            matchSimpleGlob(relativePath, pattern),
          );
          if (matchesExclude) {
            continue;
          }
        }

        // Skip known binary extensions (fast path)
        const ext = extname(entry).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) {
          continue;
        }

        // Skip files that look binary based on content probe
        const isBinary = await isBinaryFile(fullPath);
        if (isBinary) {
          continue;
        }

        yield fullPath;
      }
    }
  }
}

/**
 * Probe the first bytes of a file to detect binary content.
 *
 * A file is considered binary if it contains a null byte (0x00) in the
 * first BINARY_PROBE_SIZE bytes. This is the same heuristic used by
 * git and many other tools.
 *
 * @param filePath - Absolute path to the file.
 * @returns true if the file appears to be binary.
 */
async function isBinaryFile(filePath: string): Promise<boolean> {
  let fileHandle;
  try {
    fileHandle = await open(filePath, 'r');
    const buffer = Buffer.alloc(BINARY_PROBE_SIZE);
    const { bytesRead } = await fileHandle.read(buffer, 0, BINARY_PROBE_SIZE, 0);

    if (bytesRead === 0) {
      return false; // Empty file is not binary
    }

    // Check for null bytes in the sample
    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0x00) {
        return true;
      }
    }

    return false;
  } catch {
    // If we can't read it, treat as binary (skip it)
    return true;
  } finally {
    await fileHandle?.close();
  }
}

/**
 * Simple glob matching for include/exclude patterns.
 *
 * Consistent with the matchGlob implementation in @wigtn/core pipeline.ts.
 * Supports: '*' (non-separator), '**' (any), '?' (single char), literal equality.
 */
function matchSimpleGlob(filepath: string, pattern: string): boolean {
  if (filepath === pattern) return true;

  let regexStr = '^';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i]!;

    if (ch === '*') {
      if (i + 1 < pattern.length && pattern[i + 1] === '*') {
        regexStr += '.*';
        i += 2;
        if (i < pattern.length && pattern[i] === '/') {
          i++;
        }
        continue;
      }
      regexStr += '[^/]*';
    } else if (ch === '?') {
      regexStr += '[^/]';
    } else if (ch === '.') {
      regexStr += '\\.';
    } else if (
      ch === '(' || ch === ')' || ch === '[' || ch === ']' ||
      ch === '{' || ch === '}' || ch === '+' || ch === '^' ||
      ch === '$' || ch === '|' || ch === '\\'
    ) {
      regexStr += '\\' + ch;
    } else {
      regexStr += ch;
    }
    i++;
  }

  regexStr += '$';

  try {
    return new RegExp(regexStr).test(filepath);
  } catch {
    return filepath.includes(pattern);
  }
}

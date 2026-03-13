/**
 * SPEAR-18: URL Extractor
 *
 * Extracts HTTPS/WSS endpoints from source code, configuration files,
 * and environment files using regex pattern matching.
 *
 * This runs in SAFE mode -- no network connections are made.
 */

import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';

// ─── Types ─────────────────────────────────────────────────────

export interface ExtractedEndpoint {
  url: string;
  file: string;
  line: number;
  source: 'url-literal' | 'env-variable' | 'config-value';
}

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (1 MB). */
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024;

/** File extensions to scan for URLs. */
const TARGET_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.php',
  '.json', '.yaml', '.yml', '.toml', '.ini',
  '.env', '.cfg', '.conf', '.properties',
  '.xml', '.html', '.htm',
  '.sh', '.bash', '.zsh',
  '.tf', '.hcl',
  '.dockerfile',
]);

/** Directories to skip during traversal. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules', '.git', 'dist', 'build', 'out',
  '.next', '.nuxt', '.output', '__pycache__',
  '.venv', 'venv', 'vendor', 'target',
  '.turbo', 'coverage', '.nyc_output',
]);

// ─── URL Patterns ──────────────────────────────────────────────

/**
 * Patterns to extract URLs from source code.
 * Each pattern captures the full URL in group 1 or the full match.
 */
const URL_PATTERNS: ReadonlyArray<{ pattern: RegExp; source: ExtractedEndpoint['source'] }> = [
  // HTTPS URLs in strings or bare
  {
    pattern: /https:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d{1,5})?(?:\/[^\s'"`)}\]>]*)?/g,
    source: 'url-literal',
  },
  // WSS (WebSocket Secure) URLs
  {
    pattern: /wss:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d{1,5})?(?:\/[^\s'"`)}\]>]*)?/g,
    source: 'url-literal',
  },
  // Environment variable assignments with URLs
  {
    pattern: /(?:^|\n)\s*[A-Z_][A-Z0-9_]*(?:_URL|_ENDPOINT|_HOST|_API|_URI|_BASE|_SERVER)\s*=\s*['"]?(https?:\/\/[^\s'"]+)/g,
    source: 'env-variable',
  },
  // JSON/YAML config values with URLs
  {
    pattern: /["']?\s*(?:url|endpoint|host|api|uri|base_url|baseUrl|server|origin|domain|webhook)\s*["']?\s*[:=]\s*["'](https?:\/\/[^"'\s]+)/gi,
    source: 'config-value',
  },
];

// ─── URL Normalization ─────────────────────────────────────────

/**
 * Normalize a URL by removing trailing punctuation and query parameters
 * that are likely part of surrounding text rather than the URL itself.
 */
function normalizeUrl(raw: string): string {
  // Remove trailing punctuation that is likely not part of URL
  let url = raw.replace(/[,;:.!?)}\]>]+$/, '');
  // Remove trailing quotes
  url = url.replace(/['"`]+$/, '');
  return url;
}

/**
 * Extract just the origin (scheme + host + optional port) from a URL.
 */
function extractOrigin(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch {
    // Fallback: extract scheme://host[:port]
    const match = url.match(/^(https?:\/\/[^/?#]+)/i)
      ?? url.match(/^(wss?:\/\/[^/?#]+)/i);
    return match ? match[1]! : url;
  }
}

// ─── File Walker ───────────────────────────────────────────────

interface FileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree yielding scannable files.
 * Iterative DFS, does not follow symlinks.
 */
async function* walkFiles(rootDir: string, exclude: string[]): AsyncGenerator<FileEntry> {
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

      // Check user excludes
      const matchesExclude = exclude.some(
        (pattern) => relativePath.includes(pattern) || entry === pattern,
      );
      if (matchesExclude) {
        continue;
      }

      let stat;
      try {
        stat = await lstat(fullPath);
      } catch {
        continue;
      }

      if (stat.isSymbolicLink()) {
        continue;
      }

      if (stat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) {
          continue;
        }
        stack.push(fullPath);
      } else if (stat.isFile()) {
        const ext = extname(entry).toLowerCase();
        // Also include extensionless dotfiles like .env
        if (TARGET_EXTENSIONS.has(ext) || entry.startsWith('.env') || entry === 'Dockerfile') {
          yield { absolutePath: fullPath, relativePath };
        }
      }
    }
  }
}

// ─── Extractor ─────────────────────────────────────────────────

/**
 * Extract all HTTPS/WSS endpoints from source code under the given root directory.
 *
 * Returns deduplicated endpoints with file and line information.
 */
export async function extractEndpoints(
  rootDir: string,
  exclude: string[] = [],
): Promise<ExtractedEndpoint[]> {
  const endpoints: ExtractedEndpoint[] = [];
  const seenUrls = new Set<string>();

  for await (const { absolutePath, relativePath } of walkFiles(rootDir, exclude)) {
    let content: string;
    try {
      content = await readFile(absolutePath, 'utf-8');
    } catch {
      continue;
    }

    if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
      continue;
    }

    const lines = content.split('\n');

    for (const { pattern, source } of URL_PATTERNS) {
      // Reset the regex (global flag)
      pattern.lastIndex = 0;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.exec(line)) !== null) {
          // Use first capture group if present, otherwise full match
          const rawUrl = match[1] ?? match[0];
          const url = normalizeUrl(rawUrl);

          // Only keep HTTPS and WSS
          if (!url.startsWith('https://') && !url.startsWith('wss://')) {
            continue;
          }

          // Skip obvious placeholders and documentation URLs
          if (isPlaceholderUrl(url)) {
            continue;
          }

          const origin = extractOrigin(url);
          const dedupeKey = `${origin}::${relativePath}`;

          if (!seenUrls.has(dedupeKey)) {
            seenUrls.add(dedupeKey);
            endpoints.push({
              url: origin,
              file: relativePath,
              line: lineIndex + 1,
              source,
            });
          }
        }
      }
    }
  }

  return endpoints;
}

/**
 * Get unique origins from extracted endpoints.
 */
export function getUniqueOrigins(endpoints: ExtractedEndpoint[]): string[] {
  const origins = new Set<string>();
  for (const ep of endpoints) {
    origins.add(ep.url);
  }
  return [...origins];
}

// ─── Helpers ───────────────────────────────────────────────────

/**
 * Check if a URL is a placeholder or documentation example.
 */
function isPlaceholderUrl(url: string): boolean {
  const lower = url.toLowerCase();
  return (
    lower.includes('example.com') ||
    lower.includes('example.org') ||
    lower.includes('localhost') ||
    lower.includes('127.0.0.1') ||
    lower.includes('placeholder') ||
    lower.includes('your-domain') ||
    lower.includes('your-app') ||
    lower.includes('xxx') ||
    lower.includes('todo') ||
    lower.includes('schema.org') ||
    lower.includes('w3.org') ||
    lower.includes('json-schema.org') ||
    lower.includes('schemas.microsoft.com') ||
    lower.includes('www.w3.org') ||
    lower.includes('xmlns') ||
    lower.includes('purl.org')
  );
}

/**
 * SPEAR-22: Infrastructure Intelligence Extractor Plugin
 *
 * Extracts ALL useful infrastructure information from source code to build
 * a comprehensive intelligence map of the target project:
 *
 *   1. Cloud Infrastructure Intel  -- GCP, AWS, Azure, Docker, Terraform, Serverless
 *   2. API Endpoint Mapping        -- Next.js, Express, Fastify, fetch/axios, WebSocket, GraphQL
 *   3. Secret Names Inventory      -- env vars, CI/CD secrets, process.env, cloud secret managers
 *   4. Service Topology            -- external APIs, databases, message queues, inter-service comms
 *   5. Authentication Flow         -- OAuth, OIDC, Firebase Auth, JWT, session management
 *
 * Architecture:
 *   - Uses an iterative DFS directory walker (no recursion, no symlink following)
 *   - Each file is classified and dispatched to appropriate extractors
 *   - Extractors are generator functions yielding Finding objects
 *   - All findings are severity 'info' -- this is an intelligence module, not a scanner
 *
 * The value is in AGGREGATING all infrastructure knowledge from the codebase
 * into a single unified view that other analysis tools can consume.
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

import { extractCicd } from './extractors/cicd-extractor.js';
import { extractEndpoints } from './extractors/endpoint-extractor.js';
import { extractSecretNames } from './extractors/secret-name-extractor.js';
import { extractTopology } from './extractors/topology-extractor.js';

// ─── Constants ─────────────────────────────────────────────────────

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
  '.cache',
  '.parcel-cache',
  '.webpack',
  'bower_components',
  '.terraform',
]);

// ─── File Classification ────────────────────────────────────────────

/** File categories that determine which extractors to run. */
type FileCategory =
  | 'cicd'
  | 'dockerfile'
  | 'docker_compose'
  | 'terraform'
  | 'serverless'
  | 'source_code'
  | 'env_example'
  | 'config';

/**
 * Classify a file by its path and extension to determine which extractors apply.
 *
 * A file can belong to multiple categories (e.g., a CI/CD file also contains
 * secret references, so both cicd and secret extractors should run).
 */
function classifyFile(relativePath: string): FileCategory[] {
  const normalized = relativePath.replace(/\\/g, '/').toLowerCase();
  const fileName = basename(normalized);
  const ext = extname(normalized);
  const categories: FileCategory[] = [];

  // CI/CD configuration files
  if (
    normalized.includes('.github/workflows/') ||
    normalized.includes('.gitlab-ci') ||
    normalized.includes('.circleci/') ||
    normalized.includes('azure-pipelines') ||
    normalized.includes('bitbucket-pipelines') ||
    fileName === 'jenkinsfile' ||
    fileName === 'cloudbuild.yaml' ||
    fileName === 'cloudbuild.yml' ||
    fileName === 'buildspec.yml' ||
    fileName === 'buildspec.yaml' ||
    fileName === 'appspec.yml' ||
    fileName === 'appspec.yaml'
  ) {
    categories.push('cicd');
  }

  // Dockerfiles
  if (
    /^dockerfile/i.test(fileName) ||
    /^containerfile/i.test(fileName) ||
    fileName.startsWith('dockerfile.')
  ) {
    categories.push('dockerfile');
  }

  // Docker Compose files
  if (
    fileName === 'docker-compose.yml' ||
    fileName === 'docker-compose.yaml' ||
    fileName === 'compose.yml' ||
    fileName === 'compose.yaml' ||
    fileName.startsWith('docker-compose.')
  ) {
    categories.push('docker_compose');
  }

  // Terraform files
  if (ext === '.tf' || ext === '.tfvars') {
    categories.push('terraform');
  }

  // Serverless Framework
  if (
    fileName === 'serverless.yml' ||
    fileName === 'serverless.yaml' ||
    fileName === 'serverless.ts' ||
    fileName === 'serverless.js'
  ) {
    categories.push('serverless');
  }

  // Source code files (for endpoint, process.env, topology extraction)
  if (
    ext === '.ts' ||
    ext === '.tsx' ||
    ext === '.js' ||
    ext === '.jsx' ||
    ext === '.mjs' ||
    ext === '.cjs' ||
    ext === '.py' ||
    ext === '.vue' ||
    ext === '.svelte' ||
    ext === '.go' ||
    ext === '.rb' ||
    ext === '.java' ||
    ext === '.kt' ||
    ext === '.rs'
  ) {
    categories.push('source_code');
  }

  // Environment example files
  if (
    fileName.endsWith('.env.example') ||
    fileName.endsWith('.env.sample') ||
    fileName.endsWith('.env.template') ||
    fileName === '.env.development' ||
    fileName === '.env.production' ||
    fileName === '.env.staging' ||
    fileName === '.env.test' ||
    fileName === '.env.local.example'
  ) {
    categories.push('env_example');
  }

  // Configuration files (YAML/JSON configs that may contain infra info)
  if (
    (ext === '.yml' || ext === '.yaml' || ext === '.json' || ext === '.toml') &&
    categories.length === 0
  ) {
    categories.push('config');
  }

  return categories;
}

/**
 * Determine if a file should be scanned by any extractor.
 */
function isRelevantFile(relativePath: string): boolean {
  return classifyFile(relativePath).length > 0;
}

// ─── Extractor Dispatch ─────────────────────────────────────────────

/**
 * Dispatch file content to appropriate extractors based on file categories.
 *
 * Each extractor is a generator function that yields Finding objects.
 * A file can be dispatched to multiple extractors if it matches
 * multiple categories.
 */
function* dispatchExtractors(
  content: string,
  relativePath: string,
  categories: FileCategory[],
  pluginId: string,
): Generator<Finding> {
  const categorySet = new Set(categories);

  // CI/CD extractor -- handles GCP, AWS, Azure, Docker, Terraform, Serverless
  if (
    categorySet.has('cicd') ||
    categorySet.has('dockerfile') ||
    categorySet.has('docker_compose') ||
    categorySet.has('terraform') ||
    categorySet.has('serverless')
  ) {
    yield* extractCicd(content, relativePath, pluginId);
  }

  // Endpoint extractor -- handles API routes, fetch calls, WebSocket, GraphQL
  if (categorySet.has('source_code')) {
    yield* extractEndpoints(content, relativePath, pluginId);
  }

  // Secret name extractor -- handles all file types
  yield* extractSecretNames(content, relativePath, pluginId);

  // Topology extractor -- handles source code and config files
  if (
    categorySet.has('source_code') ||
    categorySet.has('config') ||
    categorySet.has('cicd')
  ) {
    yield* extractTopology(content, relativePath, pluginId);
  }
}

// ─── Plugin Implementation ──────────────────────────────────────────

/**
 * InfraIntelPlugin -- SPEAR-22 Intelligence Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Extracts all useful infrastructure information from source code
 * to build a comprehensive intelligence map of the target project.
 */
export class InfraIntelPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'infra-intel',
    name: 'Infrastructure Intelligence Extractor',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Extracts infrastructure intelligence from source code including cloud configs, ' +
      'API endpoints, secret names, service topology, and authentication flows. ' +
      'Builds a comprehensive map of the target project\'s infrastructure.',
    severity: 'info',
    tags: [
      'infrastructure', 'intelligence', 'cloud', 'api', 'secrets',
      'topology', 'authentication', 'gcp', 'aws', 'azure', 'docker',
      'terraform', 'serverless', 'endpoints', 'cicd',
    ],
    references: [
      'MITRE-ATT&CK-T1580',
      'MITRE-ATT&CK-T1526',
      'MITRE-ATT&CK-T1538',
    ],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log initialization. No heavy setup required for this plugin.
   */
  async setup(context: PluginContext): Promise<void> {
    context.logger.info('Infrastructure Intelligence Extractor initialized', {
      extractors: ['cicd', 'endpoints', 'secret-names', 'topology'],
    });
  }

  /**
   * Scan: Walk directory for relevant files, extract infrastructure intelligence.
   *
   * Uses an iterative DFS walker to traverse the directory tree.
   * Each file is classified and dispatched to appropriate extractors.
   * Findings are yielded via AsyncGenerator for streaming output.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const categoryCounts: Record<string, number> = {};

    context.logger.info('Starting infrastructure intelligence extraction', { rootDir });

    for await (const entry of walkRelevantFiles(rootDir, target)) {
      try {
        const content = await readFileContent(entry.absolutePath);
        if (content === null) {
          continue;
        }

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { file: entry.relativePath });
          continue;
        }

        filesScanned++;

        context.logger.debug('Extracting infrastructure intel', {
          file: entry.relativePath,
          categories: entry.categories,
        });

        for (const finding of dispatchExtractors(
          content,
          entry.relativePath,
          entry.categories,
          this.metadata.id,
        )) {
          findingsCount++;

          // Track category counts for summary
          const category = (finding.metadata?.category as string) ?? 'unknown';
          categoryCounts[category] = (categoryCounts[category] ?? 0) + 1;

          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error extracting infrastructure intel from file, skipping', {
          file: entry.relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Infrastructure intelligence extraction complete', {
      filesScanned,
      findingsCount,
      categoryCounts,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up -- all extractors are stateless.
  }
}

// ─── Directory Walker ──────────────────────────────────────────────

interface FileEntry {
  absolutePath: string;
  relativePath: string;
  categories: FileCategory[];
}

/**
 * Walk the directory tree and yield files relevant to infrastructure extraction.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 */
async function* walkRelevantFiles(
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
      // Permission denied or directory deleted -- skip silently
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relativePath = relative(rootDir, fullPath);

      // Apply exclude patterns from target
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
        // Stat failed -- skip silently
        continue;
      }

      // Never follow symlinks
      if (entryStat.isSymbolicLink()) {
        continue;
      }

      if (entryStat.isDirectory()) {
        // Skip known non-useful directories
        if (SKIP_DIRS.has(entry)) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        // Classify and check if relevant
        const categories = classifyFile(relativePath);

        if (categories.length > 0) {
          yield {
            absolutePath: fullPath,
            relativePath,
            categories,
          };
        }
      }
    }
  }
}

// ─── Utilities ─────────────────────────────────────────────────────

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

// ─── Default Export ────────────────────────────────────────────────

export default new InfraIntelPlugin();

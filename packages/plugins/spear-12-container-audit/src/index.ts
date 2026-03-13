/**
 * SPEAR-12: Container Security Auditor Plugin
 *
 * Scans project directories for container configuration files and detects
 * security misconfigurations that could lead to container escape, privilege
 * escalation, or data exposure.
 *
 * Target files:
 *   - Dockerfile, Dockerfile.*, Containerfile   -- Container image definitions
 *   - docker-compose.yml, compose.yaml          -- Multi-container orchestration
 *   - K8s manifests (Deployment, Pod, etc.)      -- Kubernetes resource definitions
 *
 * Attack categories detected:
 *   - Privileged containers  -- Full host access via privileged mode or capabilities
 *   - Root user              -- Running containers as UID 0
 *   - Exposed ports          -- Unnecessary port exposure to host
 *   - Sensitive mounts       -- Docker socket, /etc, /proc, SSH keys
 *   - Insecure registries    -- HTTP registries, untagged images
 *   - Misconfiguration       -- Missing healthchecks, resource limits, secrets in ENV
 *
 * Architecture:
 *   - Uses an iterative directory walker (no recursion, no symlink following)
 *   - Each discovered container config is dispatched to the appropriate scanner
 *   - Scanners check content against category-specific regex patterns
 *   - Findings are yielded via AsyncGenerator for streaming output
 *
 * This plugin requires only `fs:read` permission and no network access.
 * It is safe to run in both `safe` and `aggressive` modes.
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

import { isDockerfile, scanDockerfileContent } from './scanners/dockerfile-scanner.js';
import { isComposeFile, scanComposeContent } from './scanners/compose-scanner.js';
import { isK8sManifest, scanK8sContent } from './scanners/k8s-scanner.js';
import { ALL_CONTAINER_PATTERNS, getPatternCounts } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (1 MB). Container configs should be small. */
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024;

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

type ScannerType = 'dockerfile' | 'compose' | 'k8s';

/**
 * Determine which scanner should process a given file.
 * Returns null if the file is not a container configuration file.
 */
function classifyFile(relativePath: string): ScannerType | null {
  if (isDockerfile(relativePath)) return 'dockerfile';
  if (isComposeFile(relativePath)) return 'compose';
  if (isK8sManifest(relativePath)) return 'k8s';
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
    case 'dockerfile':
      yield* scanDockerfileContent(content, relativePath, pluginId);
      break;
    case 'compose':
      yield* scanComposeContent(content, relativePath, pluginId);
      break;
    case 'k8s':
      yield* scanK8sContent(content, relativePath, pluginId);
      break;
  }
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * ContainerAuditPlugin -- SPEAR-12 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects container security misconfigurations in Dockerfiles,
 * Docker Compose files, and Kubernetes manifests.
 */
export class ContainerAuditPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'container-audit',
    name: 'Container Security Auditor',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Scans Dockerfiles, docker-compose.yml, and Kubernetes manifests for security ' +
      'misconfigurations including privileged containers, root user, exposed ports, ' +
      'sensitive mounts, insecure registries, and missing security controls.',
    severity: 'high',
    tags: [
      'container', 'docker', 'kubernetes', 'k8s', 'compose',
      'privileged', 'root', 'security-context', 'mount', 'registry',
    ],
    references: [
      'CWE-250', 'CWE-269', 'CWE-732',
      'OWASP-DOCKER-TOP10',
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
    const total = ALL_CONTAINER_PATTERNS.length;

    context.logger.info('Container security auditor initialized', {
      totalPatterns: total,
      privilegedContainer: counts.privileged_container,
      rootUser: counts.root_user,
      exposedPort: counts.exposed_port,
      sensitiveMount: counts.sensitive_mount,
      insecureRegistry: counts.insecure_registry,
      misconfiguration: counts.misconfiguration,
    });
  }

  /**
   * Scan: Walk directory for container config files, scan each for security issues.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<ScannerType, number> = {
      dockerfile: 0,
      compose: 0,
      k8s: 0,
    };

    context.logger.info('Starting container security audit scan', { rootDir });

    for await (const { absolutePath, relativePath, scannerType } of walkContainerFiles(rootDir, target)) {
      try {
        const content = await readFileContent(absolutePath);
        if (content === null) {
          continue;
        }

        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large container config file', {
            file: relativePath,
          });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning container config file', {
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
        context.logger.warn('Error processing container config file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Container security audit scan complete', {
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

interface ContainerFileEntry {
  absolutePath: string;
  relativePath: string;
  scannerType: ScannerType;
}

/**
 * Walk the directory tree and yield container configuration files.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 */
async function* walkContainerFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<ContainerFileEntry> {
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

export default new ContainerAuditPlugin();

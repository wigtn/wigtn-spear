/**
 * SPEAR-13: Cloud Credential Chain Plugin
 *
 * Scans project directories for cloud provider credentials, IAM role
 * chains, and metadata service access patterns across AWS, GCP, and Azure.
 *
 * Target files:
 *   - Config:  .env, .env.*, *.yml, *.yaml, *.json, *.toml, *.ini, *.cfg
 *   - IaC:     *.tf, *.tfvars, Dockerfile, docker-compose.yml
 *   - Source:  *.ts, *.js, *.py, *.go, *.java, *.rb, *.sh, *.ps1
 *   - Cloud:   ~/.aws/credentials, service-account.json, etc.
 *
 * Credential categories detected:
 *   - AWS:     AKIA keys, secret keys, session tokens, assumed role ARNs,
 *              STS credentials, IMDS URLs
 *   - GCP:     Service account JSON, OAuth tokens, ADC paths, metadata URLs
 *   - Azure:   Client secrets, connection strings, SAS tokens, managed identity
 *   - Generic: Private keys (RSA/EC/PKCS8), IMDS link-local IP, env var exposure
 *
 * Architecture:
 *   - Uses an iterative directory walker (no recursion, no symlink following)
 *   - Each discovered file is dispatched to all applicable cloud scanners
 *   - The IAM mapper correlates findings into role chain graphs
 *   - Findings are yielded via AsyncGenerator for streaming output
 *
 * MITRE ATT&CK techniques:
 *   T1552     -- Unsecured Credentials
 *   T1078     -- Valid Accounts
 *   T1078.004 -- Valid Accounts: Cloud Accounts
 *   T1552.001 -- Unsecured Credentials: Credentials In Files
 *   T1552.004 -- Unsecured Credentials: Private Keys
 *   T1098     -- Account Manipulation
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

import { scanAWSContent, extractIAMRoleChain } from './scanners/aws-scanner.js';
import { scanGCPContent, extractServiceAccountRefs } from './scanners/gcp-scanner.js';
import { scanAzureContent, extractAzureIdentityRefs } from './scanners/azure-scanner.js';
import { scanIMDSContent, extractIMDSAccessPoints } from './scanners/imds-scanner.js';
import { mapIAMChains } from './iam-mapper.js';
import { ALL_PATTERNS, getPatternCounts } from './patterns.js';

// ─── Constants ──────────────────────────────────────────────────

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

/**
 * File extensions that are candidates for cloud credential scanning.
 * Includes config files, source code, IaC, and shell scripts.
 */
const SCANNABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  // Config files
  '.env', '.ini', '.cfg', '.conf', '.toml', '.properties',
  '.yml', '.yaml', '.json', '.xml',
  // Source code
  '.ts', '.js', '.mjs', '.cjs',
  '.py', '.go', '.java', '.rb', '.rs', '.cs',
  '.php', '.swift', '.kt',
  // Shell / Scripts
  '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
  // IaC
  '.tf', '.tfvars', '.hcl',
  // Docker
  '.dockerfile',
]);

/**
 * Filenames (without extension check) that should always be scanned.
 */
const SCANNABLE_FILENAMES: ReadonlySet<string> = new Set([
  '.env',
  '.env.local',
  '.env.development',
  '.env.staging',
  '.env.production',
  '.env.test',
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  'credentials',
  'config',
  'terraform.tfvars',
  '.boto',
  '.s3cfg',
]);

/**
 * Binary file extensions to always skip.
 */
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe', '.dll', '.so', '.dylib', '.o', '.obj', '.a', '.lib',
  '.class', '.pyc', '.wasm',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.jar', '.war', '.apk',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.webm',
  '.woff', '.woff2', '.ttf', '.otf',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.db', '.sqlite', '.sqlite3',
  '.bin', '.dat', '.img', '.iso',
]);

// ─── File Classification ────────────────────────────────────────

/**
 * Determine if a file should be scanned for cloud credentials.
 *
 * Returns true if the file has a scannable extension or is a known
 * credential-related filename.
 */
function isScannableFile(relativePath: string): boolean {
  const filename = basename(relativePath);
  const ext = extname(filename).toLowerCase();

  // Skip binary files
  if (BINARY_EXTENSIONS.has(ext)) {
    return false;
  }

  // Check by known filename
  if (SCANNABLE_FILENAMES.has(filename)) {
    return true;
  }

  // Check .env variants (e.g. .env.staging.backup)
  if (filename.startsWith('.env')) {
    return true;
  }

  // Check by extension
  if (SCANNABLE_EXTENSIONS.has(ext)) {
    return true;
  }

  return false;
}

// ─── Plugin Implementation ──────────────────────────────────────

/**
 * CloudCredentialPlugin -- SPEAR-13 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects cloud credential exposure and IAM role chain patterns.
 */
export class CloudCredentialPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'cloud-credential',
    name: 'Cloud Credential Chain Scanner',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Detects cloud provider credentials (AWS, GCP, Azure), IAM role chains, ' +
      'metadata service access, and credential file exposure in project directories',
    severity: 'critical',
    tags: [
      'cloud', 'credential', 'aws', 'gcp', 'azure', 'iam',
      'imds', 'metadata', 'secret', 'key', 'token',
    ],
    references: [
      'CWE-798', 'CWE-312', 'CWE-522',
      'MITRE-T1552', 'MITRE-T1078', 'MITRE-T1078.004',
      'MITRE-T1552.001', 'MITRE-T1552.004', 'MITRE-T1098',
    ],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log pattern statistics.
   *
   * All patterns are compiled at import time (no heavy initialization).
   */
  async setup(context: PluginContext): Promise<void> {
    const counts = getPatternCounts();
    const total = ALL_PATTERNS.length;

    context.logger.info('Cloud credential scanner initialized', {
      totalPatterns: total,
      aws: counts.aws,
      gcp: counts.gcp,
      azure: counts.azure,
      generic: counts.generic,
    });
  }

  /**
   * Scan: Walk directory for files, apply cloud-specific scanners, map IAM chains.
   *
   * The scan process:
   *   1. Walk the project directory tree (iterative DFS)
   *   2. For each scannable file, read the content
   *   3. Run all four scanners (AWS, GCP, Azure, IMDS)
   *   4. Extract IAM role chains for cross-provider correlation
   *   5. Run the IAM mapper for chain analysis findings
   *   6. Yield findings as they are discovered
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<string, number> = {
      aws: 0,
      gcp: 0,
      azure: 0,
      imds: 0,
      iamMapper: 0,
    };

    // Track unique findings to avoid duplicates from overlapping scanner patterns
    const emittedFindings = new Set<string>();

    context.logger.info('Starting cloud credential scan', { rootDir });

    for await (const { absolutePath, relativePath } of walkScannableFiles(rootDir, target)) {
      try {
        // Read file content
        const content = await readFileContent(absolutePath);
        if (content === null) {
          continue;
        }

        // Enforce max file size
        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large file', { file: relativePath });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning file for cloud credentials', {
          file: relativePath,
        });

        // ── Phase 1: Run provider-specific scanners ─────────────
        // Each scanner applies its provider + generic patterns

        for (const finding of scanAWSContent(content, relativePath, this.metadata.id)) {
          const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
          if (!emittedFindings.has(key)) {
            emittedFindings.add(key);
            findingsCount++;
            scannerHits.aws++;
            yield finding;
          }
        }

        for (const finding of scanGCPContent(content, relativePath, this.metadata.id)) {
          const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
          if (!emittedFindings.has(key)) {
            emittedFindings.add(key);
            findingsCount++;
            scannerHits.gcp++;
            yield finding;
          }
        }

        for (const finding of scanAzureContent(content, relativePath, this.metadata.id)) {
          const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
          if (!emittedFindings.has(key)) {
            emittedFindings.add(key);
            findingsCount++;
            scannerHits.azure++;
            yield finding;
          }
        }

        for (const finding of scanIMDSContent(content, relativePath, this.metadata.id)) {
          const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
          if (!emittedFindings.has(key)) {
            emittedFindings.add(key);
            findingsCount++;
            scannerHits.imds++;
            yield finding;
          }
        }

        // ── Phase 2: IAM chain mapping ──────────────────────────
        // Extract identity references and correlate across providers

        const awsEntries = extractIAMRoleChain(content);
        const gcpRefs = extractServiceAccountRefs(content);
        const azureRefs = extractAzureIdentityRefs(content);
        const imdsPoints = extractIMDSAccessPoints(content);

        // Only run mapper if any identity references were found
        if (
          awsEntries.length > 0 ||
          gcpRefs.length > 0 ||
          azureRefs.length > 0 ||
          imdsPoints.length > 0
        ) {
          const mappingResult = mapIAMChains(
            awsEntries,
            gcpRefs,
            azureRefs,
            imdsPoints,
            relativePath,
            this.metadata.id,
          );

          for (const finding of mappingResult.findings) {
            const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
            if (!emittedFindings.has(key)) {
              emittedFindings.add(key);
              findingsCount++;
              scannerHits.iamMapper++;
              yield finding;
            }
          }
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Cloud credential scan complete', {
      filesScanned,
      findingsCount,
      scannerHits,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // All patterns are stateless; no cleanup needed.
  }
}

// ─── Directory Walker ───────────────────────────────────────────

interface ScannableFileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree and yield files that should be scanned
 * for cloud credentials.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 * Skips well-known non-project directories (node_modules, .git, etc.).
 *
 * @param rootDir - The root directory to start walking from.
 * @param target - The ScanTarget with include/exclude patterns.
 * @yields ScannableFileEntry for each discovered scannable file.
 */
async function* walkScannableFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<ScannableFileEntry> {
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

      // Check exclude patterns
      if (target.exclude && target.exclude.length > 0) {
        const matchesExclude = target.exclude.some((pattern) =>
          relativePath.includes(pattern) || entry === pattern,
        );
        if (matchesExclude) {
          continue;
        }
      }

      // Use lstat (not stat) to detect symlinks without following them
      let entryStat;
      try {
        entryStat = await lstat(fullPath);
      } catch {
        continue;
      }

      // Skip symlinks entirely
      if (entryStat.isSymbolicLink()) {
        continue;
      }

      if (entryStat.isDirectory()) {
        // Skip well-known non-project directories
        if (SKIP_DIRS.has(entry)) {
          continue;
        }
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        // Check if file is scannable
        if (isScannableFile(relativePath)) {
          yield {
            absolutePath: fullPath,
            relativePath,
          };
        }
      }
    }
  }
}

// ─── Utilities ──────────────────────────────────────────────────

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

// ─── Exports ────────────────────────────────────────────────────

export { scanAWSContent, extractIAMRoleChain } from './scanners/aws-scanner.js';
export { scanGCPContent, extractServiceAccountRefs } from './scanners/gcp-scanner.js';
export { scanAzureContent, extractAzureIdentityRefs } from './scanners/azure-scanner.js';
export { scanIMDSContent, extractIMDSAccessPoints } from './scanners/imds-scanner.js';
export { mapIAMChains } from './iam-mapper.js';
export {
  ALL_PATTERNS,
  getPatternsByProvider,
  getPatternsByCategory,
  getPatternsBySeverity,
  getPatternCounts,
} from './patterns.js';
export type {
  CloudProvider,
  CredentialCategory,
  CredentialPattern,
} from './patterns.js';

// ─── Default Export ─────────────────────────────────────────────

export default new CloudCredentialPlugin();

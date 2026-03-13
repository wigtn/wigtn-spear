/**
 * SPEAR-10: AI Agent Manipulation Plugin
 *
 * Scans project directories for AI agent configuration files and detects
 * injection patterns that could manipulate AI coding assistants.
 *
 * Target files:
 *   - Cursor:   .cursorrules, .cursorignore, .cursor/rules/*
 *   - Claude:   .claude/settings.json, .claude/commands/*.md, CLAUDE.md
 *   - MCP:      mcp.json, .cursor/mcp.json, cline_mcp_settings.json
 *   - Generic:  copilot-instructions.md, AGENTS.md, .aider*, codex.md
 *
 * Attack categories detected:
 *   - Exfiltration          -- Data leak via URLs, webhooks, image tags
 *   - Privilege Escalation  -- Bypassing security controls, sudo, file writes
 *   - CoT Hijack            -- Chain-of-Thought extraction/redirect
 *   - Config Override        -- Disabling safety settings, wildcard permissions
 *   - Stealth Injection     -- Invisible chars, homoglyphs, hidden tags
 *
 * Architecture:
 *   - Uses an iterative directory walker (no recursion, no symlink following)
 *   - Each discovered AI config file is dispatched to the appropriate scanner
 *   - Scanners check file content against category-specific regex patterns
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

import { isCursorFile, scanCursorContent } from './scanners/cursorrules.js';
import { isClaudeFile, scanClaudeContent } from './scanners/claude-settings.js';
import { isMcpFile, scanMcpContent } from './scanners/mcp-config.js';
import { isGenericAgentFile, scanGenericAgentContent } from './scanners/generic-agent.js';
import { ALL_PATTERNS, getPatternCounts } from './patterns.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (1 MB). Agent config files should be small. */
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

type ScannerType = 'cursor' | 'claude' | 'mcp' | 'generic';

/**
 * Determine which scanner should process a given file.
 * Returns null if the file is not an AI agent configuration file.
 */
function classifyFile(relativePath: string): ScannerType | null {
  if (isCursorFile(relativePath)) return 'cursor';
  if (isClaudeFile(relativePath)) return 'claude';
  if (isMcpFile(relativePath)) return 'mcp';
  if (isGenericAgentFile(relativePath)) return 'generic';
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
    case 'cursor':
      yield* scanCursorContent(content, relativePath, pluginId);
      break;
    case 'claude':
      yield* scanClaudeContent(content, relativePath, pluginId);
      break;
    case 'mcp':
      yield* scanMcpContent(content, relativePath, pluginId);
      break;
    case 'generic':
      yield* scanGenericAgentContent(content, relativePath, pluginId);
      break;
  }
}

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * AgentManipulatorPlugin -- SPEAR-10 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Detects AI agent manipulation attempts in project configuration files.
 */
export class AgentManipulatorPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'agent-manipulator',
    name: 'AI Agent Manipulation Scanner',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Detects injection patterns in AI agent configuration files (.cursorrules, .claude/settings.json, mcp.json, copilot-instructions.md, etc.)',
    severity: 'critical',
    tags: ['ai', 'agent', 'manipulation', 'injection', 'mcp', 'cursor', 'claude', 'copilot'],
    references: ['CWE-94', 'CWE-77', 'OWASP-LLM01', 'OWASP-LLM07'],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log pattern statistics.
   *
   * This plugin has no heavy initialization (no rules loading, no
   * Aho-Corasick automaton). All patterns are compiled at import time.
   */
  async setup(context: PluginContext): Promise<void> {
    const counts = getPatternCounts();
    const total = ALL_PATTERNS.length;

    context.logger.info('Agent manipulation scanner initialized', {
      totalPatterns: total,
      exfiltration: counts.exfiltration,
      privilegeEscalation: counts.privilege_escalation,
      cotHijack: counts.cot_hijack,
      configOverride: counts.config_override,
      stealthInjection: counts.stealth_injection,
    });
  }

  /**
   * Scan: Walk directory for AI agent config files, scan each for injection patterns.
   *
   * The scan process:
   *   1. Walk the project directory tree (iterative DFS)
   *   2. For each file, classify it by AI agent type (cursor, claude, mcp, generic)
   *   3. If classified, read the file content
   *   4. Dispatch to the appropriate scanner
   *   5. Yield findings as they are discovered
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const scannerHits: Record<ScannerType, number> = {
      cursor: 0,
      claude: 0,
      mcp: 0,
      generic: 0,
    };

    context.logger.info('Starting AI agent manipulation scan', { rootDir });

    for await (const { absolutePath, relativePath, scannerType } of walkAgentFiles(rootDir, target)) {
      try {
        // Read file content
        const content = await readFileContent(absolutePath);
        if (content === null) {
          continue;
        }

        // Enforce max file size
        if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
          context.logger.debug('Skipping large agent config file', {
            file: relativePath,
          });
          continue;
        }

        filesScanned++;
        context.logger.debug('Scanning agent config file', {
          file: relativePath,
          scanner: scannerType,
        });

        // Dispatch to appropriate scanner and yield findings
        for (const finding of dispatchScan(scannerType, content, relativePath, this.metadata.id)) {
          findingsCount++;
          scannerHits[scannerType]++;
          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing agent config file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Agent manipulation scan complete', {
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

interface AgentFileEntry {
  absolutePath: string;
  relativePath: string;
  scannerType: ScannerType;
}

/**
 * Walk the directory tree and yield AI agent configuration files.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 * Skips well-known non-project directories (node_modules, .git, etc.).
 *
 * @param rootDir - The root directory to start walking from.
 * @param target - The ScanTarget with include/exclude patterns.
 * @yields AgentFileEntry for each discovered AI agent config file.
 */
async function* walkAgentFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<AgentFileEntry> {
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
        // Classify the file
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

export default new AgentManipulatorPlugin();

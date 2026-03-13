/**
 * SPEAR-06: Prompt Injection Fuzzer Plugin
 *
 * Scans source code for prompt injection vulnerabilities by matching
 * against the HouYi 3-stage payload generator (1000 combinations)
 * and AIShellJack 314-payload database.
 *
 * Detection approach:
 *   1. Walk the target directory to find text files
 *   2. Pre-filter using keyword sets (fast rejection)
 *   3. Line-by-line regex/substring matching against payload patterns
 *   4. Track findings on the Promptware Kill Chain (7 stages)
 *   5. Map findings to MITRE ATT&CK / ATLAS techniques
 *
 * The plugin operates in safe mode (static analysis only).
 * In aggressive mode, it additionally generates fuzzing payloads
 * that can be used with external LLM testing harnesses.
 *
 * Reference papers:
 *   - "HouYi: A Prompt Injection Approach for LLM Applications"
 *   - "AIShellJack: Automated Shell Command Injection via AI Agents"
 *   - "Promptware Kill Chain" (7-stage LLM attack lifecycle)
 */

import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';

import { generateHouYiPayloads, getHouYiKeywords } from './payloads/houyi.js';
import {
  generateAIShellJackPayloads,
  getAIShellJackKeywords,
  AISHELLJACK_PAYLOAD_COUNT,
} from './payloads/aishelljack.js';
import type { PayloadEntry } from './payloads/types.js';
import { KillChainTracker } from './kill-chain.js';
import { mapToMitre, getMitreTechnique } from './mitre-mapper.js';

// ─── Constants ──────────────────────────────────────────────

/** Maximum file size to scan (512 KB). */
const MAX_FILE_SIZE_BYTES = 512 * 1024;

/** File extensions to scan for prompt injection patterns. */
const SCAN_EXTENSIONS: ReadonlySet<string> = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.yaml', '.yml',
  '.json', '.jsonl', '.jsonc',
  '.md', '.mdx', '.txt', '.rst',
  '.html', '.htm', '.xml', '.svg',
  '.toml', '.ini', '.cfg', '.conf',
  '.env', '.env.local', '.env.example',
  '.sh', '.bash', '.zsh', '.ps1',
  '.rb', '.go', '.rs', '.java', '.kt', '.swift',
  '.vue', '.svelte',
  '.sql',
  '.prompt', '.prompts',
]);

/** Directories to skip during traversal. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules', '.git', 'dist', 'build', 'out',
  '.next', '.nuxt', '__pycache__', '.venv', 'venv',
  'vendor', 'target', '.turbo', 'coverage',
  '.nyc_output', '.cache', '.parcel-cache',
]);

// ─── Plugin Metadata ────────────────────────────────────────

const metadata: PluginMetadata = {
  id: 'spear-06-prompt-injector',
  name: 'Prompt Injection Fuzzer',
  version: '0.1.0',
  description:
    'Scans for prompt injection vulnerabilities using HouYi 3-stage payloads ' +
    '(1000 combinations) and AIShellJack 314-payload database. Tracks findings ' +
    'on the Promptware Kill Chain and maps to MITRE ATT&CK/ATLAS.',
  author: 'WIGTN Team',
  severity: 'critical',
  tags: ['prompt-injection', 'fuzzing', 'ai-security', 'llm', 'mcp'],
  references: [
    'https://arxiv.org/abs/2309.15563',
    'https://atlas.mitre.org/techniques/AML.T0051/',
  ],
  safeMode: true,
  requiresNetwork: false,
  supportedPlatforms: ['linux', 'darwin', 'win32'],
  permissions: ['fs:read'],
  trustLevel: 'builtin',
};

// ─── Helpers ────────────────────────────────────────────────

/** Check whether a file path has a scannable extension. */
function isScannable(filePath: string): boolean {
  const dot = filePath.lastIndexOf('.');
  if (dot === -1) return false;
  return SCAN_EXTENSIONS.has(filePath.slice(dot).toLowerCase());
}

/** Normalize text for keyword matching. */
function normalize(text: string): string {
  return text.toLowerCase();
}

/** Check if text contains any keyword from the set. */
function containsKeyword(text: string, keywords: string[]): boolean {
  for (const kw of keywords) {
    if (text.includes(kw)) return true;
  }
  return false;
}

// ─── Payload Scanner ────────────────────────────────────────

interface MatchResult {
  payload: PayloadEntry;
  line: number;
  column: number;
  matchedText: string;
}

/**
 * Scan file content against a set of payloads.
 * Returns all matches found in the content.
 */
function scanContent(
  content: string,
  payloads: PayloadEntry[],
): MatchResult[] {
  const results: MatchResult[] = [];
  const lines = content.split('\n');
  const seen = new Set<string>(); // Deduplicate by ruleId + line

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const normalizedLine = normalize(line);

    for (const payload of payloads) {
      const normalizedPayload = normalize(payload.payload);

      // Skip very short payloads to reduce false positives
      if (normalizedPayload.length < 4) continue;

      const colIdx = normalizedLine.indexOf(normalizedPayload);
      if (colIdx !== -1) {
        const dedupeKey = `${payload.id}:${i + 1}`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          results.push({
            payload,
            line: i + 1,
            column: colIdx + 1,
            matchedText: line.slice(colIdx, colIdx + normalizedPayload.length),
          });
        }
      }
    }
  }

  return results;
}

// ─── File Walker ────────────────────────────────────────────

/**
 * Iterative directory walker. Yields absolute file paths.
 */
async function* walkFiles(
  root: string,
  excludePatterns: string[],
): AsyncGenerator<string> {
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: string[];

    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue;
      if (entry.startsWith('.') && entry !== '.env' && entry !== '.env.local' && entry !== '.env.example') continue;

      const fullPath = join(dir, entry);

      // Check exclude patterns
      const relPath = relative(root, fullPath);
      if (excludePatterns.some((p) => relPath.startsWith(p) || relPath.includes(p))) {
        continue;
      }

      try {
        const stat = await lstat(fullPath);
        if (stat.isSymbolicLink()) continue;

        if (stat.isDirectory()) {
          stack.push(fullPath);
        } else if (stat.isFile() && stat.size <= MAX_FILE_SIZE_BYTES && isScannable(fullPath)) {
          yield fullPath;
        }
      } catch {
        continue;
      }
    }
  }
}

// ─── Plugin Implementation ──────────────────────────────────

/** Cached payload sets (initialized once in setup). */
let houYiPayloads: PayloadEntry[] = [];
let aiShellJackPayloads: PayloadEntry[] = [];
let allKeywords: string[] = [];

const plugin: SpearPlugin = {
  metadata,

  async setup(context: PluginContext): Promise<void> {
    context.logger.info('spear-06: initializing prompt injection fuzzer');

    // Generate payload databases
    houYiPayloads = generateHouYiPayloads();
    aiShellJackPayloads = generateAIShellJackPayloads();

    // Combine keywords for fast pre-filtering
    const houYiKw = getHouYiKeywords();
    const asjKw = getAIShellJackKeywords();
    allKeywords = [...new Set([...houYiKw, ...asjKw])];

    context.logger.info('spear-06: payloads loaded', {
      houYi: houYiPayloads.length,
      aiShellJack: aiShellJackPayloads.length,
      keywords: allKeywords.length,
    });
  },

  async *scan(
    target: ScanTarget,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const tracker = new KillChainTracker();
    const excludePatterns = target.exclude ?? [];
    let filesScanned = 0;
    let filesMatched = 0;

    // Combine all payloads for scanning
    const allPayloads = [...houYiPayloads, ...aiShellJackPayloads];

    context.logger.info('spear-06: starting scan', {
      target: target.path,
      payloadCount: allPayloads.length,
    });

    for await (const filePath of walkFiles(target.path, excludePatterns)) {
      filesScanned++;

      let content: string;
      try {
        content = await readFile(filePath, 'utf-8');
      } catch {
        continue;
      }

      // Pre-filter: skip files with no relevant keywords
      const normalizedContent = normalize(content);
      if (!containsKeyword(normalizedContent, allKeywords)) {
        continue;
      }

      // Scan against all payloads
      const matches = scanContent(content, allPayloads);
      if (matches.length === 0) continue;

      filesMatched++;

      for (const match of matches) {
        const relPath = relative(target.path, filePath);
        const mitreTechniques = mapToMitre(match.payload.category);
        const stage = match.payload.killChainStage ?? 'delivery';

        const finding: Finding = {
          ruleId: `spear-06/${match.payload.id}`,
          severity: match.payload.severity,
          message:
            `Prompt injection pattern detected: ${match.payload.description}`,
          file: relPath,
          line: match.line,
          column: match.column,
          mitreTechniques,
          remediation:
            `Remove or sanitize the prompt injection pattern. If this is a test file ` +
            `or security research, add it to .spearignore. Pattern: "${match.payload.payload.slice(0, 50)}..."`,
          metadata: {
            plugin: 'spear-06-prompt-injector',
            category: match.payload.category,
            killChainStage: stage,
            matchedText: match.matchedText.slice(0, 100),
            payloadSet: match.payload.id.startsWith('houyi') ? 'houyi' : 'aishelljack',
          },
        };

        // Track on kill chain
        tracker.addFinding(finding, stage, match.payload.category);

        yield finding;
      }
    }

    // Log summary with kill chain coverage
    const coverage = tracker.getCoverage();
    context.logger.info('spear-06: scan complete', {
      filesScanned,
      filesMatched,
      totalFindings: coverage.totalFindings,
      killChainCoverage: `${coverage.coveredStages}/${coverage.totalStages} stages (${coverage.coveragePercent}%)`,
      gaps: coverage.gaps,
    });
  },

  async teardown(context: PluginContext): Promise<void> {
    // Release cached payloads
    houYiPayloads = [];
    aiShellJackPayloads = [];
    allKeywords = [];
    context.logger.debug('spear-06: teardown complete');
  },
};

export default plugin;

// Re-export key types and utilities for CLI commands
export { KillChainTracker } from './kill-chain.js';
export type { KillChainCoverage, StageCoverage } from './kill-chain.js';
export { generateHouYiPayloads, getHouYiKeywords } from './payloads/houyi.js';
export {
  generateAIShellJackPayloads,
  getAIShellJackKeywords,
  AISHELLJACK_PAYLOAD_COUNT,
} from './payloads/aishelljack.js';
export { mapToMitre, getMitreTechnique, getMitreTechniquesForCategory } from './mitre-mapper.js';
export type { PayloadEntry, PayloadCategory, KillChainStage } from './payloads/types.js';

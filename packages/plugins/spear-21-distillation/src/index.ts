/**
 * SPEAR-21: Model Distillation Tester
 *
 * Tests for model distillation vulnerabilities -- techniques that attempt
 * to steal LLM capabilities by extracting internal reasoning, system prompts,
 * capability profiles, or training data from large language models.
 *
 * Scans files for patterns that indicate distillation attack payloads:
 *
 *   - CoT Extraction       -- Chain-of-thought extraction prompts
 *   - Prompt Theft         -- System prompt leakage/theft patterns
 *   - Capability Probing   -- Model capability enumeration queries
 *   - Fine-Tune Data       -- Training data generation attacks
 *   - Model Extraction     -- Behavior cloning and output harvesting
 *
 * Architecture:
 *   - Iterative directory walker (no recursion, no symlink following)
 *   - Pattern matching against 280+ distillation payload signatures
 *   - Normalized text comparison for fuzzy matching
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
  Severity,
} from '@wigtn/shared';

import {
  ALL_PAYLOADS,
  getPayloadCounts,
  type CompactDistillPayload,
  type DistillCategory,
} from './payloads.js';

// ─── Constants ─────────────────────────────────────────────────

/** Maximum file size to process (5 MB). */
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

/** File encoding for reading text files. */
const FILE_ENCODING = 'utf-8';

/** File extensions that may contain distillation prompts. */
const TARGET_EXTENSIONS: ReadonlySet<string> = new Set([
  '.txt', '.md', '.mdx',
  '.json', '.jsonl', '.yaml', '.yml', '.toml',
  '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.ipynb',
  '.csv', '.tsv',
  '.xml', '.html',
  '.sh', '.bash',
  '.prompt', '.prompts',
  '.cfg', '.conf', '.ini',
  '.env', '.env.local',
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
]);

/**
 * Category severity mapping: the baseline severity for findings in each category.
 */
const CATEGORY_SEVERITY: Record<DistillCategory, Severity> = {
  cot_extraction: 'high',
  prompt_theft: 'critical',
  capability_probe: 'medium',
  fine_tune_data: 'critical',
  model_extraction: 'critical',
};

/**
 * MITRE ATT&CK mapping per category.
 */
const CATEGORY_MITRE: Record<DistillCategory, string[]> = {
  cot_extraction: ['T1190', 'T1005'],
  prompt_theft: ['T1190', 'T1552'],
  capability_probe: ['T1592', 'T1595'],
  fine_tune_data: ['T1005', 'T1530'],
  model_extraction: ['T1005', 'T1530', 'T1592'],
};

// ─── Compiled Detection Patterns ───────────────────────────────

interface CompiledPattern {
  regex: RegExp;
  payload: CompactDistillPayload;
}

/**
 * Build compiled regex patterns from payload strings.
 * Each payload is converted to a case-insensitive regex that allows
 * flexible whitespace and minor variations.
 */
function buildCompiledPatterns(): CompiledPattern[] {
  const compiled: CompiledPattern[] = [];

  for (const payload of ALL_PAYLOADS) {
    const escaped = payload[0]
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')  // Escape regex special chars
      .replace(/\s+/g, '\\s+');                   // Allow flexible whitespace

    try {
      compiled.push({
        regex: new RegExp(escaped, 'i'),
        payload,
      });
    } catch {
      // Skip payloads that produce invalid regex (should not happen with escaping)
    }
  }

  return compiled;
}

const COMPILED_PATTERNS: CompiledPattern[] = buildCompiledPatterns();

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * DistillationPlugin -- SPEAR-21 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Scans files for model distillation attack patterns.
 */
export class DistillationPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'distillation',
    name: 'Model Distillation Tester',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Tests for model distillation vulnerabilities: chain-of-thought extraction, system prompt theft, capability probing, fine-tuning data generation, and model behavior cloning.',
    severity: 'critical',
    tags: [
      'distillation', 'model-extraction', 'prompt-theft', 'cot-extraction',
      'capability-probing', 'llm-security', 'ai-safety',
    ],
    references: [
      'OWASP-LLM06',
      'OWASP-LLM10',
      'CWE-200',
      'CWE-497',
      'MITRE-ATLAS-AML.T0024',
      'MITRE-ATLAS-AML.T0044',
    ],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log payload statistics.
   */
  async setup(context: PluginContext): Promise<void> {
    const counts = getPayloadCounts();
    const total = ALL_PAYLOADS.length;

    context.logger.info('Model distillation tester initialized', {
      totalPayloads: total,
      cotExtraction: counts.cot_extraction,
      promptTheft: counts.prompt_theft,
      capabilityProbe: counts.capability_probe,
      fineTuneData: counts.fine_tune_data,
      modelExtraction: counts.model_extraction,
      compiledPatterns: COMPILED_PATTERNS.length,
    });
  }

  /**
   * Scan: Walk directory for target files, scan each for distillation patterns.
   *
   * The scan process:
   *   1. Walk the project directory tree (iterative DFS)
   *   2. For each target file, read content
   *   3. Match content against compiled distillation payload patterns
   *   4. Yield findings for each detected distillation technique
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    let filesScanned = 0;
    let findingsCount = 0;
    const categoryHits: Record<DistillCategory, number> = {
      cot_extraction: 0,
      prompt_theft: 0,
      capability_probe: 0,
      fine_tune_data: 0,
      model_extraction: 0,
    };

    context.logger.info('Starting model distillation scan', { rootDir });

    for await (const { absolutePath, relativePath } of walkTargetFiles(rootDir, target)) {
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
        context.logger.debug('Scanning file for distillation patterns', {
          file: relativePath,
        });

        // Scan for distillation patterns
        for (const finding of scanForDistillation(content, relativePath, this.metadata.id)) {
          findingsCount++;
          const category = (finding.metadata?.['category'] as DistillCategory) ?? 'cot_extraction';
          categoryHits[category]++;
          yield finding;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('Error processing file, skipping', {
          file: relativePath,
          error: message,
        });
      }
    }

    context.logger.info('Model distillation scan complete', {
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
 * Scan file content against compiled distillation patterns.
 */
function* scanForDistillation(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');
  const matchedPayloads: Set<string> = new Set();

  for (const { regex, payload } of COMPILED_PATTERNS) {
    const [payloadText, category, severity, technique] = payload;

    // Skip if we already found this exact payload
    if (matchedPayloads.has(payloadText)) {
      continue;
    }

    // Test against full content first
    if (!regex.test(content)) {
      continue;
    }

    matchedPayloads.add(payloadText);

    // Find the specific line(s) that match
    let matchFound = false;
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex]!;
      if (regex.test(line)) {
        matchFound = true;
        yield createFinding(
          payloadText,
          category,
          severity as Severity,
          technique,
          filePath,
          lineIndex + 1,
          pluginId,
        );
        break; // One finding per payload per file
      }
    }

    if (!matchFound) {
      yield createFinding(
        payloadText,
        category,
        severity as Severity,
        technique,
        filePath,
        1,
        pluginId,
      );
    }
  }
}

/**
 * Create a Finding object for a distillation match.
 */
function createFinding(
  payloadText: string,
  category: DistillCategory,
  severity: Severity,
  technique: string,
  filePath: string,
  line: number,
  pluginId: string,
): Finding {
  return {
    ruleId: `distill-${category}-${technique}`,
    severity: severity,
    message: `[Distillation] ${getCategoryLabel(category)}: Detected distillation payload "${truncate(payloadText, 80)}"`,
    file: filePath,
    line,
    mitreTechniques: CATEGORY_MITRE[category],
    remediation: getRemediation(category),
    metadata: {
      pluginId,
      category,
      technique,
      scanner: 'distillation-matcher',
      payloadPreview: truncate(payloadText, 120),
      categorySeverity: CATEGORY_SEVERITY[category],
    },
  };
}

// ─── Directory Walker ──────────────────────────────────────────

interface TargetFileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree and yield target files for distillation scanning.
 */
async function* walkTargetFiles(
  rootDir: string,
  target: ScanTarget,
): AsyncGenerator<TargetFileEntry> {
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
        const ext = extname(entry).toLowerCase();
        if (TARGET_EXTENSIONS.has(ext)) {
          yield { absolutePath: fullPath, relativePath };
        }
      }
    }
  }
}

// ─── Utilities ─────────────────────────────────────────────────

/**
 * Read file content as UTF-8 string.
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, FILE_ENCODING);
  } catch {
    return null;
  }
}

/**
 * Truncate a string to a maximum length.
 */
function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + '...';
}

/**
 * Get a human-readable label for a distillation category.
 */
function getCategoryLabel(category: DistillCategory): string {
  const labels: Record<DistillCategory, string> = {
    cot_extraction: 'Chain-of-Thought Extraction',
    prompt_theft: 'System Prompt Theft',
    capability_probe: 'Capability Probing',
    fine_tune_data: 'Fine-Tuning Data Generation',
    model_extraction: 'Model Extraction',
  };
  return labels[category];
}

/**
 * Get remediation advice for a distillation category.
 */
function getRemediation(category: DistillCategory): string {
  const remediations: Record<DistillCategory, string> = {
    cot_extraction:
      'Remove or flag chain-of-thought extraction prompts. These attempt to steal the model\'s internal reasoning process for distillation into smaller models.',
    prompt_theft:
      'Remove system prompt theft attempts. These payloads try to extract the system prompt for replication or competitive intelligence.',
    capability_probe:
      'Review capability probing queries. While individual probes may be benign, systematic probing can map model capabilities for targeted distillation.',
    fine_tune_data:
      'Block fine-tuning data generation requests. These attacks produce structured training data from model outputs to train competing models.',
    model_extraction:
      'Prevent model extraction attempts. These techniques harvest model outputs, probability distributions, or behavioral fingerprints for cloning.',
  };
  return remediations[category];
}

// ─── Default Export ────────────────────────────────────────────

export default new DistillationPlugin();

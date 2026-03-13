/**
 * Rules loader -- recursively discovers and parses YAML rule files.
 *
 * Design decisions:
 *   - Recursive walk handles nested category directories (secrets/, vulns/, misconfig/)
 *   - Invalid files are warned and skipped, never fatal (PRD: Malformed Rule File scenario)
 *   - Empty directories and missing paths are handled gracefully
 *   - File-level parse errors include the file path and YAML line number
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { validateRule } from './validator.js';
import type { Rule, SpearLogger } from '@wigtn/shared';

const YAML_EXTENSIONS: ReadonlySet<string> = new Set(['.yaml', '.yml']);

/**
 * Load all valid YAML rules from a directory tree.
 *
 * @param rulesDir  - Root directory to scan (e.g. `./rules/`)
 * @param logger    - Optional logger for warnings/debug output
 * @returns Array of validated Rule objects (invalid files are skipped)
 */
export async function loadRules(rulesDir: string, logger?: SpearLogger): Promise<Rule[]> {
  const rules: Rule[] = [];

  // Handle missing or empty directory gracefully
  let dirStat;
  try {
    dirStat = await stat(rulesDir);
  } catch {
    logger?.warn('rules directory does not exist, returning empty rule set', {
      rulesDir,
    });
    return [];
  }

  if (!dirStat.isDirectory()) {
    logger?.warn('rules path is not a directory, returning empty rule set', {
      rulesDir,
    });
    return [];
  }

  const yamlFiles = await findYamlFiles(rulesDir);

  if (yamlFiles.length === 0) {
    logger?.warn('no YAML rule files found in rules directory', { rulesDir });
    return [];
  }

  logger?.debug('found YAML rule files', {
    count: yamlFiles.length,
    rulesDir,
  });

  for (const filePath of yamlFiles) {
    try {
      const content = await readFile(filePath, 'utf-8');

      if (content.trim() === '') {
        logger?.warn('empty rule file, skipping', { filePath });
        continue;
      }

      let parsed: unknown;
      try {
        parsed = parseYaml(content);
      } catch (yamlErr: unknown) {
        const message = yamlErr instanceof Error ? yamlErr.message : String(yamlErr);
        logger?.warn('YAML parse error, skipping rule file', {
          filePath,
          error: message,
        });
        continue;
      }

      // A single YAML file may contain one rule (object) or multiple (array)
      const rawRules = Array.isArray(parsed) ? parsed : [parsed];

      for (const rawRule of rawRules) {
        const result = validateRule(rawRule);

        if (result.rule) {
          rules.push(result.rule);
          logger?.debug('loaded rule', {
            id: result.rule.id,
            name: result.rule.name,
            filePath,
          });
        } else {
          const errorSummary = result.errors
            .map((e) => `${e.field}: ${e.message}`)
            .join('; ');
          logger?.warn('invalid rule definition, skipping', {
            filePath,
            errors: errorSummary,
          });
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger?.warn('failed to read rule file, skipping', {
        filePath,
        error: message,
      });
    }
  }

  logger?.info('rules loaded', {
    total: rules.length,
    rulesDir,
  });

  return rules;
}

/**
 * Recursively find all .yaml / .yml files under a directory.
 */
async function findYamlFiles(dir: string): Promise<string[]> {
  const results: string[] = [];

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    // Permission denied or directory vanished between stat and readdir
    return [];
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      const nested = await findYamlFiles(fullPath);
      results.push(...nested);
    } else if (entry.isFile() && YAML_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
      results.push(fullPath);
    }
  }

  return results;
}

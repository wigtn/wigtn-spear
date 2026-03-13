/**
 * `spear config set <key> <value>` command
 *
 * Sets a configuration value in .spearrc.yaml.
 * Supports both string and typed values (numbers, booleans).
 */

import { Args, Command } from '@oclif/core';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import chalk from 'chalk';

// ─── YAML Helpers ─────────────────────────────────────────

/**
 * Simple YAML key-value updater.
 *
 * Handles top-level scalar keys in a flat YAML file by finding the line
 * with the matching key and replacing its value. If the key is not found,
 * appends a new line.
 *
 * This avoids a dependency on a full YAML write library while preserving
 * comments and formatting in the .spearrc.yaml file.
 */
function updateYamlValue(content: string, key: string, value: string): string {
  const lines = content.split('\n');
  const keyPattern = new RegExp(`^${escapeRegex(key)}\\s*:`);
  let found = false;

  const updatedLines = lines.map((line) => {
    if (keyPattern.test(line)) {
      found = true;
      return `${key}: ${value}`;
    }
    return line;
  });

  if (!found) {
    updatedLines.push(`${key}: ${value}`);
  }

  return updatedLines.join('\n');
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Coerce a string value to its YAML representation.
 * - "true"/"false" -> boolean
 * - numeric strings -> number
 * - otherwise -> quoted string or bare string
 */
function coerceValue(value: string): string {
  if (value === 'true' || value === 'false') return value;
  if (/^\d+$/.test(value)) return value;
  if (/^\d+\.\d+$/.test(value)) return value;
  // If value contains special chars, quote it
  if (/[:#{}[\],&*?|>!%@`]/.test(value) || value.includes(' ')) {
    return `"${value}"`;
  }
  return value;
}

// ─── Valid Keys ───────────────────────────────────────────

const VALID_KEYS = [
  'mode',
  'verifyLimit',
  'maxWorkers',
  'gitDepth',
  'outputFormat',
  'dbPath',
  'rulesDir',
  'verbose',
];

// ─── Command ──────────────────────────────────────────────

export default class ConfigSet extends Command {
  static override description = 'Set a configuration value in .spearrc.yaml';

  static override examples = [
    '<%= config.bin %> config set mode aggressive',
    '<%= config.bin %> config set gitDepth 500',
    '<%= config.bin %> config set verbose true',
    '<%= config.bin %> config set outputFormat sarif',
  ];

  static override args = {
    key: Args.string({
      description: 'Configuration key to set',
      required: true,
    }),
    value: Args.string({
      description: 'Value to set',
      required: true,
    }),
  };

  async run(): Promise<void> {
    const { args } = await this.parse(ConfigSet);
    const { key, value } = args;

    // Warn about unknown keys
    if (!VALID_KEYS.includes(key)) {
      this.warn(
        `"${key}" is not a recognized configuration key. ` +
        `Valid keys: ${VALID_KEYS.join(', ')}`,
      );
    }

    const rcPath = resolve(process.cwd(), '.spearrc.yaml');

    if (!existsSync(rcPath)) {
      this.error(
        `No .spearrc.yaml found.\nRun ${chalk.cyan('spear init')} first.`,
        { exit: 1 },
      );
    }

    const content = readFileSync(rcPath, 'utf-8');
    const yamlValue = coerceValue(value);
    const updated = updateYamlValue(content, key, yamlValue);
    writeFileSync(rcPath, updated, 'utf-8');

    this.log(`  ${chalk.green('Set')} ${chalk.bold(key)} = ${chalk.dim(yamlValue)}`);
  }
}

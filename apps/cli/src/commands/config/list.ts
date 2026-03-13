/**
 * `spear config list` command
 *
 * Displays all effective configuration values (merged from defaults
 * and .spearrc.yaml) in a formatted table.
 */

import { Command } from '@oclif/core';
import chalk from 'chalk';
import { loadConfig } from '@wigtn/shared';

// ─── Command ──────────────────────────────────────────────

export default class ConfigList extends Command {
  static override description = 'List all configuration values';

  static override examples = [
    '<%= config.bin %> config list',
  ];

  async run(): Promise<void> {
    const config = loadConfig(process.cwd());
    const configRecord = config as unknown as Record<string, unknown>;

    this.log(chalk.white.bold('\n  WIGTN-SPEAR Configuration'));
    this.log(chalk.dim('  ════════════════════════════════════════'));

    // Determine max key length for alignment
    const keys = Object.keys(configRecord);
    const maxKeyLen = Math.max(...keys.map((k) => k.length));

    for (const key of keys) {
      const value = configRecord[key];
      const paddedKey = key.padEnd(maxKeyLen);
      let displayValue: string;

      if (Array.isArray(value)) {
        displayValue = value.length > 0 ? value.join(', ') : chalk.dim('(empty)');
      } else if (typeof value === 'boolean') {
        displayValue = value ? chalk.green('true') : chalk.dim('false');
      } else if (typeof value === 'number') {
        displayValue = value === 0 ? chalk.dim('0 (auto)') : String(value);
      } else if (typeof value === 'string') {
        displayValue = value || chalk.dim('(not set)');
      } else {
        displayValue = String(value);
      }

      this.log(`  ${chalk.bold(paddedKey)}  ${displayValue}`);
    }

    this.log('');
  }
}

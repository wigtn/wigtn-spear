/**
 * `spear config get <key>` command
 *
 * Reads and displays a single configuration value from the effective
 * configuration (merged: defaults + .spearrc.yaml).
 */

import { Args, Command } from '@oclif/core';
import chalk from 'chalk';
import { loadConfig } from '@wigtn/shared';
import type { SpearConfig } from '@wigtn/shared';

// ─── Command ──────────────────────────────────────────────

export default class ConfigGet extends Command {
  static override description = 'Get a configuration value';

  static override examples = [
    '<%= config.bin %> config get mode',
    '<%= config.bin %> config get gitDepth',
    '<%= config.bin %> config get outputFormat',
  ];

  static override args = {
    key: Args.string({
      description: 'Configuration key to retrieve',
      required: true,
    }),
  };

  async run(): Promise<void> {
    const { args } = await this.parse(ConfigGet);
    const { key } = args;

    const config = loadConfig(process.cwd());
    const configRecord = config as unknown as Record<string, unknown>;

    if (!(key in configRecord)) {
      this.error(`Unknown configuration key: "${key}"`, { exit: 1 });
    }

    const value = configRecord[key];
    const displayValue = Array.isArray(value)
      ? value.join(', ')
      : String(value);

    this.log(`  ${chalk.bold(key)} = ${chalk.dim(displayValue)}`);
  }
}

/**
 * `spear arena submit` command
 *
 * Validates and submits arena attack payloads.
 * Currently supports local JSON validation only;
 * API submission is planned for future integration.
 */

import { Command, Flags } from '@oclif/core';
import { readFileSync, existsSync } from 'node:fs';
import chalk from 'chalk';

import { validateSubmission } from '@wigtn/spear-26-scenario-engine';
import type { ArenaSubmission } from '@wigtn/shared';

// ─── Command ──────────────────────────────────────────────

export default class ArenaSubmit extends Command {
  static override description = 'Validate and submit an arena attack payload';

  static override examples = [
    '<%= config.bin %> arena submit --file attack.json',
    '<%= config.bin %> arena submit --file attack.json --validate-only',
  ];

  static override flags = {
    file: Flags.string({
      char: 'f',
      description: 'Path to submission JSON file',
      required: true,
    }),
    'validate-only': Flags.boolean({
      description: 'Only validate the JSON, do not submit',
      default: true,
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(ArenaSubmit);
    const filePath = flags.file;

    this.log('');
    this.log(chalk.red.bold('  ARENA SUBMISSION VALIDATOR'));
    this.log(chalk.dim('  ════════════════════════════════════════'));
    this.log('');

    // ── Read file ──────────────────────────────────────────

    if (!existsSync(filePath)) {
      this.error(`File not found: ${filePath}`, { exit: 1 });
    }

    let data: unknown;
    try {
      const raw = readFileSync(filePath, 'utf-8');
      data = JSON.parse(raw);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.error(`Failed to parse JSON: ${message}`, { exit: 1 });
    }

    this.log(chalk.white.bold('  File: ') + chalk.dim(filePath));
    this.log('');

    // ── Validate ───────────────────────────────────────────

    const submission = data as ArenaSubmission;
    const result = validateSubmission(submission);

    if (result.valid) {
      this.log(chalk.green.bold('  PASS') + chalk.green(' - Submission JSON is valid'));
      this.log('');

      this.log(chalk.white.bold('  Scenario:   ') + submission.scenario_id);
      this.log(chalk.white.bold('  Track:      ') + submission.track);
      this.log(chalk.white.bold('  Action:     ') + submission.selected_action_id);
      this.log(chalk.white.bold('  Channel:    ') + submission.channel);
      this.log(chalk.white.bold('  Confidence: ') + submission.confidence);
      this.log(chalk.white.bold('  Method:     ') + submission.attack_method);
      this.log('');
    } else {
      this.log(chalk.red.bold(`  FAIL`) + chalk.red(` - ${result.errors.length} validation error(s)`));
      this.log('');

      for (const err of result.errors) {
        this.log(chalk.red(`  ${err}`));
      }

      this.log('');
      return this.exit(1);
    }

    // ── Submit or defer ────────────────────────────────────

    if (flags['validate-only']) {
      this.log(chalk.dim('  Validation-only mode. Use --no-validate-only to attempt submission.'));
      this.log('');
    } else {
      this.log(
        chalk.yellow(
          '  API submission not yet integrated. Copy JSON to arena web interface.',
        ),
      );
      this.log('');
    }
  }
}

/**
 * `spear arena generate` command
 *
 * Generates an adversarial attack payload for a specific
 * Judgement Day Arena scenario. Supports strategy selection
 * and integrates with spear-26 (scenario engine) and
 * spear-27 (authority spoof templates).
 */

import { Command, Flags } from '@oclif/core';
import { writeFileSync } from 'node:fs';
import chalk from 'chalk';

import {
  SCENARIOS,
  getScenario,
  recommendStrategies,
  generateAttack,
  formatSubmission,
} from '@wigtn/spear-26-scenario-engine';
import type { ArenaChannel } from '@wigtn/shared';

// ─── Command ──────────────────────────────────────────────

export default class ArenaGenerate extends Command {
  static override description = 'Generate an adversarial attack payload for an arena scenario';

  static override examples = [
    '<%= config.bin %> arena generate --scenario emergency-triage',
    '<%= config.bin %> arena generate --scenario soc-cybersecurity --strategy authority-spoof',
    '<%= config.bin %> arena generate --scenario emergency-triage --output attack.json',
    '<%= config.bin %> arena generate --scenario aircraft-maintenance --model claude-opus-4.6',
  ];

  static override flags = {
    scenario: Flags.string({
      description: 'Scenario ID (e.g. emergency-triage)',
      required: true,
    }),
    channel: Flags.string({
      description: 'Attack channel (auto-selects based on scenario if omitted)',
    }),
    strategy: Flags.string({
      description: 'Attack strategy (auto-selects best if omitted)',
    }),
    output: Flags.string({
      char: 'o',
      description: 'Write attack JSON to file path',
    }),
    model: Flags.string({
      description: 'Target model (e.g. gpt-5.4, claude-opus-4.6)',
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(ArenaGenerate);

    // ── Look up scenario ───────────────────────────────────

    const scenario = getScenario(flags.scenario);
    if (!scenario) {
      const available = SCENARIOS.map((s) => s.id).join(', ');
      this.error(
        `Unknown scenario: "${flags.scenario}". Available: ${available}`,
        { exit: 1 },
      );
    }

    // ── Determine strategy and channel ─────────────────────

    const strategy = flags.strategy ?? recommendStrategies(scenario)[0]?.strategy ?? 'authority-spoof';
    const channel = (flags.channel ?? scenario.availableChannels[0] ?? 'text') as ArenaChannel;
    const model = flags.model ?? scenario.targetModels[0] ?? 'gpt-5.4';

    this.log('');
    this.log(chalk.red.bold('  ARENA ATTACK GENERATOR'));
    this.log(chalk.dim('  ════════════════════════════════════════'));
    this.log('');

    // ── Scenario info ──────────────────────────────────────

    this.log(chalk.white.bold('  Scenario:  ') + chalk.yellow(scenario.name));
    this.log(chalk.white.bold('  ID:        ') + scenario.id);
    this.log(chalk.white.bold('  Track:     ') + scenario.track.replace('_', ' '));
    this.log(chalk.white.bold('  Domain:    ') + scenario.domain.replace(/_/g, ' '));
    this.log(chalk.white.bold('  Channel:   ') + chalk.cyan(channel));
    this.log(chalk.white.bold('  Strategy:  ') + chalk.magenta(strategy));
    this.log(chalk.white.bold('  Model:     ') + chalk.dim(model));
    this.log(chalk.white.bold('  Status:    ') + (scenario.active ? chalk.green('Active') : chalk.dim('Upcoming')));
    this.log('');

    // ── Generate attack via spear-26 ─────────────────────

    const attack = generateAttack(scenario, { strategy: strategy as any, channel });

    // ── Display attack ─────────────────────────────────────

    this.log(chalk.white.bold('  Generated Payload:'));
    this.log(chalk.dim('  ────────────────────────────────────────'));
    this.log('');
    this.log(chalk.white(`  ${attack.payload}`));
    this.log('');

    const confidenceColor =
      attack.confidence === 'HIGH' ? chalk.green : attack.confidence === 'MEDIUM' ? chalk.yellow : chalk.red;
    this.log(chalk.white.bold('  Confidence: ') + confidenceColor(attack.confidence));
    this.log(chalk.white.bold('  Reasoning:  ') + chalk.dim(attack.reasoning));
    this.log('');

    // ── Submission structure ───────────────────────────────

    const submission = formatSubmission(attack, scenario);

    // ── Output ─────────────────────────────────────────────

    if (flags.output) {
      const outputJson = JSON.stringify(submission, null, 2);
      writeFileSync(flags.output, outputJson, 'utf-8');
      this.log(chalk.green.bold(`  Submission JSON written to: ${flags.output}`));
      this.log('');
    } else {
      this.log(chalk.white.bold('  Submission JSON:'));
      this.log(chalk.dim('  ────────────────────────────────────────'));
      this.log('');
      const lines = JSON.stringify(submission, null, 2).split('\n');
      for (const line of lines) {
        this.log(chalk.dim(`  ${line}`));
      }
      this.log('');
    }
  }
}

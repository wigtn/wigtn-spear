/**
 * `spear arena list` command
 *
 * Displays all Judgement Day Arena scenarios in a formatted table.
 * Supports filtering by wave (1 or 2) and track (induction or suppression).
 */

import { Command, Flags } from '@oclif/core';
import chalk from 'chalk';

import {
  SCENARIOS,
  getActiveScenarios,
} from '@wigtn/spear-26-scenario-engine';
import type { ArenaScenario } from '@wigtn/shared';

// ─── Command ──────────────────────────────────────────────

export default class ArenaList extends Command {
  static override description = 'List all Judgement Day Arena scenarios';

  static override examples = [
    '<%= config.bin %> arena list',
    '<%= config.bin %> arena list --wave 1',
    '<%= config.bin %> arena list --track induction',
  ];

  static override flags = {
    wave: Flags.integer({
      description: 'Filter by wave (1 or 2)',
      options: [1, 2] as unknown as string[],
    }),
    track: Flags.string({
      description: 'Filter by track',
      options: ['induction', 'suppression'],
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(ArenaList);

    let scenarios: readonly ArenaScenario[] = SCENARIOS;

    // Apply filters
    if (flags.wave) {
      scenarios = scenarios.filter((s) => s.wave === flags.wave);
    }
    if (flags.track) {
      const trackValue =
        flags.track === 'induction' ? 'action_induction' : 'action_suppression';
      scenarios = scenarios.filter((s) => s.track === trackValue);
    }

    // ── Header ─────────────────────────────────────────────

    this.log('');
    this.log(chalk.red.bold('  JUDGEMENT DAY AI RED TEAM ARENA'));
    this.log(chalk.dim('  ════════════════════════════════════════════════════════════════════════════'));
    this.log('');

    // ── Table Header ───────────────────────────────────────

    const colId = 'ID'.padEnd(30);
    const colTrack = 'Track'.padEnd(14);
    const colWave = 'Wave'.padEnd(6);
    const colDomain = 'Domain'.padEnd(24);
    const colAction = 'Target Action'.padEnd(30);
    const colChannels = 'Channels'.padEnd(24);
    const colStatus = 'Status';

    this.log(
      chalk.bold(
        `  ${colId} ${colTrack} ${colWave} ${colDomain} ${colAction} ${colChannels} ${colStatus}`,
      ),
    );
    this.log(chalk.dim('  ' + '─'.repeat(136)));

    // ── Rows ───────────────────────────────────────────────

    for (const s of scenarios) {
      const id = s.id.padEnd(30);
      const track =
        s.track === 'action_induction'
          ? chalk.yellow('Induction'.padEnd(14))
          : chalk.cyan('Suppression'.padEnd(14));
      const wave = String(s.wave).padEnd(6);
      const domain = s.domain.replace(/_/g, ' ').padEnd(24);
      const action = s.targetAction.padEnd(30);
      const channels = s.availableChannels.join(', ').padEnd(24);
      const status = s.active
        ? chalk.green.bold('Active')
        : chalk.dim('Upcoming');

      this.log(`  ${id} ${track} ${wave} ${domain} ${action} ${channels} ${status}`);
    }

    this.log('');

    // ── Summary ────────────────────────────────────────────

    const activeCount = getActiveScenarios().length;
    const upcomingCount = SCENARIOS.length - activeCount;

    this.log(
      chalk.white.bold(
        `  ${activeCount} active scenarios, ${upcomingCount} upcoming (Wave 2: Apr 27)`,
      ),
    );
    this.log('');
  }
}

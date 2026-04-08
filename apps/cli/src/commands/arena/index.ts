/**
 * `spear arena` topic
 *
 * Judgement Day AI Red Team Arena commands for generating,
 * listing, and submitting adversarial attack payloads.
 */

import { Command } from '@oclif/core';

export default class Arena extends Command {
  static override description = 'Judgement Day AI Red Team Arena commands';

  async run(): Promise<void> {
    this.log('Judgement Day AI Red Team Arena');
    this.log('');
    this.log('Available commands:');
    this.log('  spear arena list       List active arena scenarios');
    this.log('  spear arena generate   Generate attack payloads');
    this.log('  spear arena submit     Validate & format submissions');
    this.log('');
    this.log('Run "spear arena <command> --help" for more details.');
  }
}

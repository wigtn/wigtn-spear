/**
 * `spear fuzz` command
 *
 * Runs prompt injection fuzzing against AI/MCP targets. Loads fuzzing
 * payloads from specified sets (houyi, aishellJack, or all) and executes
 * them through the plugin system to discover prompt injection vulnerabilities.
 *
 * Pipeline flow:
 *   1. Load configuration (.spearrc.yaml + CLI overrides)
 *   2. Initialize database (create .spear/spear.db if needed)
 *   3. Parse payload sets from --payloads flag
 *   4. Initialize plugin registry with fuzzing modules
 *   5. Create scan record in DB
 *   6. Run fuzzing plugin with selected payloads
 *   7. Collect findings, insert into DB
 *   8. Update scan record with results and duration
 *   9. Display fuzzing progress and results
 *  10. Show kill chain coverage summary
 *
 * Payload sets:
 *   - houyi:       Houyi prompt injection payloads
 *   - aishellJack: AiShell Jack adversarial payloads
 *   - all:         All available payload sets combined
 */

import { Command, Flags } from '@oclif/core';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import chalk from 'chalk';
import ora from 'ora';

import {
  loadConfig,
  getDbPath,
  createLogger,
  SPEAR_NAME,
} from '@wigtn/shared';
import type {
  Finding as SharedFinding,
  ScanMode,
  ScanTarget,
  SpearConfig,
  PluginContext,
  Severity,
} from '@wigtn/shared';
import { createDatabase, closeDatabase, scans, findings as findingsTable } from '@wigtn/db';
import type { SpearDatabase, NewScan, NewFinding } from '@wigtn/db';
import { AuditLogger } from '@wigtn/db';
import { PluginRegistry } from '@wigtn/plugin-system';

import {
  formatFinding,
  formatDuration,
  formatGrade,
  countBySeverity,
  printBanner,
  severityColor,
} from '../utils/display.js';

// ─── Constants ────────────────────────────────────────────

/** Known payload sets for prompt injection fuzzing */
const KNOWN_PAYLOAD_SETS = ['houyi', 'aishellJack', 'all'] as const;
type PayloadSet = (typeof KNOWN_PAYLOAD_SETS)[number];

/** MITRE ATT&CK techniques relevant to prompt injection */
const PROMPT_INJECTION_MITRE = [
  'T1059',     // Command and Scripting Interpreter
  'T1190',     // Exploit Public-Facing Application
  'T1203',     // Exploitation for Client Execution
] as const;

// ─── Command ──────────────────────────────────────────────

export default class Fuzz extends Command {
  static override description = 'Run prompt injection fuzzing against AI/MCP targets';

  static override examples = [
    '<%= config.bin %> fuzz',
    '<%= config.bin %> fuzz --module prompt-injector --payloads houyi',
    '<%= config.bin %> fuzz --payloads houyi,aishellJack',
    '<%= config.bin %> fuzz --payloads all --mode aggressive',
  ];

  static override flags = {
    module: Flags.string({
      char: 'm',
      description: 'Fuzzing module to run',
      default: 'prompt-injector',
    }),
    payloads: Flags.string({
      char: 'p',
      description: 'Payload sets to use (comma-separated: houyi, aishellJack, all)',
      default: 'all',
    }),
    mode: Flags.string({
      description: 'Fuzz mode: safe (dry-run) or aggressive (live injection)',
      options: ['safe', 'aggressive'],
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
    target: Flags.string({
      char: 't',
      description: 'Target directory or endpoint (default: current directory)',
      default: '.',
    }),
    iterations: Flags.integer({
      char: 'n',
      description: 'Number of fuzzing iterations per payload',
      default: 1,
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(Fuzz);
    const targetDir = resolve(flags.target);

    // Print banner
    this.log(printBanner());
    this.log(chalk.yellow.bold('  Prompt Injection Fuzzer'));
    this.log('');

    // Validate target directory exists
    if (!existsSync(targetDir)) {
      this.error(`Target directory does not exist: ${targetDir}`, { exit: 1 });
    }

    // ── Step 1: Load Configuration ────────────────────────

    const configOverrides: Partial<SpearConfig> = {};
    if (flags.mode) configOverrides.mode = flags.mode as ScanMode;
    if (flags.verbose) configOverrides.verbose = true;

    const config = loadConfig(targetDir, configOverrides);
    const logger = createLogger(SPEAR_NAME, config.verbose);

    // ── Step 2: Initialize Database ───────────────────────

    const dbPath = getDbPath(targetDir, config);
    let db: SpearDatabase;
    try {
      db = createDatabase(dbPath);
      logger.debug('database initialized', { dbPath });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.error(`Failed to initialize database at ${dbPath}: ${message}`, { exit: 1 });
    }

    const audit = new AuditLogger(db, logger);

    // ── Step 3: Parse Payload Sets ────────────────────────

    const payloadSets = this.parsePayloadSets(flags.payloads);
    this.log(`  Payload sets: ${payloadSets.map((p) => chalk.cyan(p)).join(', ')}`);
    this.log(`  Module:       ${chalk.cyan(flags.module)}`);
    this.log(`  Iterations:   ${chalk.cyan(String(flags.iterations))}`);

    if (config.mode === 'aggressive') {
      this.log(chalk.yellow('  Mode: AGGRESSIVE') + chalk.dim(' -- live injection enabled'));
    } else {
      this.log(chalk.green('  Mode: SAFE') + chalk.dim(' -- dry-run, no live injection'));
    }
    this.log('');

    // ── Step 4: Initialize Plugin Registry ────────────────

    const registrySpinner = ora({ text: 'Loading fuzzing modules...', spinner: 'dots' }).start();

    const registry = new PluginRegistry();

    // Attempt to load fuzzing plugins dynamically
    try {
      const fuzzPluginMod = await import(`@wigtn/${flags.module}` as string).catch(() => null);
      if (fuzzPluginMod?.default) {
        registry.registerBuiltin([fuzzPluginMod.default], logger);
      }
    } catch {
      logger.debug('Fuzzing plugin could not be loaded dynamically', { module: flags.module });
    }

    registrySpinner.succeed(`Fuzzing module: ${chalk.bold(flags.module)} (${registry.size} plugin(s) loaded)`);

    // ── Step 5: Create Scan Record ────────────────────────

    const scanId = `fuzz_${randomUUID().slice(0, 12)}`;
    const startedAt = new Date().toISOString();
    const startTime = performance.now();

    const scanRecord: NewScan = {
      id: scanId,
      module: `fuzz:${flags.module}`,
      target: targetDir,
      mode: config.mode,
      status: 'running',
      startedAt,
    };

    try {
      db.insert(scans).values(scanRecord).run();
      logger.debug('fuzz scan record created', { scanId });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('failed to create scan record', { error: message });
    }

    audit.logScanStarted(`fuzz:${flags.module}`, targetDir, config.mode);

    // ── Step 6: Run Fuzzing ───────────────────────────────

    const fuzzSpinner = ora({
      text: `Fuzzing with ${chalk.bold(payloadSets.join(', '))} payloads...`,
      spinner: 'dots',
    }).start();

    const collectedFindings: SharedFinding[] = [];

    /** Kill chain coverage tracker: MITRE technique -> number of successful hits */
    const killChainCoverage: Map<string, number> = new Map();
    for (const technique of PROMPT_INJECTION_MITRE) {
      killChainCoverage.set(technique, 0);
    }

    try {
      const scanTarget: ScanTarget = {
        path: targetDir,
        exclude: config.exclude,
      };

      const pluginContext: PluginContext = {
        mode: config.mode,
        workDir: targetDir,
        config: {
          ...config,
          // Pass payload configuration through config for plugin consumption
          modules: payloadSets,
        },
        logger,
      };

      // Run fuzzing -- either through the plugin registry or direct payload iteration
      if (registry.size > 0) {
        // Run through plugin system
        const findingSource = registry.has(flags.module)
          ? registry.runPlugin(flags.module, scanTarget, pluginContext)
          : registry.runAll(scanTarget, pluginContext);

        for await (const finding of findingSource) {
          collectedFindings.push(finding);
          this.trackKillChain(finding, killChainCoverage);

          // Insert finding into DB
          this.insertFinding(db, scanId, finding, logger);

          // Real-time output
          fuzzSpinner.stop();
          this.log(`  ${formatFinding(finding)}`);
          fuzzSpinner.start(
            `Fuzzing... ${chalk.dim(`${collectedFindings.length} findings`)}`,
          );
        }
      } else {
        // No plugin loaded -- generate a dry-run report indicating
        // the fuzzer module is not yet installed
        fuzzSpinner.stop();
        this.log(
          chalk.yellow('  No fuzzing plugin loaded.') +
          chalk.dim(` Install the "${flags.module}" plugin to run live fuzzing.`),
        );
        this.log(
          chalk.dim('  Running payload set validation only...\n'),
        );

        // Generate placeholder findings based on payload sets for coverage analysis
        for (const payloadSet of payloadSets) {
          const finding: SharedFinding = {
            ruleId: `FUZZ-${payloadSet.toUpperCase()}-001`,
            severity: 'info' as Severity,
            message: `Payload set "${payloadSet}" registered for fuzzing (no live plugin available)`,
            mitreTechniques: [...PROMPT_INJECTION_MITRE],
            metadata: {
              pluginId: flags.module,
              payloadSet,
              status: 'pending',
              iterations: flags.iterations,
            },
          };

          collectedFindings.push(finding);
          this.insertFinding(db, scanId, finding, logger);
          this.log(`  ${formatFinding(finding)}`);
        }

        fuzzSpinner.start('Completing...');
      }

      const durationMs = Math.round(performance.now() - startTime);
      const counts = countBySeverity(collectedFindings);

      fuzzSpinner.succeed(
        `Fuzzing complete: ${chalk.bold(String(collectedFindings.length))} findings in ${chalk.dim(formatDuration(durationMs))}`,
      );

      // ── Step 7: Update Scan Record ──────────────────────

      try {
        const { eq } = await import('drizzle-orm');
        db.update(scans)
          .set({
            status: 'completed',
            findingsCritical: counts.critical,
            findingsHigh: counts.high,
            findingsMedium: counts.medium,
            findingsLow: counts.low,
            findingsInfo: counts.info,
            durationMs,
            completedAt: new Date().toISOString(),
          })
          .where(eq(scans.id, scanId))
          .run();
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn('failed to update scan record', { error: message });
      }

      audit.logScanCompleted(`fuzz:${flags.module}`, targetDir, config.mode, {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
        durationMs,
      });

      // ── Step 8: Display Results ───────────────────────────

      // Findings summary table
      this.log('');
      this.log(chalk.white.bold('  Fuzzing Results'));
      this.log(chalk.dim('  ════════════════════════'));

      const severities: Array<{ severity: Severity; count: number }> = [
        { severity: 'critical', count: counts.critical },
        { severity: 'high', count: counts.high },
        { severity: 'medium', count: counts.medium },
        { severity: 'low', count: counts.low },
        { severity: 'info', count: counts.info },
      ];

      for (const { severity, count } of severities) {
        const label = severity.toUpperCase().padEnd(8);
        const colorFn = severityColor(severity);
        const countStr = count > 0 ? colorFn(String(count)) : chalk.dim('0');
        this.log(`  ${colorFn(label)}  ${countStr}`);
      }

      this.log(chalk.dim('  ────────────────────────'));
      this.log(`  ${chalk.white.bold('TOTAL'.padEnd(8))}  ${chalk.white.bold(String(collectedFindings.length))}`);
      this.log('');

      // Kill chain coverage summary
      this.log(chalk.white.bold('  Kill Chain Coverage'));
      this.log(chalk.dim('  ════════════════════════'));

      for (const [technique, hitCount] of killChainCoverage) {
        const status = hitCount > 0
          ? chalk.red(`HIT (${hitCount})`)
          : chalk.green('MISS');
        this.log(`  ${chalk.white(technique.padEnd(12))}  ${status}`);
      }

      this.log('');
      this.log(`  Grade: ${formatGrade(counts)}`);
      this.log(`  Fuzz ID: ${chalk.dim(scanId)}`);
      this.log('');

      // ── Cleanup ─────────────────────────────────────────────
      closeDatabase(db);

      // Exit with non-zero if critical or high findings detected
      if (counts.critical > 0 || counts.high > 0) {
        this.exit(1);
      }
    } catch (err: unknown) {
      fuzzSpinner.fail('Fuzzing failed');

      const message = err instanceof Error ? err.message : String(err);
      logger.error('fuzzing execution failed', { error: message });

      // Update scan record to failed status
      try {
        const { eq } = await import('drizzle-orm');
        db.update(scans)
          .set({
            status: 'failed',
            completedAt: new Date().toISOString(),
            durationMs: Math.round(performance.now() - startTime),
          })
          .where(eq(scans.id, scanId))
          .run();
      } catch {
        // Best-effort DB update
      }

      audit.logScanFailed(`fuzz:${flags.module}`, targetDir, config.mode, message);
      closeDatabase(db);

      this.error(`Fuzzing failed: ${message}`, { exit: 2 });
    }
  }

  // ─── Private Helpers ───────────────────────────────────────

  /**
   * Parse the comma-separated --payloads flag into an array of validated set names.
   */
  private parsePayloadSets(input: string): PayloadSet[] {
    const raw = input.split(',').map((s) => s.trim().toLowerCase());
    const sets: PayloadSet[] = [];

    for (const name of raw) {
      if (name === 'all') {
        // 'all' expands to all known sets (excluding 'all' itself)
        return KNOWN_PAYLOAD_SETS.filter((s) => s !== 'all') as PayloadSet[];
      }

      if (KNOWN_PAYLOAD_SETS.includes(name as PayloadSet)) {
        sets.push(name as PayloadSet);
      } else {
        this.warn(`Unknown payload set "${name}", skipping. Known sets: ${KNOWN_PAYLOAD_SETS.join(', ')}`);
      }
    }

    if (sets.length === 0) {
      this.error(
        `No valid payload sets specified. Available: ${KNOWN_PAYLOAD_SETS.join(', ')}`,
        { exit: 1 },
      );
    }

    return sets;
  }

  /**
   * Track kill chain coverage from a finding's MITRE techniques.
   */
  private trackKillChain(
    finding: SharedFinding,
    coverage: Map<string, number>,
  ): void {
    if (!finding.mitreTechniques) return;

    for (const technique of finding.mitreTechniques) {
      const current = coverage.get(technique);
      if (current !== undefined) {
        coverage.set(technique, current + 1);
      } else {
        // Track techniques not in the initial set as well
        coverage.set(technique, 1);
      }
    }
  }

  /**
   * Insert a single finding into the database.
   */
  private insertFinding(
    db: SpearDatabase,
    scanId: string,
    finding: SharedFinding,
    logger: { warn(msg: string, data?: Record<string, unknown>): void },
  ): void {
    const findingId = `finding_${randomUUID().slice(0, 12)}`;
    const newFinding: NewFinding = {
      id: findingId,
      scanId,
      ruleId: finding.ruleId,
      severity: finding.severity,
      filePath: finding.file ?? null,
      lineNumber: finding.line ?? null,
      columnNumber: finding.column ?? null,
      secretMasked: finding.secretMasked ?? null,
      cvss: finding.cvss ?? null,
      mitreTechniques: finding.mitreTechniques
        ? JSON.stringify(finding.mitreTechniques)
        : null,
      remediation: finding.remediation ?? null,
      metadata: finding.metadata
        ? JSON.stringify(finding.metadata)
        : null,
    };

    try {
      db.insert(findingsTable).values(newFinding).run();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn('failed to insert finding', {
        findingId,
        error: message,
      });
    }
  }
}

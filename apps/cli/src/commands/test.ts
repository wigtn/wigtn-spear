/**
 * `spear test` command
 *
 * Runs AI/MCP attack test modules against a target. Uses the plugin
 * registry to load and execute specified (or all) attack modules,
 * collecting findings via the AsyncGenerator streaming pipeline.
 *
 * Pipeline flow:
 *   1. Load configuration (.spearrc.yaml + CLI overrides)
 *   2. Initialize database (create .spear/spear.db if needed)
 *   3. Load rules from YAML files
 *   4. Initialize plugin registry with builtin plugins
 *   5. Create scan record in DB
 *   6. Run selected plugin(s) via the registry
 *   7. Collect findings, insert into DB
 *   8. Update scan record with results and duration
 *   9. Display results in formatted table
 *
 * Modes:
 *   - safe (default): Read-only, no network access, no live verification
 *   - aggressive: Enables live secret verification via network calls
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
  SPEAR_VERSION,
  SPEAR_NAME,
} from '@wigtn/shared';
import type {
  Finding as SharedFinding,
  ScanMode,
  ScanTarget,
  SpearConfig,
  PluginContext,
} from '@wigtn/shared';
import { createDatabase, closeDatabase, scans, findings as findingsTable } from '@wigtn/db';
import type { SpearDatabase, NewScan, NewFinding } from '@wigtn/db';
import { AuditLogger } from '@wigtn/db';
import { PluginRegistry } from '@wigtn/plugin-system';
import { loadRules } from '@wigtn/rules-engine';

import {
  formatFinding,
  formatSummary,
  formatDuration,
  formatGrade,
  countBySeverity,
  printBanner,
} from '../utils/display.js';

// ─── Command ──────────────────────────────────────────────

export default class Test extends Command {
  static override description = 'Run AI/MCP attack test modules against a target';

  static override examples = [
    '<%= config.bin %> test',
    '<%= config.bin %> test --module secret-scanner',
    '<%= config.bin %> test --module git-miner --mode aggressive',
    '<%= config.bin %> test --module all --mode safe',
  ];

  static override flags = {
    module: Flags.string({
      char: 'm',
      description: 'Specific attack module to run (default: all)',
      default: 'all',
    }),
    mode: Flags.string({
      description: 'Test mode: safe (read-only) or aggressive (live verification)',
      options: ['safe', 'aggressive'],
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
    'rules-dir': Flags.string({
      description: 'Custom rules directory',
    }),
    target: Flags.string({
      char: 't',
      description: 'Target directory to test (default: current directory)',
      default: '.',
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(Test);
    const targetDir = resolve(flags.target);

    // Print banner
    this.log(printBanner());

    // Validate target directory exists
    if (!existsSync(targetDir)) {
      this.error(`Target directory does not exist: ${targetDir}`, { exit: 1 });
    }

    // ── Step 1: Load Configuration ────────────────────────

    const configOverrides: Partial<SpearConfig> = {};
    if (flags.mode) configOverrides.mode = flags.mode as ScanMode;
    if (flags.verbose) configOverrides.verbose = true;
    if (flags['rules-dir']) configOverrides.rulesDir = flags['rules-dir'];
    if (flags.module && flags.module !== 'all') {
      configOverrides.modules = [flags.module];
    }

    const config = loadConfig(targetDir, configOverrides);
    const logger = createLogger(SPEAR_NAME, config.verbose);

    logger.info('test configuration loaded', {
      mode: config.mode,
      target: targetDir,
      module: flags.module,
    });

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

    // ── Step 3: Load Rules ────────────────────────────────

    const spinner = ora({ text: 'Loading rules...', spinner: 'dots' }).start();

    let rulesDir = config.rulesDir;
    if (!rulesDir) {
      const localRulesDir = resolve(targetDir, 'rules');
      if (existsSync(localRulesDir)) {
        rulesDir = localRulesDir;
      } else {
        const monorepoRulesDir = resolve(targetDir, '../../rules');
        if (existsSync(monorepoRulesDir)) {
          rulesDir = monorepoRulesDir;
        }
      }
    } else {
      rulesDir = resolve(targetDir, rulesDir);
    }

    let rules: Awaited<ReturnType<typeof loadRules>> = [];
    if (rulesDir && existsSync(rulesDir)) {
      rules = await loadRules(rulesDir, logger);
      spinner.succeed(`Loaded ${chalk.bold(String(rules.length))} rules from ${chalk.dim(rulesDir)}`);
    } else {
      spinner.warn('No rules directory found. Test will rely on plugin-bundled rules.');
      logger.warn('no rules directory found', { rulesDir });
    }

    // ── Step 4: Initialize Plugin Registry ────────────────

    const registrySpinner = ora({ text: 'Loading attack modules...', spinner: 'dots' }).start();

    const registry = new PluginRegistry();

    // Import all builtin plugins dynamically
    try {
      const pluginImports = await Promise.all([
        import('@wigtn/spear-01-secret-scanner' as string).catch(() => null),
        import('@wigtn/spear-02-git-miner' as string).catch(() => null),
        import('@wigtn/spear-03-env-exfil' as string).catch(() => null),
        import('@wigtn/spear-04-mcp-poisoner' as string).catch(() => null),
        import('@wigtn/spear-05-dep-confusion' as string).catch(() => null),
        import('@wigtn/spear-06-prompt-injector' as string).catch(() => null),
        import('@wigtn/spear-08-supply-chain' as string).catch(() => null),
        import('@wigtn/spear-10-agent-manipulator' as string).catch(() => null),
        import('@wigtn/spear-11-cicd-exploiter' as string).catch(() => null),
        import('@wigtn/spear-12-container-audit' as string).catch(() => null),
        import('@wigtn/spear-13-cloud-credential' as string).catch(() => null),
        import('@wigtn/spear-14-ssrf-tester' as string).catch(() => null),
        import('@wigtn/spear-15-ide-audit' as string).catch(() => null),
        import('@wigtn/spear-16-webhook-scanner' as string).catch(() => null),
        import('@wigtn/spear-17-llm-exploiter' as string).catch(() => null),
        import('@wigtn/spear-19-social-eng' as string).catch(() => null),
        import('@wigtn/spear-21-distillation' as string).catch(() => null),
        import('@wigtn/spear-18-tls-recon' as string).catch(() => null),
        import('@wigtn/spear-22-infra-intel' as string).catch(() => null),
        import('@wigtn/spear-23-live-prompt-inject' as string).catch(() => null),
        import('@wigtn/spear-24-mcp-live-test' as string).catch(() => null),
        import('@wigtn/spear-25-endpoint-prober' as string).catch(() => null),
      ]);

      const builtinPlugins = pluginImports
        .map((mod) => mod?.default)
        .filter(Boolean);

      if (builtinPlugins.length > 0) {
        registry.registerBuiltin(builtinPlugins, logger);
      }
    } catch {
      logger.debug('Some builtin plugins could not be loaded');
    }

    const registeredCount = registry.size;
    registrySpinner.succeed(`Loaded ${chalk.bold(String(registeredCount))} attack module(s)`);

    // ── Step 5: Create Scan Record ────────────────────────

    const scanId = `test_${randomUUID().slice(0, 12)}`;
    const moduleName = flags.module ?? 'all';
    const startedAt = new Date().toISOString();
    const startTime = performance.now();

    const scanRecord: NewScan = {
      id: scanId,
      module: moduleName,
      target: targetDir,
      mode: config.mode,
      status: 'running',
      startedAt,
    };

    try {
      db.insert(scans).values(scanRecord).run();
      logger.debug('test scan record created', { scanId });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('failed to create scan record', { error: message });
    }

    audit.logScanStarted(moduleName, targetDir, config.mode);

    // ── Step 6: Run Attack Module(s) ──────────────────────

    const testSpinner = ora({
      text: `Running attack test: ${chalk.bold(moduleName)}...`,
      spinner: 'dots',
    }).start();

    // Display mode information
    if (config.mode === 'aggressive') {
      this.log(chalk.yellow('  Mode: AGGRESSIVE') + chalk.dim(' -- live verification enabled'));
    } else {
      this.log(chalk.green('  Mode: SAFE') + chalk.dim(' -- read-only, no network access'));
    }

    const collectedFindings: SharedFinding[] = [];

    try {
      const scanTarget: ScanTarget = {
        path: targetDir,
        exclude: config.exclude,
      };

      const pluginContext: PluginContext = {
        mode: config.mode,
        workDir: targetDir,
        config,
        logger,
      };

      // Determine which plugins to run
      let findingSource: AsyncGenerator<SharedFinding>;
      if (moduleName === 'all') {
        findingSource = registry.runAll(scanTarget, pluginContext);
      } else {
        findingSource = registry.runPlugin(moduleName, scanTarget, pluginContext);
      }

      for await (const finding of findingSource) {
        collectedFindings.push(finding);

        // Insert finding into DB
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

        // Real-time output: print each finding as discovered
        testSpinner.stop();
        this.log(`  ${formatFinding(finding)}`);
        testSpinner.start(`Running test... ${chalk.dim(`${collectedFindings.length} findings`)}`);
      }

      const durationMs = Math.round(performance.now() - startTime);
      const counts = countBySeverity(collectedFindings);

      testSpinner.succeed(
        `Test complete: ${chalk.bold(String(collectedFindings.length))} findings in ${chalk.dim(formatDuration(durationMs))}`,
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

      audit.logScanCompleted(moduleName, targetDir, config.mode, {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
        durationMs,
      });

      // ── Step 8: Display Results ───────────────────────────

      this.log(formatSummary(collectedFindings));
      this.log(`  Grade: ${formatGrade(counts)}`);
      this.log(`  Test ID: ${chalk.dim(scanId)}`);
      this.log('');

      // ── Cleanup ─────────────────────────────────────────────
      closeDatabase(db);

      // Exit with non-zero if critical or high findings detected
      if (counts.critical > 0 || counts.high > 0) {
        this.exit(1);
      }
    } catch (err: unknown) {
      testSpinner.fail('Test failed');

      const message = err instanceof Error ? err.message : String(err);
      logger.error('test execution failed', { error: message });

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

      audit.logScanFailed(moduleName, targetDir, config.mode, message);
      closeDatabase(db);

      this.error(`Test failed: ${message}`, { exit: 2 });
    }
  }
}

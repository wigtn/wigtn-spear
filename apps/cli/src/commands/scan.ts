/**
 * `spear scan [target]` command
 *
 * The primary command for WIGTN-SPEAR. Runs a security scan against
 * a target directory, collecting findings via the scan pipeline and
 * plugin registry.
 *
 * Pipeline flow:
 *   1. Load configuration (.spearrc.yaml + CLI overrides)
 *   2. Initialize database (create .spear/spear.db if needed)
 *   3. Load rules from YAML files
 *   4. Create scan record in DB
 *   5. Run scan pipeline (Aho-Corasick -> Regex -> Entropy)
 *   6. Collect findings, insert into DB
 *   7. Update scan record with results and duration
 *   8. Generate report in requested format (text/sarif/json)
 *   9. Display summary
 *
 * Modes:
 *   - safe (default): Read-only, no network access, no live verification
 *   - aggressive: Enables live secret verification via network calls
 */

import { Args, Command, Flags } from '@oclif/core';
import { resolve } from 'node:path';
import { existsSync, writeFileSync } from 'node:fs';
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
  SpearConfig,
  ScanTarget,
} from '@wigtn/shared';
import { scanPipeline, loadSpearignore } from '@wigtn/core';
import { createDatabase, closeDatabase, scans, findings as findingsTable } from '@wigtn/db';
import type { SpearDatabase, NewScan, NewFinding } from '@wigtn/db';
import { AuditLogger } from '@wigtn/db';
import { loadRules } from '@wigtn/rules-engine';
import { SARIFReporter, JSONReporter } from '@wigtn/reporters';

import {
  formatFinding,
  formatSummary,
  formatDuration,
  formatGrade,
  countBySeverity,
  printBanner,
} from '../utils/display.js';

// ─── Command ──────────────────────────────────────────────

export default class Scan extends Command {
  static override description = 'Run a security scan against a target directory';

  static override examples = [
    '<%= config.bin %> scan',
    '<%= config.bin %> scan ./my-project',
    '<%= config.bin %> scan --mode aggressive --output sarif',
    '<%= config.bin %> scan --module secret-scanner --output json -o report.json',
  ];

  static override args = {
    target: Args.string({
      description: 'Target directory to scan (default: current directory)',
      required: false,
      default: '.',
    }),
  };

  static override flags = {
    module: Flags.string({
      char: 'm',
      description: 'Specific module to run (default: all)',
      multiple: true,
    }),
    mode: Flags.string({
      description: 'Scan mode: safe (read-only) or aggressive (live verification)',
      options: ['safe', 'aggressive'],
    }),
    output: Flags.string({
      char: 'f',
      description: 'Output format',
      options: ['text', 'sarif', 'json'],
    }),
    'output-file': Flags.string({
      char: 'o',
      description: 'Write report to file instead of stdout',
    }),
    'git-depth': Flags.integer({
      description: 'Number of git commits to scan (0 = HEAD only, -1 = unlimited)',
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
    'rules-dir': Flags.string({
      description: 'Custom rules directory',
    }),
  };

  async run(): Promise<void> {
    const { args, flags } = await this.parse(Scan);
    const targetDir = resolve(args.target);

    // Print banner
    this.log(printBanner());

    // Validate target directory exists
    if (!existsSync(targetDir)) {
      this.error(`Target directory does not exist: ${targetDir}`, { exit: 1 });
    }

    // ── Step 1: Load Configuration ────────────────────────

    const configOverrides: Partial<SpearConfig> = {};
    if (flags.mode) configOverrides.mode = flags.mode as ScanMode;
    if (flags.output) configOverrides.outputFormat = flags.output as SpearConfig['outputFormat'];
    if (flags['git-depth'] != null) configOverrides.gitDepth = flags['git-depth'];
    if (flags.verbose) configOverrides.verbose = true;
    if (flags['rules-dir']) configOverrides.rulesDir = flags['rules-dir'];
    if (flags.module) configOverrides.modules = flags.module;

    const config = loadConfig(targetDir, configOverrides);
    const logger = createLogger(SPEAR_NAME, config.verbose);

    logger.info('scan configuration loaded', {
      mode: config.mode,
      target: targetDir,
      modules: config.modules,
      outputFormat: config.outputFormat,
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

    // Determine rules directory: config override > project-relative > bundled rules
    let rulesDir = config.rulesDir;
    if (!rulesDir) {
      // Try project-local rules/ directory first
      const localRulesDir = resolve(targetDir, 'rules');
      if (existsSync(localRulesDir)) {
        rulesDir = localRulesDir;
      } else {
        // Fall back to monorepo rules/ directory (development mode)
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
      spinner.warn('No rules directory found. Scan will produce no findings from rule matching.');
      logger.warn('no rules directory found', { rulesDir });
    }

    // ── Step 4: Create Scan Record ────────────────────────

    const scanId = `scan_${randomUUID().slice(0, 12)}`;
    const scanModule = config.modules.includes('all')
      ? 'all'
      : config.modules.join(',');
    const startedAt = new Date().toISOString();
    const startTime = performance.now();

    const scanRecord: NewScan = {
      id: scanId,
      module: scanModule,
      target: targetDir,
      mode: config.mode,
      status: 'running',
      startedAt,
    };

    try {
      db.insert(scans).values(scanRecord).run();
      logger.debug('scan record created', { scanId });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('failed to create scan record', { error: message });
    }

    audit.logScanStarted(scanModule, targetDir, config.mode);

    // ── Step 5: Run Scan Pipeline ─────────────────────────

    const scanSpinner = ora({
      text: `Scanning ${chalk.dim(targetDir)}...`,
      spinner: 'dots',
    }).start();

    const collectedFindings: SharedFinding[] = [];
    let filesProcessed = 0;
    let filesMatched = 0;

    try {
      // Display mode information
      if (config.mode === 'aggressive') {
        this.log(chalk.yellow('  Mode: AGGRESSIVE') + chalk.dim(' -- live verification enabled'));
      } else {
        this.log(chalk.green('  Mode: SAFE') + chalk.dim(' -- read-only, no network access'));
      }

      // Build scan target
      const scanTarget: ScanTarget = {
        path: targetDir,
        exclude: config.exclude,
      };

      // Load spearignore
      const spearignore = loadSpearignore(targetDir);

      // Run the scan pipeline if we have rules
      if (rules.length > 0) {
        const pipelineGen = scanPipeline(scanTarget, rules, {
          mode: config.mode,
          spearignore,
          onFileProcessed: (filePath, matched) => {
            filesProcessed++;
            if (matched) filesMatched++;
            if (filesProcessed % 100 === 0) {
              scanSpinner.text = `Scanning... ${chalk.dim(`${filesProcessed} files processed, ${collectedFindings.length} findings`)}`;
            }
          },
          onError: (filePath, error) => {
            logger.warn('pipeline error on file', { filePath, error: error.message });
          },
        });

        for await (const finding of pipelineGen) {
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

          // Real-time output in text mode: print each finding as discovered
          if (config.outputFormat === 'text') {
            scanSpinner.stop();
            this.log(`  ${formatFinding(finding)}`);
            scanSpinner.start(`Scanning... ${chalk.dim(`${filesProcessed} files, ${collectedFindings.length} findings`)}`);
          }
        }
      }

      const durationMs = Math.round(performance.now() - startTime);
      const counts = countBySeverity(collectedFindings);

      scanSpinner.succeed(
        `Scan complete: ${chalk.bold(String(filesProcessed))} files scanned, ` +
        `${chalk.bold(String(collectedFindings.length))} findings in ${chalk.dim(formatDuration(durationMs))}`,
      );

      // ── Step 6: Update Scan Record ──────────────────────

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

      audit.logScanCompleted(scanModule, targetDir, config.mode, {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
        durationMs,
      });

      // ── Step 7: Generate Report ───────────────────────────

      if (config.outputFormat === 'sarif' || flags['output-file']?.endsWith('.sarif.json')) {
        const reporter = new SARIFReporter();
        const sarifJson = reporter.stringify(collectedFindings, {
          module: scanModule,
          target: targetDir,
          version: SPEAR_VERSION,
        });

        if (flags['output-file']) {
          const outputPath = resolve(flags['output-file']);
          writeFileSync(outputPath, sarifJson, 'utf-8');
          this.log(`\n  ${chalk.green('Report saved:')} ${chalk.dim(outputPath)}`);
          audit.logReportGenerated('sarif', outputPath);
        } else {
          this.log(sarifJson);
        }
      } else if (config.outputFormat === 'json') {
        const reporter = new JSONReporter();
        const jsonStr = reporter.stringify(collectedFindings, {
          module: scanModule,
          target: targetDir,
          version: SPEAR_VERSION,
          mode: config.mode,
          durationMs,
          startedAt,
          completedAt: new Date().toISOString(),
        });

        if (flags['output-file']) {
          const outputPath = resolve(flags['output-file']);
          writeFileSync(outputPath, jsonStr, 'utf-8');
          this.log(`\n  ${chalk.green('Report saved:')} ${chalk.dim(outputPath)}`);
          audit.logReportGenerated('json', outputPath);
        } else {
          this.log(jsonStr);
        }
      } else {
        // text format: summary has already been streamed; show summary table
        this.log(formatSummary(collectedFindings));
        this.log(`  Grade: ${formatGrade(counts)}`);
        this.log(`  Scan ID: ${chalk.dim(scanId)}`);
        this.log('');

        // Also write to file if requested
        if (flags['output-file']) {
          const reporter = new JSONReporter();
          const jsonStr = reporter.stringify(collectedFindings, {
            module: scanModule,
            target: targetDir,
            version: SPEAR_VERSION,
            mode: config.mode,
            durationMs,
            startedAt,
            completedAt: new Date().toISOString(),
          });
          const outputPath = resolve(flags['output-file']);
          writeFileSync(outputPath, jsonStr, 'utf-8');
          this.log(`  ${chalk.green('Report saved:')} ${chalk.dim(outputPath)}`);
          audit.logReportGenerated('json', outputPath);
        }
      }

      // ── Cleanup ─────────────────────────────────────────────
      closeDatabase(db);

      // Exit with non-zero if critical or high findings detected
      if (counts.critical > 0 || counts.high > 0) {
        this.exit(1);
      }
    } catch (err: unknown) {
      scanSpinner.fail('Scan failed');

      const message = err instanceof Error ? err.message : String(err);
      logger.error('scan pipeline failed', { error: message });

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

      audit.logScanFailed(scanModule, targetDir, config.mode, message);
      closeDatabase(db);

      this.error(`Scan failed: ${message}`, { exit: 2 });
    }
  }
}

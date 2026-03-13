/**
 * `spear audit [target]` command
 *
 * Runs a comprehensive security audit against a target directory,
 * generating both an HTML report and a CVSS security score.
 *
 * Pipeline flow:
 *   1. Load configuration (.spearrc.yaml + CLI overrides)
 *   2. Initialize database (create .spear/spear.db if needed)
 *   3. Load rules from YAML files
 *   4. Create scan record in DB
 *   5. Run scan pipeline (Aho-Corasick -> Regex -> Entropy)
 *   6. Collect findings, insert into DB
 *   7. Update scan record with results and duration
 *   8. Calculate CVSS security score
 *   9. Generate HTML report and save to .spear/report.html
 *  10. Display security grade in terminal
 *
 * Modes:
 *   - safe (default): Read-only, no network access, no live verification
 *   - aggressive: Enables live secret verification via network calls
 */

import { Args, Command, Flags } from '@oclif/core';
import { resolve, dirname } from 'node:path';
import { existsSync, writeFileSync, mkdirSync } from 'node:fs';
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
import { scanPipeline, loadSpearignore, calculateSecurityScore } from '@wigtn/core';
import { createDatabase, closeDatabase, scans, findings as findingsTable } from '@wigtn/db';
import type { SpearDatabase, NewScan, NewFinding } from '@wigtn/db';
import { AuditLogger } from '@wigtn/db';
import { loadRules } from '@wigtn/rules-engine';
import { generateHtmlReport } from '@wigtn/reporters';

import {
  formatFinding,
  formatSummary,
  formatDuration,
  countBySeverity,
  printBanner,
} from '../utils/display.js';

// ─── Grade Display Helper ─────────────────────────────────

function formatSecurityGrade(grade: string, score: number): string {
  const gradeColors: Record<string, (text: string) => string> = {
    A: (text: string) => chalk.green.bold(text),
    B: (text: string) => chalk.green(text),
    C: (text: string) => chalk.yellow(text),
    D: (text: string) => chalk.red(text),
    F: (text: string) => chalk.red.bold(text),
  };

  const colorFn = gradeColors[grade] ?? ((text: string) => text);
  return colorFn(`${grade} (${score}/100)`);
}

// ─── Command ──────────────────────────────────────────────

export default class Audit extends Command {
  static override description = 'Run a security audit and generate an HTML report with CVSS score';

  static override examples = [
    '<%= config.bin %> audit',
    '<%= config.bin %> audit ./my-project',
    '<%= config.bin %> audit --mode aggressive',
    '<%= config.bin %> audit --output-file ./custom-report.html',
  ];

  static override args = {
    target: Args.string({
      description: 'Target directory to audit (default: current directory)',
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
    'output-file': Flags.string({
      char: 'o',
      description: 'Write HTML report to a custom path (default: .spear/report.html)',
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
    const { args, flags } = await this.parse(Audit);
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
    if (flags.verbose) configOverrides.verbose = true;
    if (flags['rules-dir']) configOverrides.rulesDir = flags['rules-dir'];
    if (flags.module) configOverrides.modules = flags.module;

    const config = loadConfig(targetDir, configOverrides);
    const logger = createLogger(SPEAR_NAME, config.verbose);

    logger.info('audit configuration loaded', {
      mode: config.mode,
      target: targetDir,
      modules: config.modules,
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
      spinner.warn('No rules directory found. Audit will produce no findings from rule matching.');
      logger.warn('no rules directory found', { rulesDir });
    }

    // ── Step 4: Create Scan Record ────────────────────────

    const scanId = `audit_${randomUUID().slice(0, 12)}`;
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
      logger.debug('audit scan record created', { scanId });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('failed to create scan record', { error: message });
    }

    audit.logScanStarted(scanModule, targetDir, config.mode);

    // ── Step 5: Run Scan Pipeline ─────────────────────────

    const scanSpinner = ora({
      text: `Auditing ${chalk.dim(targetDir)}...`,
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
              scanSpinner.text = `Auditing... ${chalk.dim(`${filesProcessed} files processed, ${collectedFindings.length} findings`)}`;
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

          // Real-time output: print each finding as discovered
          scanSpinner.stop();
          this.log(`  ${formatFinding(finding)}`);
          scanSpinner.start(`Auditing... ${chalk.dim(`${filesProcessed} files, ${collectedFindings.length} findings`)}`);
        }
      }

      const durationMs = Math.round(performance.now() - startTime);
      const counts = countBySeverity(collectedFindings);
      const completedAt = new Date().toISOString();

      scanSpinner.succeed(
        `Audit complete: ${chalk.bold(String(filesProcessed))} files scanned, ` +
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
            completedAt,
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

      // ── Step 7: Calculate Security Score ────────────────

      const scoreResult = calculateSecurityScore(collectedFindings);

      // ── Step 8: Generate HTML Report ────────────────────

      const reportSpinner = ora({ text: 'Generating HTML report...', spinner: 'dots' }).start();

      const htmlReport = generateHtmlReport(collectedFindings, {
        module: scanModule,
        target: targetDir,
        version: SPEAR_VERSION,
        mode: config.mode,
        durationMs,
        startedAt,
        completedAt,
      });

      // Determine output path
      const outputPath = flags['output-file']
        ? resolve(flags['output-file'])
        : resolve(targetDir, '.spear', 'report.html');

      // Ensure parent directory exists
      const outputDir = dirname(outputPath);
      if (!existsSync(outputDir)) {
        mkdirSync(outputDir, { recursive: true });
      }

      writeFileSync(outputPath, htmlReport, 'utf-8');
      reportSpinner.succeed(`HTML report saved to ${chalk.dim(outputPath)}`);

      audit.logReportGenerated('html', outputPath);

      // ── Step 9: Display Results ─────────────────────────

      this.log(formatSummary(collectedFindings));

      // Security Score Display
      this.log(chalk.white.bold('  Security Score'));
      this.log(chalk.dim('  ════════════════════════'));
      this.log(`  Grade: ${formatSecurityGrade(scoreResult.grade, scoreResult.score)}`);
      this.log(`  Score: ${chalk.white.bold(String(scoreResult.score))}${chalk.dim('/100')}`);
      this.log(`  Penalty: ${chalk.dim(`-${scoreResult.totalPenalty} points`)}`);

      if (scoreResult.moduleBreakdown.length > 0) {
        this.log('');
        this.log(chalk.dim('  Module Breakdown:'));
        for (const mod of scoreResult.moduleBreakdown) {
          this.log(`    ${chalk.white(mod.module.padEnd(16))} ${chalk.dim('-')}${chalk.red(String(mod.penalty).padStart(3))} pts  ${chalk.dim(`(${mod.counts.total} findings)`)}`);
        }
      }

      this.log('');
      this.log(`  Report: ${chalk.underline(outputPath)}`);
      this.log(`  Scan ID: ${chalk.dim(scanId)}`);
      this.log('');

      // ── Cleanup ─────────────────────────────────────────

      closeDatabase(db);

      // Exit with non-zero if critical or high findings detected
      if (counts.critical > 0 || counts.high > 0) {
        this.exit(1);
      }
    } catch (err: unknown) {
      scanSpinner.fail('Audit failed');

      const message = err instanceof Error ? err.message : String(err);
      logger.error('audit pipeline failed', { error: message });

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

      this.error(`Audit failed: ${message}`, { exit: 2 });
    }
  }
}

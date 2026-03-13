/**
 * `spear report` command
 *
 * Generates a report from a previously completed scan stored in the local
 * SPEAR database. Supports SARIF and JSON output formats.
 *
 * If no --scan-id is specified, generates a report from the most recent scan.
 */

import { Command, Flags } from '@oclif/core';
import { resolve } from 'node:path';
import { existsSync, writeFileSync } from 'node:fs';
import chalk from 'chalk';

import {
  loadConfig,
  getDbPath,
  createLogger,
  SPEAR_VERSION,
  SPEAR_NAME,
} from '@wigtn/shared';
import type { Finding as SharedFinding } from '@wigtn/shared';
import {
  createDatabase,
  closeDatabase,
  scans,
  findings as findingsTable,
  AuditLogger,
} from '@wigtn/db';
import type { SpearDatabase } from '@wigtn/db';
import { SARIFReporter, JSONReporter } from '@wigtn/reporters';
import { printBanner, formatSummary, countBySeverity, formatGrade } from '../utils/display.js';

// ─── Command ──────────────────────────────────────────────

export default class Report extends Command {
  static override description = 'Generate a report from a completed scan';

  static override examples = [
    '<%= config.bin %> report --format sarif',
    '<%= config.bin %> report --format json --output report.json',
    '<%= config.bin %> report --scan-id scan_abc123 --format sarif -o results.sarif.json',
  ];

  static override flags = {
    format: Flags.string({
      char: 'f',
      description: 'Output format',
      options: ['sarif', 'json'],
      default: 'json',
    }),
    'scan-id': Flags.string({
      char: 's',
      description: 'Scan ID to generate report for (default: most recent)',
    }),
    output: Flags.string({
      char: 'o',
      description: 'Write report to file instead of stdout',
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
  };

  async run(): Promise<void> {
    const { flags } = await this.parse(Report);

    this.log(printBanner());

    const cwd = process.cwd();
    const config = loadConfig(cwd, { verbose: flags.verbose });
    const logger = createLogger(SPEAR_NAME, config.verbose);

    // ── Open Database ─────────────────────────────────────

    const dbPath = getDbPath(cwd, config);
    if (!existsSync(dbPath)) {
      this.error(
        `No SPEAR database found at ${dbPath}.\n` +
        `Run ${chalk.cyan('spear init')} and ${chalk.cyan('spear scan')} first.`,
        { exit: 1 },
      );
    }

    let db: SpearDatabase;
    try {
      db = createDatabase(dbPath);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.error(`Failed to open database: ${message}`, { exit: 1 });
    }

    const audit = new AuditLogger(db, logger);

    try {
      // ── Find Scan ─────────────────────────────────────────

      const { eq, desc } = await import('drizzle-orm');

      let scanRow;
      if (flags['scan-id']) {
        const rows = db
          .select()
          .from(scans)
          .where(eq(scans.id, flags['scan-id']))
          .all();

        if (rows.length === 0) {
          this.error(`Scan not found: ${flags['scan-id']}`, { exit: 1 });
        }
        scanRow = rows[0]!;
      } else {
        // Get most recent completed scan
        const rows = db
          .select()
          .from(scans)
          .where(eq(scans.status, 'completed'))
          .orderBy(desc(scans.createdAt))
          .limit(1)
          .all();

        if (rows.length === 0) {
          this.error(
            `No completed scans found.\nRun ${chalk.cyan('spear scan')} first.`,
            { exit: 1 },
          );
        }
        scanRow = rows[0]!;
      }

      this.log(`  Scan: ${chalk.dim(scanRow.id)}`);
      this.log(`  Target: ${chalk.dim(scanRow.target)}`);
      this.log(`  Status: ${chalk.dim(scanRow.status)}`);
      this.log('');

      // ── Load Findings ───────────────────────────────────────

      const findingRows = db
        .select()
        .from(findingsTable)
        .where(eq(findingsTable.scanId, scanRow.id))
        .all();

      // Convert DB findings back to shared Finding type
      const sharedFindings: SharedFinding[] = findingRows.map((row) => {
        const finding: SharedFinding = {
          ruleId: row.ruleId,
          severity: row.severity as SharedFinding['severity'],
          message: `${row.ruleId}: Finding in ${row.filePath ?? 'unknown'}`,
          file: row.filePath ?? undefined,
          line: row.lineNumber ?? undefined,
          column: row.columnNumber ?? undefined,
          secretMasked: row.secretMasked ?? undefined,
          cvss: row.cvss ?? undefined,
          mitreTechniques: row.mitreTechniques
            ? (JSON.parse(row.mitreTechniques) as string[])
            : undefined,
          remediation: row.remediation ?? undefined,
          metadata: row.metadata
            ? (JSON.parse(row.metadata) as Record<string, unknown>)
            : undefined,
        };
        return finding;
      });

      this.log(`  Found ${chalk.bold(String(sharedFindings.length))} findings.\n`);

      // ── Generate Report ───────────────────────────────────

      let reportStr: string;

      if (flags.format === 'sarif') {
        const reporter = new SARIFReporter();
        reportStr = reporter.stringify(sharedFindings, {
          module: scanRow.module,
          target: scanRow.target,
          version: SPEAR_VERSION,
        });
      } else {
        const reporter = new JSONReporter();
        reportStr = reporter.stringify(sharedFindings, {
          module: scanRow.module,
          target: scanRow.target,
          version: SPEAR_VERSION,
          mode: scanRow.mode as 'safe' | 'aggressive',
          durationMs: scanRow.durationMs ?? 0,
          startedAt: scanRow.startedAt ?? scanRow.createdAt,
          completedAt: scanRow.completedAt ?? scanRow.createdAt,
        });
      }

      // ── Output ──────────────────────────────────────────────

      if (flags.output) {
        const outputPath = resolve(flags.output);
        writeFileSync(outputPath, reportStr, 'utf-8');
        this.log(`  ${chalk.green('Report saved:')} ${chalk.dim(outputPath)}`);
        audit.logReportGenerated(flags.format!, outputPath);

        // Also show summary in terminal
        const counts = countBySeverity(sharedFindings);
        this.log(formatSummary(sharedFindings));
        this.log(`  Grade: ${formatGrade(counts)}`);
      } else {
        // Write to stdout
        this.log(reportStr);
      }

      this.log('');
    } finally {
      closeDatabase(db);
    }
  }
}

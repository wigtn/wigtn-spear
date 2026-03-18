/**
 * `spear attack` command
 *
 * Runs live attack modules against a target URL or MCP server command.
 * Unlike `spear test` which performs static analysis on a directory,
 * this command sends live requests to a remote endpoint.
 *
 * Available attack modules:
 *   - prompt-inject:   Test for prompt injection vulnerabilities on
 *                      OpenAI-compatible chat completion endpoints
 *   - mcp-live:        Test a live MCP server (SSE or stdio transport)
 *                      for tool poisoning and protocol violations
 *   - endpoint-prober: Probe an HTTP endpoint for authentication,
 *                      authorization, and exposure issues
 *
 * Pipeline flow:
 *   1. Parse target URL and custom headers
 *   2. Build LiveAttackOptions for plugin context
 *   3. Load configuration (forced aggressive mode)
 *   4. Initialize database
 *   5. Load live attack plugins via registry
 *   6. Create scan record in DB
 *   7. Run selected plugin(s) via the registry
 *   8. Collect findings, insert into DB
 *   9. Update scan record with results and duration
 *  10. Display results in formatted table
 */

import { Command, Flags, Args } from '@oclif/core';
import { resolve } from 'node:path';
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
  ScanTarget,
  SpearConfig,
  PluginContext,
  LiveAttackOptions,
} from '@wigtn/shared';
import { createDatabase, closeDatabase, scans, findings as findingsTable } from '@wigtn/db';
import type { SpearDatabase, NewScan, NewFinding } from '@wigtn/db';
import { AuditLogger } from '@wigtn/db';
import { PluginRegistry } from '@wigtn/plugin-system';
import { SecretVerifier, RateLimiter, VerificationCache } from '@wigtn/core';

import {
  formatFinding,
  formatSummary,
  formatDuration,
  formatGrade,
  countBySeverity,
  printBanner,
} from '../utils/display.js';

// ─── Command ──────────────────────────────────────────────

export default class Attack extends Command {
  static override description = 'Run live attack modules against a target URL';

  static override examples = [
    '<%= config.bin %> attack https://api.openai.com/v1/chat/completions --module prompt-inject --api-key sk-...',
    '<%= config.bin %> attack https://mcp.example.com --module mcp-live',
    '<%= config.bin %> attack https://api.example.com --module endpoint-prober',
  ];

  static override args = {
    target: Args.string({
      description: 'Target URL or MCP server command',
      required: true,
    }),
  };

  static override flags = {
    module: Flags.string({
      char: 'm',
      description: 'Specific attack module (prompt-inject, mcp-live, endpoint-prober, or all)',
      default: 'all',
    }),
    'api-key': Flags.string({
      description: 'API key for authenticated endpoints',
    }),
    timeout: Flags.integer({
      description: 'Request timeout in ms (default: 30000)',
      default: 30000,
    }),
    'max-requests': Flags.integer({
      description: 'Maximum number of requests to send (default: 100)',
      default: 100,
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
    'source-dir': Flags.string({
      description: 'Source directory for hybrid mode (static + live)',
      default: '.',
    }),
    header: Flags.string({
      char: 'H',
      description: 'Custom header (format: "Key: Value")',
      multiple: true,
    }),
    'judge-key': Flags.string({
      description: 'LLM API key for multi-turn attacks and LLM-as-judge (enables advanced mode)',
      env: 'SPEAR_JUDGE_API_KEY',
    }),
    'judge-model': Flags.string({
      description: 'LLM model for judge/attacker (default: gpt-4o-mini)',
      default: 'gpt-4o-mini',
    }),
    'judge-provider': Flags.string({
      description: 'LLM provider for judge (openai, anthropic, google)',
      default: 'openai',
      options: ['openai', 'anthropic', 'google'],
    }),
    'multi-turn': Flags.boolean({
      description: 'Enable multi-turn attack strategies (Crescendo + TAP)',
      default: false,
    }),
    'multi-turn-strategy': Flags.string({
      description: 'Multi-turn strategy (crescendo, tap, both)',
      default: 'both',
      options: ['crescendo', 'tap', 'both'],
    }),
    tui: Flags.boolean({
      description: 'Enable interactive terminal UI for real-time attack visualization',
      default: false,
    }),
  };

  async run(): Promise<void> {
    const { args, flags } = await this.parse(Attack);
    const targetUrl = args.target;
    const sourceDir = resolve(flags['source-dir']);

    // ── Print Banner ─────────────────────────────────────────

    this.log(printBanner());
    this.log(chalk.red.bold('  ⚡ LIVE ATTACK MODE'));
    this.log(chalk.red(`  Target: ${targetUrl}`));
    if (flags['judge-key']) {
      this.log(chalk.yellow(`  🧠 LLM Judge: ${flags['judge-model']} (${flags['judge-provider']})`));
      if (flags['multi-turn']) {
        this.log(chalk.yellow(`  🔄 Multi-turn: ${flags['multi-turn-strategy']}`));
      }
    }
    this.log('');

    // ── Parse Custom Headers ─────────────────────────────────

    const customHeaders: Record<string, string> = {};
    if (flags.header) {
      for (const h of flags.header) {
        const colonIdx = h.indexOf(':');
        if (colonIdx > 0) {
          const key = h.slice(0, colonIdx).trim();
          const value = h.slice(colonIdx + 1).trim();
          customHeaders[key] = value;
        }
      }
    }

    // ── Build LiveAttackOptions ──────────────────────────────

    const liveAttack: LiveAttackOptions = {
      targetUrl,
      apiKey: flags['api-key'],
      headers: Object.keys(customHeaders).length > 0 ? customHeaders : undefined,
      timeout: flags.timeout,
      maxRequests: flags['max-requests'],
      judgeApiKey: flags['judge-key'],
      judgeModel: flags['judge-model'],
      judgeProvider: flags['judge-provider'] as LiveAttackOptions['judgeProvider'],
      multiTurn: flags['multi-turn'],
      multiTurnStrategy: flags['multi-turn-strategy'] as LiveAttackOptions['multiTurnStrategy'],
    };

    // ── Step 1: Load Configuration (forced aggressive) ───────

    const config = loadConfig(sourceDir, {
      mode: 'aggressive',
      verbose: flags.verbose,
      modules: flags.module !== 'all' ? [flags.module] : undefined,
    });
    const logger = createLogger(SPEAR_NAME, config.verbose);

    logger.info('attack configuration loaded', {
      mode: 'aggressive',
      target: targetUrl,
      module: flags.module,
    });

    // ── Step 2: Initialize Database ──────────────────────────

    const dbPath = getDbPath(sourceDir, config);
    let db: SpearDatabase;
    try {
      db = createDatabase(dbPath);
      logger.debug('database initialized', { dbPath });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.error(`Failed to initialize database: ${message}`, { exit: 1 });
    }

    const audit = new AuditLogger(db, logger);

    // ── Step 3: Load Live Attack Plugins ─────────────────────

    const registrySpinner = ora({ text: 'Loading live attack modules...', spinner: 'dots' }).start();

    const registry = new PluginRegistry();

    try {
      const pluginImports = await Promise.all([
        import('@wigtn/spear-23-live-prompt-inject' as string).catch(() => null),
        import('@wigtn/spear-24-mcp-live-test' as string).catch(() => null),
        import('@wigtn/spear-25-endpoint-prober' as string).catch(() => null),
      ]);

      const livePlugins = pluginImports
        .map((mod) => mod?.default)
        .filter(Boolean);

      if (livePlugins.length > 0) {
        registry.registerBuiltin(livePlugins, logger);
      }
    } catch {
      logger.debug('Some live attack plugins could not be loaded');
    }

    registrySpinner.succeed(`Loaded ${chalk.bold(String(registry.size))} live attack module(s)`);

    // ── Step 4: Create Scan Record ───────────────────────────

    const scanId = `attack_${randomUUID().slice(0, 12)}`;
    const moduleName = flags.module ?? 'all';
    const startTime = performance.now();

    const scanRecord: NewScan = {
      id: scanId,
      module: `attack:${moduleName}`,
      target: targetUrl,
      mode: 'aggressive',
      status: 'running',
      startedAt: new Date().toISOString(),
    };

    try {
      db.insert(scans).values(scanRecord).run();
      logger.debug('attack scan record created', { scanId });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn('failed to create scan record', { error: message });
    }

    audit.logScanStarted(`attack:${moduleName}`, targetUrl, 'aggressive');

    // ── Step 5: Run Attack Module(s) ─────────────────────────

    const scanTarget: ScanTarget = {
      path: sourceDir,
      exclude: config.exclude,
    };

    // Initialize SecretVerifier for live credential validation
    const rateLimiter = new RateLimiter({ rpm: 30, concurrent: 5 });
    const verificationCache = new VerificationCache({ maxSize: 200, ttlMs: 5 * 60 * 1000 });
    const secretVerifier = new SecretVerifier(rateLimiter, verificationCache);

    const pluginContext: PluginContext = {
      mode: 'aggressive',
      workDir: sourceDir,
      config,
      logger,
      liveAttack,
      secretVerifier,
    };

    // Determine which plugins to run
    const createFindingSource = (): AsyncGenerator<SharedFinding> => {
      if (moduleName === 'all') {
        return registry.runAll(scanTarget, pluginContext);
      }
      // Map friendly names to plugin IDs
      const MODULE_MAP: Record<string, string> = {
        'prompt-inject': 'live-prompt-inject',
        'mcp-live': 'mcp-live-test',
        'endpoint-prober': 'endpoint-prober',
      };
      const pluginId = MODULE_MAP[moduleName] ?? moduleName;
      return registry.runPlugin(pluginId, scanTarget, pluginContext);
    };

    // Helper: insert finding into DB
    const insertFinding = (finding: SharedFinding): void => {
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
        confidence: finding.confidence ?? null,
        fingerprintId: finding.fingerprintId ?? null,
      };
      try {
        db.insert(findingsTable).values(newFinding).run();
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn('failed to insert finding', { findingId, error: message });
      }
    };

    // Helper: update scan record on completion
    const completeScan = async (durationMs: number, counts: ReturnType<typeof countBySeverity>): Promise<void> => {
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
      audit.logScanCompleted(`attack:${moduleName}`, targetUrl, 'aggressive', {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
        durationMs,
      });
    };

    // Helper: mark scan as failed
    const failScan = async (errorMessage: string): Promise<void> => {
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
      audit.logScanFailed(`attack:${moduleName}`, targetUrl, 'aggressive', errorMessage);
    };

    // ── TUI Mode ───────────────────────────────────────────────
    const useTui = flags.tui && process.stdout.isTTY !== false;

    if (useTui) {
      try {
        const { renderAttackTUI, AttackEventBus } = await import('@wigtn/tui' as string);
        const bus = new AttackEventBus();

        let aborted = false;
        const findingSource = createFindingSource();
        const collectedFindings: SharedFinding[] = [];

        const { waitUntilExit, unmount } = renderAttackTUI({
          bus,
          targetUrl,
          scanId,
          onQuit: () => {
            aborted = true;
            findingSource.return(undefined);
          },
        });

        try {
          for await (const finding of findingSource) {
            collectedFindings.push(finding);
            insertFinding(finding);

            bus.emitFinding({
              ruleId: finding.ruleId,
              severity: finding.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
              message: finding.message ?? finding.ruleId,
            });
          }

          const durationMs = Math.round(performance.now() - startTime);
          const counts = countBySeverity(collectedFindings);
          const grade = formatGrade(counts);

          bus.emitComplete(durationMs, grade, counts);
          await completeScan(durationMs, counts);

          // Wait for user to press q to exit
          await waitUntilExit();

          closeDatabase(db);

          if (counts.critical > 0 || counts.high > 0) {
            return this.exit(1);
          }
        } catch (err: unknown) {
          if (err && typeof err === 'object' && 'oclif' in err) {
            throw err;
          }
          if (aborted) {
            // User pressed q -- show partial results
            const durationMs = Math.round(performance.now() - startTime);
            const counts = countBySeverity(collectedFindings);
            const grade = formatGrade(counts);
            bus.emitComplete(durationMs, grade, counts);
            await completeScan(durationMs, counts);
            await waitUntilExit();
            closeDatabase(db);
            return this.exit(130);
          }
          unmount();
          const message = err instanceof Error ? err.message : String(err);
          logger.error('attack execution failed', { error: message });
          await failScan(message);
          closeDatabase(db);
          this.error(`Attack failed: ${message}`, { exit: 2 });
        }
      } catch (err: unknown) {
        // TUI import failed -- fallback to text mode
        if (err && typeof err === 'object' && 'oclif' in err) {
          throw err;
        }
        logger.warn('TUI mode unavailable, falling back to text mode');
        // Fall through to text mode below
        await this.runTextMode({
          createFindingSource, insertFinding, completeScan, failScan,
          moduleName, targetUrl, startTime, scanId, db, audit, logger,
          closeDatabase,
        });
        return;
      }
    } else {
      // ── Text Mode (default) ──────────────────────────────────
      await this.runTextMode({
        createFindingSource, insertFinding, completeScan, failScan,
        moduleName, targetUrl, startTime, scanId, db, audit, logger,
        closeDatabase,
      });
    }
  }

  private async runTextMode(ctx: {
    createFindingSource: () => AsyncGenerator<SharedFinding>;
    insertFinding: (f: SharedFinding) => void;
    completeScan: (durationMs: number, counts: ReturnType<typeof countBySeverity>) => Promise<void>;
    failScan: (msg: string) => Promise<void>;
    moduleName: string;
    targetUrl: string;
    startTime: number;
    scanId: string;
    db: SpearDatabase;
    audit: AuditLogger;
    logger: ReturnType<typeof createLogger>;
    closeDatabase: typeof closeDatabase;
  }): Promise<void> {
    const attackSpinner = ora({
      text: `Running live attack: ${chalk.bold(ctx.moduleName)}...`,
      spinner: 'dots',
    }).start();

    this.log(chalk.red.bold('  ⚠️  SENDING LIVE REQUESTS TO TARGET'));
    this.log('');

    const collectedFindings: SharedFinding[] = [];

    try {
      const findingSource = ctx.createFindingSource();

      for await (const finding of findingSource) {
        collectedFindings.push(finding);
        ctx.insertFinding(finding);

        // Real-time output: print each finding as discovered
        attackSpinner.stop();
        this.log(`  ${formatFinding(finding)}`);
        attackSpinner.start(`Attacking... ${chalk.dim(`${collectedFindings.length} findings`)}`);
      }

      const durationMs = Math.round(performance.now() - ctx.startTime);
      const counts = countBySeverity(collectedFindings);

      attackSpinner.succeed(
        `Attack complete: ${chalk.bold(String(collectedFindings.length))} findings in ${chalk.dim(formatDuration(durationMs))}`,
      );

      await ctx.completeScan(durationMs, counts);

      // ── Display Results ────────────────────────────────────

      this.log(formatSummary(collectedFindings));
      this.log(`  Grade: ${formatGrade(counts)}`);
      this.log(`  Attack ID: ${chalk.dim(ctx.scanId)}`);
      this.log('');

      // ── Cleanup ────────────────────────────────────────────
      ctx.closeDatabase(ctx.db);

      // Exit with non-zero if critical or high findings detected
      if (counts.critical > 0 || counts.high > 0) {
        return this.exit(1);
      }
    } catch (err: unknown) {
      // Don't catch oclif ExitError -- let it propagate
      if (err && typeof err === 'object' && 'oclif' in err) {
        throw err;
      }
      attackSpinner.fail('Attack failed');

      const message = err instanceof Error ? err.message : String(err);
      ctx.logger.error('attack execution failed', { error: message });

      await ctx.failScan(message);
      ctx.closeDatabase(ctx.db);

      this.error(`Attack failed: ${message}`, { exit: 2 });
    }
  }
}

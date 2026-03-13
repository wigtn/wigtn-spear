/**
 * AuditLogger -- structured append-only audit trail for SPEAR operations.
 *
 * Required by PRD FR-074 for legal compliance (CFAA / Korean ICNA)
 * and operational visibility. Every scan start, completion, failure,
 * report generation, and mode change is recorded.
 *
 * Uses the existing @wigtn/shared logger for stderr output alongside
 * the database write so operators get real-time feedback.
 */

import { auditLogs } from './schema/audit-logs.js';
import type { SpearDatabase } from './client.js';
import type { SpearLogger } from '@wigtn/shared';

export interface AuditEntry {
  action: string;
  module?: string;
  target?: string;
  mode?: string;
  resultSummary?: Record<string, unknown>;
}

export class AuditLogger {
  private readonly db: SpearDatabase;
  private readonly logger: SpearLogger | undefined;

  constructor(db: SpearDatabase, logger?: SpearLogger) {
    this.db = db;
    this.logger = logger;
  }

  /**
   * Record an audit event.
   *
   * The result_summary is serialised to JSON for flexible querying.
   * Failures to write are logged but never thrown -- audit logging
   * must not crash a scan in progress.
   */
  log(entry: AuditEntry): void {
    try {
      this.db.insert(auditLogs).values({
        action: entry.action,
        module: entry.module ?? null,
        target: entry.target ?? null,
        mode: entry.mode ?? null,
        resultSummary: entry.resultSummary
          ? JSON.stringify(entry.resultSummary)
          : null,
      }).run();

      this.logger?.debug('audit event recorded', {
        action: entry.action,
        module: entry.module,
      });
    } catch (err: unknown) {
      // Audit failures must not crash the running scan
      const message = err instanceof Error ? err.message : String(err);
      this.logger?.warn('failed to write audit log', {
        action: entry.action,
        error: message,
      });
    }
  }

  /**
   * Convenience: log the start of a scan.
   */
  logScanStarted(module: string, target: string, mode: string): void {
    this.log({
      action: 'scan_started',
      module,
      target,
      mode,
    });
  }

  /**
   * Convenience: log scan completion with summary counters.
   */
  logScanCompleted(
    module: string,
    target: string,
    mode: string,
    summary: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      durationMs: number;
    },
  ): void {
    this.log({
      action: 'scan_completed',
      module,
      target,
      mode,
      resultSummary: summary,
    });
  }

  /**
   * Convenience: log a scan failure.
   */
  logScanFailed(module: string, target: string, mode: string, error: string): void {
    this.log({
      action: 'scan_failed',
      module,
      target,
      mode,
      resultSummary: { error },
    });
  }

  /**
   * Convenience: log scan interruption with checkpoint data.
   */
  logScanInterrupted(
    module: string,
    target: string,
    mode: string,
    checkpoint: string,
  ): void {
    this.log({
      action: 'scan_interrupted',
      module,
      target,
      mode,
      resultSummary: { checkpoint },
    });
  }

  /**
   * Convenience: log report generation.
   */
  logReportGenerated(format: string, outputPath: string): void {
    this.log({
      action: 'report_generated',
      resultSummary: { format, outputPath },
    });
  }

  /**
   * Convenience: log ToS acceptance (FR-080).
   */
  logTosAccepted(version: string): void {
    this.log({
      action: 'tos_accepted',
      resultSummary: { version, acceptedAt: new Date().toISOString() },
    });
  }

  /**
   * Convenience: log authorization confirmation (FR-081).
   */
  logAuthorizationConfirmed(target: string): void {
    this.log({
      action: 'authorization_confirmed',
      target,
      resultSummary: { confirmedAt: new Date().toISOString() },
    });
  }
}

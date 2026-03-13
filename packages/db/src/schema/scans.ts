/**
 * Scans table schema -- PRD Section 5.3
 *
 * Tracks every scan execution with severity counters,
 * duration, security scoring, and resume checkpoints.
 */

import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const scans = sqliteTable('scans', {
  /** Unique scan identifier, e.g. "scan_abc123" */
  id: text('id').primaryKey(),

  /** Module that executed the scan: 'secret-scanner', 'git-miner', etc. */
  module: text('module').notNull(),

  /** Filesystem path that was scanned */
  target: text('target').notNull(),

  /** Scan mode: 'safe' (passive only) or 'aggressive' (live verification) */
  mode: text('mode').notNull().default('safe'),

  /** Current scan lifecycle state */
  status: text('status').notNull().default('pending'),

  // ── Severity counters ──────────────────────────────────────
  findingsCritical: integer('findings_critical').default(0),
  findingsHigh: integer('findings_high').default(0),
  findingsMedium: integer('findings_medium').default(0),
  findingsLow: integer('findings_low').default(0),
  findingsInfo: integer('findings_info').default(0),

  /** Wall-clock scan duration in milliseconds */
  durationMs: integer('duration_ms'),

  /** Computed security score 0-100 */
  securityScore: integer('security_score'),

  /** Letter grade A-F derived from securityScore */
  securityGrade: text('security_grade'),

  /**
   * Opaque checkpoint token for scan resumption (FR: Scan Interruption Recovery).
   * Serialised as JSON -- contains the last processed file index or commit SHA
   * so `spear scan --resume <token>` can continue where it left off.
   */
  checkpoint: text('checkpoint'),

  startedAt: text('started_at'),
  completedAt: text('completed_at'),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;

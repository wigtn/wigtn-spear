/**
 * Audit logs table schema -- PRD Section 5.3, FR-074
 *
 * Immutable append-only log of every significant action taken by SPEAR:
 * scan starts/completions, report generation, mode changes, etc.
 * Required for legal compliance (CFAA / Korean ICNA) and operational auditing.
 */

import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const auditLogs = sqliteTable(
  'audit_logs',
  {
    /** Auto-incrementing primary key */
    id: integer('id').primaryKey({ autoIncrement: true }),

    /**
     * Action type:
     *   'scan_started' | 'scan_completed' | 'scan_failed' | 'scan_interrupted' |
     *   'report_generated' | 'authorization_confirmed' | 'tos_accepted' |
     *   'aggressive_mode_enabled' | 'plugin_installed' | 'rules_updated'
     */
    action: text('action').notNull(),

    /** Module name involved, if applicable */
    module: text('module'),

    /** Target path or resource */
    target: text('target'),

    /** Scan mode at time of action */
    mode: text('mode'),

    /** JSON-serialised summary of the action result */
    resultSummary: text('result_summary'),

    createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
  },
  (table) => ({
    actionIdx: index('idx_audit_logs_action').on(table.action),
  }),
);

export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;

/**
 * Findings table schema -- PRD Section 5.3
 *
 * Individual security findings discovered during a scan.
 * INVARIANT: secret_masked stores ONLY the masked value produced by
 * SecureSecret.mask(). The raw secret is NEVER written to disk.
 */

import { sqliteTable, text, integer, real, index } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';
import { scans } from './scans.js';

export const findings = sqliteTable(
  'findings',
  {
    /** Unique finding identifier, e.g. "finding_001" */
    id: text('id').primaryKey(),

    /** Foreign key to the parent scan */
    scanId: text('scan_id')
      .notNull()
      .references(() => scans.id),

    /** Rule that triggered this finding, e.g. "SPEAR-S001" */
    ruleId: text('rule_id').notNull(),

    /** Severity level: critical | high | medium | low | info */
    severity: text('severity').notNull(),

    /** Relative file path where the finding was located */
    filePath: text('file_path'),

    lineNumber: integer('line_number'),
    columnNumber: integer('column_number'),

    /**
     * Masked representation of the detected secret.
     * Produced by SecureSecret.mask() -- NEVER the raw value.
     * Example: "AKIA****MPLE"
     */
    secretMasked: text('secret_masked'),

    /** Whether the secret was live-verified (Aggressive Mode) */
    verified: integer('verified', { mode: 'boolean' }).default(false),

    /** ISO-8601 timestamp of verification */
    verifiedAt: text('verified_at'),

    /** CVSS v3.1 base score (0.0 - 10.0) */
    cvss: real('cvss'),

    /** JSON array of MITRE ATT&CK technique IDs, e.g. '["T1552.001"]' */
    mitreTechniques: text('mitre_techniques'),

    /** Human-readable remediation guidance */
    remediation: text('remediation'),

    /** JSON object with module-specific extra data */
    metadata: text('metadata'),

    createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
  },
  (table) => ({
    scanIdIdx: index('idx_findings_scan_id').on(table.scanId),
    severityIdx: index('idx_findings_severity').on(table.severity),
    ruleIdIdx: index('idx_findings_rule_id').on(table.ruleId),
  }),
);

export type Finding = typeof findings.$inferSelect;
export type NewFinding = typeof findings.$inferInsert;

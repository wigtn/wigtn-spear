/**
 * Shield tests table schema -- PRD Section 5.3
 *
 * Records the results of SPEAR attacks executed against a
 * WIGTN-SHIELD deployment for Red Team / Blue Team gap analysis.
 */

import { sqliteTable, text, integer, real } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const shieldTests = sqliteTable('shield_tests', {
  id: text('id').primaryKey(),

  /** Attack scenario name, e.g. "brute-force-login" */
  scenario: text('scenario').notNull(),

  /** Human-readable description of the simulated attack */
  attackDescription: text('attack_description'),

  /** Whether SHIELD detected the attack (0 = missed, 1 = detected) */
  shieldDetected: integer('shield_detected', { mode: 'boolean' }),

  /** Time in ms from attack start to SHIELD detection */
  detectionTimeMs: integer('detection_time_ms'),

  /** Which SHIELD agent performed the detection */
  shieldAgent: text('shield_agent'),

  /** Detection confidence score 0.0 - 1.0 */
  confidence: real('confidence'),

  /** Explanation of why the attack was missed (when shieldDetected = false) */
  gapDescription: text('gap_description'),

  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export type ShieldTest = typeof shieldTests.$inferSelect;
export type NewShieldTest = typeof shieldTests.$inferInsert;

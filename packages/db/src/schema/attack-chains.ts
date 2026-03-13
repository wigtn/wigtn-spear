/**
 * Attack chains table schema -- PRD Section 5.3
 *
 * Stores the multi-step attack path data that visualises how
 * an attacker could chain individual findings into a full compromise.
 * chain_data is a JSON-serialised array of attack steps.
 */

import { sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';
import { scans } from './scans.js';

export const attackChains = sqliteTable('attack_chains', {
  id: text('id').primaryKey(),

  /** Parent scan that produced this chain */
  scanId: text('scan_id')
    .notNull()
    .references(() => scans.id),

  /**
   * JSON-serialised attack chain steps.
   * Example:
   * [
   *   { "step": 1, "technique": "Secret Discovery", "finding": "finding_001", "description": "..." },
   *   { "step": 2, "technique": "Cloud Credential Access", "description": "..." }
   * ]
   */
  chainData: text('chain_data').notNull(),

  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export type AttackChain = typeof attackChains.$inferSelect;
export type NewAttackChain = typeof attackChains.$inferInsert;

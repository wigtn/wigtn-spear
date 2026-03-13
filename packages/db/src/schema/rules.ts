/**
 * Rules table schema -- PRD Section 5.3
 *
 * Caches the YAML rule definitions that were loaded by the rules engine.
 * This allows the dashboard and reporters to reference rule metadata
 * without re-parsing the YAML files.
 */

import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const rules = sqliteTable('rules', {
  /** Rule identifier matching the YAML id field, e.g. "SPEAR-S001" */
  id: text('id').primaryKey(),

  /** Category: 'secret' | 'vulnerability' | 'misconfiguration' */
  category: text('category').notNull(),

  name: text('name').notNull(),

  description: text('description'),

  /** Regex detection pattern */
  pattern: text('pattern'),

  /** Severity level: critical | high | medium | low | info */
  severity: text('severity').notNull(),

  /** JSON array of tags, e.g. '["aws","cloud","credential"]' */
  tags: text('tags'),

  /** JSON array of reference URLs (CVE, CWE links) */
  references: text('references'),

  /** Whether this rule is active for scanning */
  enabled: integer('enabled', { mode: 'boolean' }).default(true),

  /** Semantic version of the rule definition */
  version: text('version').notNull(),

  updatedAt: text('updated_at').notNull().default(sql`(datetime('now'))`),
});

export type RuleRow = typeof rules.$inferSelect;
export type NewRuleRow = typeof rules.$inferInsert;

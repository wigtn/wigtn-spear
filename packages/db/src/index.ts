/**
 * @wigtn/db -- Data layer for WIGTN-SPEAR
 *
 * Provides:
 *   - Drizzle ORM schema definitions for all six tables
 *   - Database client factory with WAL mode + auto-migration
 *   - AuditLogger for FR-074 compliance
 *
 * Usage:
 *   import { createDatabase, closeDatabase, AuditLogger, scans, findings } from '@wigtn/db';
 *
 *   const db = createDatabase('.spear/spear.db');
 *   const audit = new AuditLogger(db, logger);
 *   audit.logScanStarted('secret-scanner', '/path', 'safe');
 */

// Schema tables and inferred types
export {
  scans,
  type Scan,
  type NewScan,
  findings,
  type Finding,
  type NewFinding,
  attackChains,
  type AttackChain,
  type NewAttackChain,
  rules,
  type RuleRow,
  type NewRuleRow,
  shieldTests,
  type ShieldTest,
  type NewShieldTest,
  auditLogs,
  type AuditLog,
  type NewAuditLog,
} from './schema/index.js';

// Database client
export { createDatabase, closeDatabase, type SpearDatabase } from './client.js';

// Audit logger
export { AuditLogger, type AuditEntry } from './audit.js';

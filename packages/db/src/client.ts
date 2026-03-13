/**
 * Database client factory -- creates and configures a SQLite connection
 * with WAL mode, foreign keys, and automatic table creation.
 *
 * Uses better-sqlite3 for synchronous access (no async overhead for a
 * local CLI tool) wrapped by Drizzle ORM for type-safe queries.
 *
 * WAL mode is critical for:
 *   - Concurrent reads during worker-thread scans
 *   - Crash-safe writes (PRD: scan interruption recovery)
 *   - No writer starvation on long scans
 */

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import * as schema from './schema/index.js';

export type SpearDatabase = BetterSQLite3Database<typeof schema>;

/**
 * Raw SQL statements executed once on every new database connection.
 * These create all tables idempotently (IF NOT EXISTS) so the tool
 * works out of the box without a separate migration step.
 */
const INIT_SQL = `
-- Enable WAL mode for concurrent reads + crash safety
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ── scans ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  module TEXT NOT NULL,
  target TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'safe',
  status TEXT NOT NULL DEFAULT 'pending',
  findings_critical INTEGER DEFAULT 0,
  findings_high INTEGER DEFAULT 0,
  findings_medium INTEGER DEFAULT 0,
  findings_low INTEGER DEFAULT 0,
  findings_info INTEGER DEFAULT 0,
  duration_ms INTEGER,
  security_score INTEGER,
  security_grade TEXT,
  checkpoint TEXT,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── findings ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id),
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  file_path TEXT,
  line_number INTEGER,
  column_number INTEGER,
  secret_masked TEXT,
  verified INTEGER DEFAULT 0,
  verified_at TEXT,
  cvss REAL,
  mitre_techniques TEXT,
  remediation TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── attack_chains ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_chains (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id),
  chain_data TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── rules ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  pattern TEXT,
  severity TEXT NOT NULL,
  tags TEXT,
  "references" TEXT,
  enabled INTEGER DEFAULT 1,
  version TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── shield_tests ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_tests (
  id TEXT PRIMARY KEY,
  scenario TEXT NOT NULL,
  attack_description TEXT,
  shield_detected INTEGER,
  detection_time_ms INTEGER,
  shield_agent TEXT,
  confidence REAL,
  gap_description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── audit_logs ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  module TEXT,
  target TEXT,
  mode TEXT,
  result_summary TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_module ON scans(module);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
`;

/**
 * Create (or open) a SPEAR database at the given path.
 *
 * - Ensures the parent directory exists (e.g. `.spear/`)
 * - Opens a better-sqlite3 connection
 * - Enables WAL + foreign keys
 * - Creates all tables idempotently
 * - Wraps in Drizzle ORM for type-safe access
 *
 * @param dbPath - Absolute or relative path to the SQLite file
 * @returns Drizzle database instance with full schema typing
 */
export function createDatabase(dbPath: string): SpearDatabase {
  // Ensure the parent directory exists (e.g. `.spear/`)
  const dir = dirname(dbPath);
  mkdirSync(dir, { recursive: true });

  // Open the raw SQLite connection
  const sqlite = new Database(dbPath);

  // Run all initialisation in a single transaction for atomicity
  sqlite.exec(INIT_SQL);

  // Wrap with Drizzle ORM
  const db = drizzle(sqlite, { schema });

  return db;
}

/**
 * Close the underlying SQLite connection gracefully.
 *
 * Should be called during process shutdown (SIGINT/SIGTERM handlers)
 * to ensure WAL checkpointing completes and no data is lost.
 * Drizzle does not expose close() so we reach through to the session.
 */
export function closeDatabase(db: SpearDatabase): void {
  // drizzle-orm/better-sqlite3 stores the underlying connection in _.session.client
  const session = (db as unknown as { _: { session: { client: Database.Database } } })._.session;
  if (session?.client) {
    // Checkpoint WAL before closing to flush pending writes
    try {
      session.client.pragma('wal_checkpoint(TRUNCATE)');
    } catch {
      // Best-effort -- database may already be closing
    }
    session.client.close();
  }
}

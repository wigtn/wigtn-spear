/**
 * Schema barrel export
 *
 * Re-exports every table definition and its inferred types
 * so consumers can import from '@wigtn/db' directly.
 */

export { scans, type Scan, type NewScan } from './scans.js';
export { findings, type Finding, type NewFinding } from './findings.js';
export { attackChains, type AttackChain, type NewAttackChain } from './attack-chains.js';
export { rules, type RuleRow, type NewRuleRow } from './rules.js';
export { shieldTests, type ShieldTest, type NewShieldTest } from './shield-tests.js';
export { auditLogs, type AuditLog, type NewAuditLog } from './audit-logs.js';

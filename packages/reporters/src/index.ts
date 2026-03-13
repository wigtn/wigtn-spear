/**
 * @wigtn/reporters -- Output format generators for WIGTN-SPEAR
 *
 * Provides:
 *   - SARIFReporter  -- SARIF 2.1.0 compliant output (GitHub Code Scanning, etc.)
 *   - JSONReporter   -- Structured JSON report with severity summary
 *
 * Usage:
 *   import { SARIFReporter, JSONReporter } from '@wigtn/reporters';
 *
 *   const sarif = new SARIFReporter();
 *   const sarifLog = sarif.generate(findings, { module: 'secret-scanner', target: '.' });
 *
 *   const json = new JSONReporter();
 *   const report = json.generate(findings, { module: 'secret-scanner', target: '.' });
 */

export { SARIFReporter, type ScanInfo as SarifScanInfo } from './sarif.js';
export { JSONReporter, type ScanInfo as JsonScanInfo, type SpearReport, type SeveritySummary } from './json.js';

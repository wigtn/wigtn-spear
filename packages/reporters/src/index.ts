/**
 * @wigtn/reporters -- Output format generators for WIGTN-SPEAR
 *
 * Provides:
 *   - SARIFReporter       -- SARIF 2.1.0 compliant output (GitHub Code Scanning, etc.)
 *   - JSONReporter        -- Structured JSON report with severity summary
 *   - generateHtmlReport  -- Self-contained HTML report with dark theme
 *
 * Usage:
 *   import { SARIFReporter, JSONReporter, generateHtmlReport } from '@wigtn/reporters';
 *
 *   const sarif = new SARIFReporter();
 *   const sarifLog = sarif.generate(findings, { module: 'secret-scanner', target: '.' });
 *
 *   const json = new JSONReporter();
 *   const report = json.generate(findings, { module: 'secret-scanner', target: '.' });
 *
 *   const html = generateHtmlReport(findings, { module: 'secret-scanner', target: '.' });
 */

export { SARIFReporter, type ScanInfo as SarifScanInfo } from './sarif.js';
export { JSONReporter, type ScanInfo as JsonScanInfo, type SpearReport, type SeveritySummary } from './json.js';
export { generateHtmlReport, type ReportMeta } from './html.js';

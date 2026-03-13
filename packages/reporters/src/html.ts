/**
 * HTML Reporter for WIGTN-SPEAR
 *
 * Generates a self-contained HTML report with inline CSS (no external deps).
 * Dark theme, modern design with:
 *   - Scan summary header
 *   - Severity breakdown chart (CSS-based bars)
 *   - Findings table with sortable columns
 *   - Remediation suggestions per finding
 *
 * The report is a single HTML file suitable for sharing, embedding
 * in CI artifacts, or opening directly in a browser.
 */

import type { Finding, Severity, ScanMode } from '@wigtn/shared';
import { SPEAR_VERSION, SPEAR_NAME, SEVERITY_ORDER } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────

export interface ReportMeta {
  /** Module that executed the scan, e.g. 'secret-scanner' */
  module: string;
  /** Version of the module or tool */
  version?: string;
  /** Filesystem path or URI of the scan target */
  target: string;
  /** Scan mode: safe or aggressive */
  mode?: ScanMode;
  /** Scan duration in milliseconds */
  durationMs?: number;
  /** Scan start time (ISO-8601) */
  startedAt?: string;
  /** Scan completion time (ISO-8601) */
  completedAt?: string;
}

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

// ─── Severity Colors ──────────────────────────────────────

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ff4d4f',
  high: '#ff7a45',
  medium: '#faad14',
  low: '#1890ff',
  info: '#8c8c8c',
};

// ─── Helpers ──────────────────────────────────────────────

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function computeSeverityCounts(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };

  for (const finding of findings) {
    const severity = finding.severity as keyof Omit<SeverityCounts, 'total'>;
    if (severity in counts) {
      counts[severity]++;
    }
  }

  return counts;
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDiff =
      (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    if (severityDiff !== 0) return severityDiff;

    const fileA = a.file ?? '';
    const fileB = b.file ?? '';
    const fileDiff = fileA.localeCompare(fileB);
    if (fileDiff !== 0) return fileDiff;

    return (a.line ?? 0) - (b.line ?? 0);
  });
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = ((ms % 60_000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

function computeGrade(counts: SeverityCounts): { grade: string; color: string } {
  // Simple scoring: 100 - (critical*25 + high*15 + medium*8 + low*3 + info*1)
  const score = Math.max(
    0,
    100 -
      counts.critical * 25 -
      counts.high * 15 -
      counts.medium * 8 -
      counts.low * 3 -
      counts.info * 1,
  );

  if (score >= 90) return { grade: 'A', color: '#52c41a' };
  if (score >= 80) return { grade: 'B', color: '#73d13d' };
  if (score >= 70) return { grade: 'C', color: '#faad14' };
  if (score >= 60) return { grade: 'D', color: '#ff7a45' };
  return { grade: 'F', color: '#ff4d4f' };
}

// ─── HTML Generation ──────────────────────────────────────

function buildStyles(): string {
  return `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1, h2, h3 { color: #f0f6fc; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* Header */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem 2rem;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      margin-bottom: 1.5rem;
    }
    .header-title { font-size: 1.5rem; font-weight: 700; }
    .header-title span { color: #ff4d4f; }
    .header-meta { font-size: 0.85rem; color: #8b949e; text-align: right; }
    .header-meta div { margin-bottom: 0.25rem; }

    /* Grade Badge */
    .grade-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 64px;
      height: 64px;
      border-radius: 50%;
      font-size: 2rem;
      font-weight: 900;
      border: 3px solid;
      margin-right: 1.5rem;
    }

    /* Summary Cards */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .summary-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }
    .summary-card .count {
      font-size: 2rem;
      font-weight: 700;
      display: block;
    }
    .summary-card .label {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #8b949e;
      margin-top: 0.25rem;
    }

    /* Chart Section */
    .chart-section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1.5rem 2rem;
      margin-bottom: 1.5rem;
    }
    .chart-section h2 { font-size: 1.1rem; margin-bottom: 1rem; }
    .bar-row {
      display: flex;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    .bar-label {
      width: 80px;
      font-size: 0.8rem;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.04em;
    }
    .bar-track {
      flex: 1;
      height: 24px;
      background: #21262d;
      border-radius: 4px;
      overflow: hidden;
      margin: 0 0.75rem;
    }
    .bar-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s ease;
      min-width: 0;
    }
    .bar-count {
      width: 40px;
      text-align: right;
      font-weight: 600;
      font-size: 0.9rem;
    }

    /* Findings Table */
    .table-section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1.5rem 2rem;
      margin-bottom: 1.5rem;
      overflow-x: auto;
    }
    .table-section h2 { font-size: 1.1rem; margin-bottom: 1rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th {
      text-align: left;
      padding: 0.75rem 0.5rem;
      border-bottom: 2px solid #30363d;
      color: #8b949e;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }
    th:hover { color: #f0f6fc; }
    th .sort-arrow { margin-left: 4px; opacity: 0.4; }
    td {
      padding: 0.6rem 0.5rem;
      border-bottom: 1px solid #21262d;
      vertical-align: top;
    }
    tr:hover td { background: #1c2128; }
    .severity-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: #0d1117;
    }
    .file-path { font-family: 'SF Mono', Consolas, monospace; font-size: 0.8rem; color: #58a6ff; }
    .message-cell { max-width: 400px; }
    .remediation-cell { max-width: 300px; color: #3fb950; font-size: 0.8rem; }

    /* Footer */
    .footer {
      text-align: center;
      padding: 1.5rem;
      color: #484f58;
      font-size: 0.8rem;
    }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 3rem;
      color: #8b949e;
    }
    .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
  `;
}

function buildScript(): string {
  return `
    document.addEventListener('DOMContentLoaded', function() {
      var table = document.getElementById('findings-table');
      if (!table) return;
      var headers = table.querySelectorAll('th[data-sort]');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var sortState = {};

      var severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

      headers.forEach(function(header) {
        header.addEventListener('click', function() {
          var key = header.getAttribute('data-sort');
          var ascending = sortState[key] !== 'asc';
          sortState = {};
          sortState[key] = ascending ? 'asc' : 'desc';

          // Update arrows
          headers.forEach(function(h) {
            var arrow = h.querySelector('.sort-arrow');
            if (arrow) arrow.textContent = '\\u2195';
          });
          var arrow = header.querySelector('.sort-arrow');
          if (arrow) arrow.textContent = ascending ? '\\u2191' : '\\u2193';

          rows.sort(function(a, b) {
            var aVal = a.getAttribute('data-' + key) || '';
            var bVal = b.getAttribute('data-' + key) || '';

            if (key === 'severity') {
              aVal = severityOrder[aVal] !== undefined ? severityOrder[aVal] : 99;
              bVal = severityOrder[bVal] !== undefined ? severityOrder[bVal] : 99;
              return ascending ? aVal - bVal : bVal - aVal;
            }
            if (key === 'line') {
              aVal = parseInt(aVal, 10) || 0;
              bVal = parseInt(bVal, 10) || 0;
              return ascending ? aVal - bVal : bVal - aVal;
            }
            return ascending
              ? aVal.toString().localeCompare(bVal.toString())
              : bVal.toString().localeCompare(aVal.toString());
          });

          rows.forEach(function(row) { tbody.appendChild(row); });
        });
      });
    });
  `;
}

function buildSeverityChart(counts: SeverityCounts): string {
  const maxCount = Math.max(counts.critical, counts.high, counts.medium, counts.low, counts.info, 1);
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  const bars = severities.map((sev) => {
    const count = counts[sev];
    const pct = (count / maxCount) * 100;
    const color = SEVERITY_COLORS[sev];
    return `
      <div class="bar-row">
        <span class="bar-label" style="color:${color}">${escapeHtml(sev)}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="bar-count" style="color:${color}">${count}</span>
      </div>
    `;
  }).join('');

  return `
    <div class="chart-section">
      <h2>Severity Breakdown</h2>
      ${bars}
    </div>
  `;
}

function buildFindingsTable(findings: Finding[]): string {
  if (findings.length === 0) {
    return `
      <div class="table-section">
        <h2>Findings</h2>
        <div class="empty-state">
          <div class="icon">&#10003;</div>
          <p>No findings detected. Your project looks clean!</p>
        </div>
      </div>
    `;
  }

  const sorted = sortFindings(findings);

  const headerRow = `
    <tr>
      <th data-sort="severity">Severity <span class="sort-arrow">&#8597;</span></th>
      <th data-sort="ruleId">Rule <span class="sort-arrow">&#8597;</span></th>
      <th data-sort="file">File <span class="sort-arrow">&#8597;</span></th>
      <th data-sort="line">Line <span class="sort-arrow">&#8597;</span></th>
      <th data-sort="message">Message <span class="sort-arrow">&#8597;</span></th>
      <th>Remediation</th>
    </tr>
  `;

  const bodyRows = sorted
    .map((f) => {
      const color = SEVERITY_COLORS[f.severity];
      const location = f.file ? escapeHtml(f.file) : '-';
      const line = f.line != null ? String(f.line) : '-';
      const message = escapeHtml(f.message);
      const masked = f.secretMasked ? ` <code>${escapeHtml(f.secretMasked)}</code>` : '';
      const remediation = f.remediation ? escapeHtml(f.remediation) : '-';

      return `
        <tr data-severity="${escapeHtml(f.severity)}"
            data-ruleid="${escapeHtml(f.ruleId)}"
            data-file="${escapeHtml(f.file ?? '')}"
            data-line="${f.line ?? 0}"
            data-message="${escapeHtml(f.message)}">
          <td>
            <span class="severity-badge" style="background:${color}">${escapeHtml(f.severity)}</span>
          </td>
          <td><code>${escapeHtml(f.ruleId)}</code></td>
          <td class="file-path">${location}</td>
          <td>${line}</td>
          <td class="message-cell">${message}${masked}</td>
          <td class="remediation-cell">${remediation}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div class="table-section">
      <h2>Findings (${findings.length})</h2>
      <table id="findings-table">
        <thead>${headerRow}</thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>
  `;
}

// ─── Public API ───────────────────────────────────────────

/**
 * Generate a self-contained HTML report from an array of findings
 * and scan metadata.
 *
 * The returned string is a complete HTML document with inline CSS
 * and JavaScript for column sorting. No external dependencies required.
 *
 * @param findings - Array of findings from a completed scan
 * @param meta - Metadata about the scan
 * @returns A complete HTML document as a string
 */
export function generateHtmlReport(findings: Finding[], meta: ReportMeta): string {
  const counts = computeSeverityCounts(findings);
  const { grade, color: gradeColor } = computeGrade(counts);
  const now = new Date().toISOString();
  const version = meta.version ?? SPEAR_VERSION;
  const duration = meta.durationMs != null ? formatDuration(meta.durationMs) : '-';
  const mode = meta.mode ?? 'safe';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(SPEAR_NAME)} Security Report</title>
  <style>${buildStyles()}</style>
</head>
<body>
  <div class="container">

    <!-- Header -->
    <div class="header">
      <div style="display:flex;align-items:center">
        <div class="grade-badge" style="color:${gradeColor};border-color:${gradeColor}">${grade}</div>
        <div>
          <div class="header-title"><span>${escapeHtml(SPEAR_NAME.toUpperCase())}</span> Security Report</div>
          <div style="color:#8b949e;font-size:0.85rem;margin-top:0.25rem">
            ${escapeHtml(meta.target)} &middot; ${escapeHtml(mode)} mode &middot; ${escapeHtml(meta.module)}
          </div>
        </div>
      </div>
      <div class="header-meta">
        <div>Version: ${escapeHtml(version)}</div>
        <div>Duration: ${escapeHtml(duration)}</div>
        <div>Generated: ${escapeHtml(now)}</div>
        ${meta.startedAt ? `<div>Started: ${escapeHtml(meta.startedAt)}</div>` : ''}
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="summary-grid">
      <div class="summary-card">
        <span class="count" style="color:${SEVERITY_COLORS.critical}">${counts.critical}</span>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card">
        <span class="count" style="color:${SEVERITY_COLORS.high}">${counts.high}</span>
        <div class="label">High</div>
      </div>
      <div class="summary-card">
        <span class="count" style="color:${SEVERITY_COLORS.medium}">${counts.medium}</span>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card">
        <span class="count" style="color:${SEVERITY_COLORS.low}">${counts.low}</span>
        <div class="label">Low</div>
      </div>
      <div class="summary-card">
        <span class="count" style="color:${SEVERITY_COLORS.info}">${counts.info}</span>
        <div class="label">Info</div>
      </div>
      <div class="summary-card">
        <span class="count" style="color:#f0f6fc">${counts.total}</span>
        <div class="label">Total</div>
      </div>
    </div>

    <!-- Severity Chart -->
    ${buildSeverityChart(counts)}

    <!-- Findings Table -->
    ${buildFindingsTable(findings)}

    <!-- Footer -->
    <div class="footer">
      Generated by ${escapeHtml(SPEAR_NAME)} v${escapeHtml(version)} &middot; ${escapeHtml(now)}
    </div>

  </div>

  <script>${buildScript()}</script>
</body>
</html>`;
}

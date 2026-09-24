import type { APKAnalysis } from "@/types/apk";

/**
 * Generates an executive printable HTML report designed to be saved as PDF.
 */
export function openPrintableReport(analysis: APKAnalysis) {
  const counts = {
    high: analysis.findings.filter(x => x.severity === "high").length,
    medium: analysis.findings.filter(x => x.severity === "medium").length,
    low: analysis.findings.filter(x => x.severity === "low").length,
  };
  const score = Math.max(0, 100 - counts.high * 20 - counts.medium * 10 - counts.low * 3);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Assessment Report - ${analysis.fileName}</title>
  <style>
    @page { size: A4; margin: 20mm; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.5; margin: 0; padding: 20px; }
    .header { border-bottom: 2px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
    .brand { font-size: 24px; font-weight: 800; color: #0f172a; }
    .brand span { color: #0284c7; }
    .score-box { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px 25px; text-align: center; }
    .score-val { font-size: 32px; font-weight: 800; color: ${score < 50 ? "#dc2626" : score < 80 ? "#d97706" : "#16a34a"}; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 25px; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; }
    .card span { font-size: 12px; color: #64748b; display: block; text-transform: uppercase; font-weight: 600; }
    .card b { font-size: 15px; color: #0f172a; word-break: break-all; }
    h2 { font-size: 18px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
    th { background: #f1f5f9; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .high { background: #fee2e2; color: #991b1b; }
    .medium { background: #fef3c7; color: #92400e; }
    .low { background: #e0f2fe; color: #075985; }
    .info { background: #f1f5f9; color: #475569; }
    .footer { margin-top: 50px; font-size: 11px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 15px; }
    @media print {
      body { padding: 0; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 20px; display: flex; gap: 10px;">
    <button onclick="window.print()" style="padding: 10px 20px; background: #0284c7; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">🖨️ Print / Save as PDF</button>
  </div>

  <div class="header">
    <div>
      <div class="brand">APK<span>Lens</span> Executive Report</div>
      <div style="font-size: 13px; color: #64748b;">Static Mobile Application Security Assessment</div>
    </div>
    <div class="score-box">
      <div class="score-val">${score}/100</div>
      <div style="font-size: 12px; color: #64748b; font-weight: 600;">Security Score</div>
    </div>
  </div>

  <div class="grid">
    <div class="card"><span>Application File</span><b>${analysis.fileName}</b></div>
    <div class="card"><span>Package Name</span><b>${analysis.packageName || "Unknown"}</b></div>
    <div class="card"><span>Version</span><b>${analysis.versionName || "Unknown"} (Code: ${analysis.versionCode || "Unknown"})</b></div>
    <div class="card"><span>SDK Range</span><b>Min: ${analysis.minSdk || "N/A"} · Target: ${analysis.targetSdk || "N/A"}</b></div>
    <div class="card" style="grid-column: span 2;"><span>SHA-256 Checksum</span><b style="font-family: monospace; font-size: 13px;">${analysis.sha256}</b></div>
  </div>

  <h2>Security Findings & Vulnerabilities (${analysis.findings.length})</h2>
  <table>
    <thead><tr><th style="width: 100px;">Severity</th><th>Finding Title</th><th>Evidence / Technical Detail</th></tr></thead>
    <tbody>
      ${analysis.findings.map(f => `<tr><td><span class="badge ${f.severity}">${f.severity}</span></td><td><b>${f.title}</b></td><td style="font-family: monospace; font-size: 12px;">${f.evidence}</td></tr>`).join("")}
    </tbody>
  </table>

  <h2>Application Attack Surface</h2>
  <table>
    <thead><tr><th>Metric</th><th>Count</th><th>Risk Considerations</th></tr></thead>
    <tbody>
      <tr><td><b>Exported Activities</b></td><td>${analysis.activities.filter(a => a.exported === "true").length} of ${analysis.activities.length}</td><td>Accessible to third-party apps on the device</td></tr>
      <tr><td><b>Exported Services</b></td><td>${analysis.services.filter(s => s.exported === "true").length} of ${analysis.services.length}</td><td>Potential unauthorized background invocation</td></tr>
      <tr><td><b>Exported Receivers</b></td><td>${analysis.receivers.filter(r => r.exported === "true").length} of ${analysis.receivers.length}</td><td>Susceptible to malicious Intent broadcasts</td></tr>
      <tr><td><b>Content Providers</b></td><td>${analysis.providers.length}</td><td>Inspect for SQL injection and file traversal</td></tr>
      <tr><td><b>Requested Permissions</b></td><td>${analysis.permissions.length}</td><td>Review sensitive runtime access rights</td></tr>
      <tr><td><b>Compiled Classes</b></td><td>${analysis.dexFiles.reduce((acc, d) => acc + (d.classCount || 0), 0)}</td><td>Dalvik compiled Java/Kotlin codebase</td></tr>
    </tbody>
  </table>

  <h2>Certificate & Code Signing</h2>
  <div class="grid">
    <div class="card"><span>Signing Scheme</span><b>${analysis.certificate?.scheme || "Unsigned / Unknown"}</b></div>
    <div class="card"><span>Algorithm</span><b>${analysis.certificate?.sigAlg || "Unknown"}</b></div>
    <div class="card"><span>Subject</span><b>${analysis.certificate?.subject || "Unknown"}</b></div>
    <div class="card"><span>Issuer</span><b>${analysis.certificate?.issuer || "Unknown"}</b></div>
    <div class="card" style="grid-column: span 2;"><span>Certificate SHA-256</span><b style="font-family: monospace; font-size: 13px;">${analysis.certificate?.sha256Fingerprint || "N/A"}</b></div>
  </div>

  <div class="footer">
    Report generated by APKLens on ${new Date().toUTCString()} · Designed by JOJIN JOHN · Confidential Security Report
  </div>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank");
}

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from scanner.models import Finding, SystemContext


def build_report_data(ctx: SystemContext, findings: List[Finding]) -> Dict[str, Any]:
    """Generate normalized dictionary for JSON serialization."""
    now_iso = datetime.now(timezone.utc).isoformat()

    summary = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status == "PASS"),
        "fail": sum(1 for f in findings if f.status == "FAIL"),
        "warn": sum(1 for f in findings if f.status == "WARN"),
        "not_applicable": sum(1 for f in findings if f.status == "NOT_APPLICABLE"),
    }

    # Category canonical order
    category_order = {
        "System": 1,
        "Accounts": 2,
        "Permissions": 3,
        "SSH": 4,
        "Network": 5,
        "Firewall": 6,
        "Logs": 7
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: (category_order.get(f.category, 99), f.id)
    )

    return {
        "scan": {
            "timestamp": now_iso,
            "host": ctx.hostname,
            "platform": ctx.platform,
            "distribution": ctx.distribution,
            "distribution_version": ctx.distribution_version,
            "kernel": ctx.kernel,
            "init_system": ctx.init_system,
            "logging": ctx.logging_mechanism,
            "scan_user": ctx.current_user,
            "is_root": ctx.is_root
        },
        "summary": summary,
        "available_tools": ctx.available_tools,
        "findings": [f.to_dict() for f in sorted_findings]
    }


def write_json_report(report_data: Dict[str, Any], output_path: str) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)


def render_html_report(report_data: Dict[str, Any], template_path: Optional[str] = None) -> str:
    """Render a standalone, CSS-styled, modern HTML report."""
    scan = report_data["scan"]
    summary = report_data["summary"]
    findings = report_data["findings"]

    # Status color classes
    status_classes = {
        "PASS": "badge-pass",
        "FAIL": "badge-fail",
        "WARN": "badge-warn",
        "NOT_APPLICABLE": "badge-na"
    }

    severity_classes = {
        "HIGH": "badge-high",
        "MEDIUM": "badge-med",
        "LOW": "badge-low",
        "INFO": "badge-info"
    }

    findings_rows = []
    for f in findings:
        st_cls = status_classes.get(f["status"], "badge-na")
        sev_cls = severity_classes.get(f["severity"], "badge-info")
        safe_ev = html.escape(f["evidence"])
        safe_desc = html.escape(f["description"])
        safe_exp = html.escape(f["expected"])
        safe_rem = html.escape(f["remediation"])
        refs_html = "".join([f"<li>{html.escape(r)}</li>" for r in f.get("references", [])])

        row = f"""
        <tr class="finding-row status-{f['status'].lower()}">
            <td class="col-id"><strong>{html.escape(f['id'])}</strong></td>
            <td>
                <span class="badge {st_cls}">{html.escape(f['status'])}</span>
                <span class="badge {sev_cls}">{html.escape(f['severity'])}</span>
            </td>
            <td>
                <div class="finding-title">{html.escape(f['title'])}</div>
                <div class="finding-cat">Category: {html.escape(f['category'])}</div>
                <div class="finding-desc">{safe_desc}</div>
                <details class="finding-details">
                    <summary>View Evidence & Remediation</summary>
                    <div class="detail-block">
                        <strong>Observed Evidence:</strong>
                        <pre class="evidence-box"><code>{safe_ev}</code></pre>
                    </div>
                    <div class="detail-block">
                        <strong>Expected Baseline:</strong>
                        <div class="expected-box">{safe_exp}</div>
                    </div>
                    <div class="detail-block">
                        <strong>Remediation Guidance:</strong>
                        <div class="remediation-box">{safe_rem}</div>
                    </div>
                    {f'<div class="detail-block"><strong>References:</strong><ul>{refs_html}</ul></div>' if refs_html else ''}
                </details>
            </td>
        </tr>
        """
        findings_rows.append(row)

    tools_badges = "".join([
        f'<span class="tool-tag {"tool-avail" if avail else "tool-unavail"}">{t}</span>'
        for t, avail in report_data.get("available_tools", {}).items()
    ])

    html_content = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Hardening & Log Audit Report - {html.escape(scan['host'])}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --color-pass: #10b981;
            --color-fail: #ef4444;
            --color-warn: #f59e0b;
            --color-na: #64748b;
            --color-blue: #38bdf8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }}
        h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px;
            position: relative;
            overflow: hidden;
        }}
        .card-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .card-pass .card-value {{ color: var(--color-pass); }}
        .card-fail .card-value {{ color: var(--color-fail); }}
        .card-warn .card-value {{ color: var(--color-warn); }}
        .card-na .card-value {{ color: var(--color-na); }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 0.9rem;
        }}
        .meta-item strong {{ color: #cbd5e1; }}
        .meta-item span {{ color: #38bdf8; font-family: monospace; }}

        .tool-bar {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }}
        .tool-tag {{
            font-size: 0.75rem;
            padding: 3px 8px;
            border-radius: 6px;
            font-family: monospace;
        }}
        .tool-avail {{ background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }}
        .tool-unavail {{ background: #374151; color: #9ca3af; border: 1px dashed #4b5563; }}

        .table-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            overflow: hidden;
        }}
        .table-header {{
            padding: 16px 20px;
            font-size: 1.1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #0f172a;
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 12px 18px;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr.status-fail {{ background-color: rgba(239, 68, 68, 0.05); }}
        tr.status-warn {{ background-color: rgba(245, 158, 11, 0.04); }}

        .col-id {{ width: 100px; font-family: monospace; font-size: 0.95rem; }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 4px;
        }}
        .badge-pass {{ background: #064e3b; color: #6ee7b7; }}
        .badge-fail {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-warn {{ background: #78350f; color: #fcd34d; }}
        .badge-na {{ background: #334155; color: #94a3b8; }}

        .badge-high {{ background: #450a0a; color: #f87171; border: 1px solid #dc2626; }}
        .badge-med {{ background: #451a03; color: #fbbf24; border: 1px solid #d97706; }}
        .badge-low {{ background: #1e3a8a; color: #93c5fd; border: 1px solid #3b82f6; }}
        .badge-info {{ background: #1e293b; color: #94a3b8; border: 1px solid #475569; }}

        .finding-title {{ font-size: 1rem; font-weight: 600; color: #ffffff; margin-bottom: 4px; }}
        .finding-cat {{ font-size: 0.75rem; color: #94a3b8; margin-bottom: 6px; }}
        .finding-desc {{ font-size: 0.9rem; color: #cbd5e1; margin-bottom: 8px; }}

        details.finding-details {{
            margin-top: 10px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 10px 14px;
        }}
        details summary {{
            cursor: pointer;
            font-weight: 500;
            font-size: 0.85rem;
            color: #38bdf8;
            outline: none;
        }}
        .detail-block {{ margin-top: 10px; font-size: 0.85rem; }}
        .detail-block strong {{ color: #e2e8f0; display: block; margin-bottom: 4px; }}
        .evidence-box {{
            background: #090d16;
            color: #34d399;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 250px;
            overflow-y: auto;
        }}
        .expected-box {{
            background: #111827;
            padding: 8px 12px;
            border-radius: 4px;
            color: #cbd5e1;
            border-left: 3px solid #38bdf8;
        }}
        .remediation-box {{
            background: #172554;
            padding: 8px 12px;
            border-radius: 4px;
            color: #bfdbfe;
            border-left: 3px solid #60a5fa;
        }}
        .detail-block ul {{ padding-left: 20px; color: #94a3b8; }}

        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.8rem;
            margin-top: 40px;
            padding-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Linux Hardening & Log Audit Report</h1>
            <div class="subtitle">Distribution-Agnostic Baseline Auditing & Log Monitoring Engine</div>
        </header>

        <div class="grid-summary">
            <div class="card">
                <div class="card-label">Total Checks</div>
                <div class="card-value">{summary['total']}</div>
            </div>
            <div class="card card-pass">
                <div class="card-label">Passed</div>
                <div class="card-value">{summary['pass']}</div>
            </div>
            <div class="card card-fail">
                <div class="card-label">Failed</div>
                <div class="card-value">{summary['fail']}</div>
            </div>
            <div class="card card-warn">
                <div class="card-label">Warnings / Review</div>
                <div class="card-value">{summary['warn']}</div>
            </div>
            <div class="card card-na">
                <div class="card-label">Not Applicable</div>
                <div class="card-value">{summary['not_applicable']}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-item"><strong>Host:</strong> <span>{html.escape(scan['host'])}</span></div>
            <div class="meta-item"><strong>OS & Distro:</strong> <span>{html.escape(scan['distribution'])} ({html.escape(scan['distribution_version'])})</span></div>
            <div class="meta-item"><strong>Kernel:</strong> <span>{html.escape(scan['kernel'])}</span></div>
            <div class="meta-item"><strong>Init System:</strong> <span>{html.escape(scan['init_system'])}</span></div>
            <div class="meta-item"><strong>Logging Source:</strong> <span>{html.escape(scan['logging'])}</span></div>
            <div class="meta-item"><strong>Scan Operator:</strong> <span>{html.escape(scan['scan_user'])} (root={scan['is_root']})</span></div>
            <div class="meta-item"><strong>Timestamp:</strong> <span>{html.escape(scan['timestamp'])}</span></div>
        </div>

        <div class="tool-bar">
            <strong style="font-size: 0.85rem; color: #cbd5e1; margin-right: 6px;">Discovered Tools:</strong>
            {tools_badges}
        </div>

        <div class="table-card">
            <div class="table-header">
                <span>Security & Log Audit Findings</span>
                <span style="font-size: 0.85rem; color: #94a3b8;">Grouped by Category (System &bull; Accounts &bull; Permissions &bull; SSH &bull; Network &bull; Firewall &bull; Logs)</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Status / Severity</th>
                        <th>Details, Evidence & Remediation Guidance</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(findings_rows)}
                </tbody>
            </table>
        </div>

        <footer>
            Automated Log-Monitoring & Linux Hardening Toolkit &bull; Safe Read-Only Baseline &bull; Generated {html.escape(scan['timestamp'])}
        </footer>
    </div>
</body>
</html>
"""
    return html_content


def write_html_report(report_data: Dict[str, Any], output_path: str) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    html_content = render_html_report(report_data)
    p.write_text(html_content, encoding="utf-8")

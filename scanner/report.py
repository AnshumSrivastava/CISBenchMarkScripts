import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
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

    # Compliance score: passed / (passed + failed + warn) * 100
    scored_total = summary["pass"] + summary["fail"] + summary["warn"]
    compliance_score = round((summary["pass"] / scored_total * 100)) if scored_total > 0 else 0
    summary["score"] = compliance_score

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
    """Render a standalone, state-of-the-art interactive HTML security report."""
    scan = report_data["scan"]
    summary = report_data["summary"]
    findings = report_data["findings"]
    score = summary.get("score", 0)

    # Score color rating
    if score >= 80:
        score_gradient = "linear-gradient(135deg, #10b981 0%, #059669 100%)"
        score_status = "Compliant"
    elif score >= 50:
        score_gradient = "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)"
        score_status = "Review Required"
    else:
        score_gradient = "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)"
        score_status = "Action Needed"

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

    category_icons = {
        "System": "💻",
        "Accounts": "👤",
        "Permissions": "🔒",
        "SSH": "🔑",
        "Network": "🌐",
        "Firewall": "🛡️",
        "Logs": "📜"
    }

    # Group counts by category
    categories = ["All", "System", "Accounts", "Permissions", "SSH", "Network", "Firewall", "Logs"]
    category_counts = {c: 0 for c in categories}
    category_counts["All"] = len(findings)
    for f in findings:
        cat = f.get("category", "")
        if cat in category_counts:
            category_counts[cat] += 1

    findings_rows = []
    for f in findings:
        st_cls = status_classes.get(f["status"], "badge-na")
        sev_cls = severity_classes.get(f["severity"], "badge-info")
        safe_ev = html.escape(f["evidence"])
        safe_desc = html.escape(f["description"])
        safe_exp = html.escape(f["expected"])
        safe_rem = html.escape(f["remediation"])
        refs_html = "".join([f"<li>{html.escape(r)}</li>" for r in f.get("references", [])])
        cat_icon = category_icons.get(f["category"], "📁")

        row = f"""
        <tr class="finding-row" data-status="{f['status']}" data-category="{f['category']}" data-search="{html.escape((f['id'] + ' ' + f['title'] + ' ' + f['category'] + ' ' + f['description']).lower())}">
            <td class="col-id">
                <span class="id-tag">{html.escape(f['id'])}</span>
            </td>
            <td class="col-status">
                <div class="status-stack">
                    <span class="badge {st_cls}">{html.escape(f['status'])}</span>
                    <span class="badge {sev_cls}">{html.escape(f['severity'])}</span>
                </div>
            </td>
            <td class="col-content">
                <div class="content-header">
                    <div class="finding-title">{html.escape(f['title'])}</div>
                    <span class="category-pill">{cat_icon} {html.escape(f['category'])}</span>
                </div>
                <div class="finding-desc">{safe_desc}</div>
                <details class="finding-details">
                    <summary><span class="details-icon">▶</span> Detailed Evidence & Safe Remediation</summary>
                    <div class="details-body">
                        <div class="detail-block">
                            <strong><span class="block-icon">🔎</span> Observed System Evidence:</strong>
                            <pre class="evidence-box"><code>{safe_ev}</code></pre>
                        </div>
                        <div class="detail-block">
                            <strong><span class="block-icon">🎯</span> Target CIS Baseline:</strong>
                            <div class="expected-box">{safe_exp}</div>
                        </div>
                        <div class="detail-block">
                            <strong><span class="block-icon">🛠️</span> Remediation Guidance:</strong>
                            <div class="remediation-box">{safe_rem}</div>
                        </div>
                        {f'<div class="detail-block"><strong><span class="block-icon">📚</span> Benchmark References:</strong><ul class="ref-list">{refs_html}</ul></div>' if refs_html else ''}
                    </div>
                </details>
            </td>
        </tr>
        """
        findings_rows.append(row)

    tools_badges = "".join([
        f'<span class="tool-tag {"tool-avail" if avail else "tool-unavail"}"><span class="dot"></span>{t}</span>'
        for t, avail in sorted(report_data.get("available_tools", {}).items())
    ])

    category_filters_html = "".join([
        f'<button class="tab-btn {"active" if cat == "All" else ""}" data-category="{cat}">{category_icons.get(cat, "")} {cat} <span class="tab-count">{category_counts.get(cat, 0)}</span></button>'
        for cat in categories if category_counts.get(cat, 0) > 0 or cat == "All"
    ])

    html_content = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Hardening & Log Audit Report &bull; {html.escape(scan['host'])}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: rgba(17, 24, 39, 0.75);
            --bg-card-hover: rgba(30, 41, 59, 0.7);
            --bg-surface: #131d31;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-focus: #38bdf8;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --color-pass: #10b981;
            --color-pass-bg: rgba(16, 185, 129, 0.12);
            --color-fail: #f43f5e;
            --color-fail-bg: rgba(244, 63, 94, 0.12);
            --color-warn: #f59e0b;
            --color-warn-bg: rgba(245, 158, 11, 0.12);
            --color-na: #64748b;
            --color-na-bg: rgba(100, 116, 139, 0.12);
            --color-cyan: #06b6d4;
            --color-blue: #3b82f6;
            --color-indigo: #6366f1;
            --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: var(--font-sans);
            background-color: var(--bg-body);
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
                radial-gradient(at 50% 100%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            line-height: 1.6;
            padding: 40px 24px;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}

        /* Header Styling */
        header {{
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 28px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(12px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 24px;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .brand-icon {{
            font-size: 2.4rem;
            background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            filter: drop-shadow(0 2px 8px rgba(14, 165, 233, 0.4));
        }}

        h1 {{
            font-size: 1.85rem;
            font-weight: 800;
            color: #ffffff;
            letter-spacing: -0.02em;
            line-height: 1.2;
        }}

        .subtitle {{
            color: var(--text-muted);
            font-size: 0.95rem;
            font-weight: 500;
            margin-top: 4px;
        }}

        /* Score Gauge Pill */
        .score-card {{
            display: flex;
            align-items: center;
            gap: 18px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-subtle);
            padding: 14px 22px;
            border-radius: 14px;
        }}

        .score-circle {{
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: {score_gradient};
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.35rem;
            font-weight: 800;
            color: #ffffff;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.3);
        }}

        .score-info {{
            display: flex;
            flex-direction: column;
        }}

        .score-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-dim);
            font-weight: 600;
        }}

        .score-val-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: #ffffff;
        }}

        /* Summary Cards Grid */
        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 20px;
            backdrop-filter: blur(8px);
            transition: transform 0.2s ease, border-color 0.2s ease;
            position: relative;
            overflow: hidden;
        }}

        .card:hover {{
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.16);
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }}

        .card-total::before {{ background: #38bdf8; }}
        .card-pass::before {{ background: var(--color-pass); }}
        .card-fail::before {{ background: var(--color-fail); }}
        .card-warn::before {{ background: var(--color-warn); }}
        .card-na::before {{ background: var(--color-na); }}

        .card-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            font-weight: 600;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .card-value {{
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.02em;
        }}

        .card-pass .card-value {{ color: var(--color-pass); }}
        .card-fail .card-value {{ color: var(--color-fail); }}
        .card-warn .card-value {{ color: var(--color-warn); }}
        .card-na .card-value {{ color: var(--color-na); }}
        .card-total .card-value {{ color: #38bdf8; }}

        /* Meta Grid */
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 12px;
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 18px 22px;
            margin-bottom: 24px;
            backdrop-filter: blur(8px);
        }}

        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}

        .meta-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            font-weight: 600;
        }}

        .meta-val {{
            color: #38bdf8;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            font-weight: 500;
        }}

        /* Tool Bar */
        .tool-bar {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 14px 20px;
            margin-bottom: 28px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
        }}

        .tool-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
            margin-right: 4px;
        }}

        .tool-tag {{
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 20px;
            font-family: var(--font-mono);
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-weight: 500;
        }}

        .tool-tag .dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }}

        .tool-avail {{
            background: rgba(16, 185, 129, 0.1);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .tool-avail .dot {{ background: #10b981; }}

        .tool-unavail {{
            background: rgba(100, 116, 139, 0.1);
            color: #94a3b8;
            border: 1px solid rgba(100, 116, 139, 0.2);
        }}
        .tool-unavail .dot {{ background: #64748b; }}

        /* Filter Controls */
        .filter-section {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 20px 24px;
            margin-bottom: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .filter-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .search-box {{
            position: relative;
            flex: 1;
            min-width: 260px;
            max-width: 420px;
        }}

        .search-input {{
            width: 100%;
            padding: 10px 16px 10px 38px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            color: #ffffff;
            font-size: 0.9rem;
            font-family: var(--font-sans);
            outline: none;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }}

        .search-input:focus {{
            border-color: var(--color-cyan);
            box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
        }}

        .search-icon {{
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-dim);
            font-size: 0.9rem;
            pointer-events: none;
        }}

        .status-pills {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .status-pill {{
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid var(--border-subtle);
            background: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .status-pill.active {{
            background: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            border-color: rgba(56, 189, 248, 0.4);
        }}

        .category-tabs {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            border-top: 1px solid var(--border-subtle);
            padding-top: 14px;
        }}

        .tab-btn {{
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-muted);
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }}

        .tab-btn:hover {{
            background: rgba(255, 255, 255, 0.05);
            color: #ffffff;
        }}

        .tab-btn.active {{
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            border-color: rgba(99, 102, 241, 0.35);
        }}

        .tab-count {{
            font-size: 0.75rem;
            padding: 1px 6px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.1);
        }}

        /* Findings Table Card */
        .table-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(8px);
        }}

        .table-header {{
            padding: 18px 24px;
            font-size: 1.1rem;
            font-weight: 700;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(15, 23, 42, 0.4);
        }}

        .table-counter {{
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: 500;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            background: rgba(11, 15, 25, 0.9);
            color: var(--text-dim);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700;
            padding: 14px 20px;
            border-bottom: 1px solid var(--border-subtle);
        }}

        td {{
            padding: 18px 20px;
            border-bottom: 1px solid var(--border-subtle);
            vertical-align: top;
        }}

        tr.finding-row {{
            transition: background-color 0.15s ease;
        }}

        tr.finding-row:hover {{
            background-color: var(--bg-card-hover);
        }}

        tr:last-child td {{ border-bottom: none; }}

        .col-id {{
            width: 120px;
            white-space: nowrap;
        }}

        .id-tag {{
            font-family: var(--font-mono);
            font-size: 0.85rem;
            font-weight: 600;
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.2);
            padding: 4px 8px;
            border-radius: 6px;
            display: inline-block;
        }}

        .col-status {{
            width: 130px;
            white-space: nowrap;
        }}

        .status-stack {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            text-align: center;
        }}

        .badge-pass {{ background: var(--color-pass-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-fail {{ background: var(--color-fail-bg); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }}
        .badge-warn {{ background: var(--color-warn-bg); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-na {{ background: var(--color-na-bg); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }}

        .badge-high {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-med {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.15); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-info {{ background: rgba(100, 116, 139, 0.15); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.4); }}

        .content-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 6px;
        }}

        .finding-title {{
            font-size: 1.05rem;
            font-weight: 700;
            color: #ffffff;
        }}

        .category-pill {{
            font-size: 0.75rem;
            color: #cbd5e1;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border-subtle);
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 500;
        }}

        .finding-desc {{
            font-size: 0.9rem;
            color: #cbd5e1;
            margin-bottom: 12px;
        }}

        /* Accordion Details */
        details.finding-details {{
            background: rgba(11, 15, 25, 0.6);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            overflow: hidden;
            transition: all 0.2s ease;
        }}

        details.finding-details[open] {{
            border-color: rgba(56, 189, 248, 0.3);
            background: rgba(11, 15, 25, 0.9);
        }}

        details summary {{
            cursor: pointer;
            padding: 10px 16px;
            font-weight: 600;
            font-size: 0.85rem;
            color: #38bdf8;
            outline: none;
            user-select: none;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: color 0.15s ease;
        }}

        details summary:hover {{
            color: #7dd3fc;
        }}

        .details-icon {{
            font-size: 0.7rem;
            transition: transform 0.2s ease;
        }}

        details[open] .details-icon {{
            transform: rotate(90deg);
        }}

        .details-body {{
            padding: 0 16px 16px 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .detail-block {{
            font-size: 0.85rem;
        }}

        .detail-block strong {{
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 6px;
            font-weight: 600;
        }}

        .block-icon {{
            font-size: 0.9rem;
        }}

        .evidence-box {{
            background: #060911;
            color: #34d399;
            border: 1px solid rgba(52, 211, 153, 0.2);
            padding: 12px 14px;
            border-radius: 8px;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 250px;
            overflow-y: auto;
        }}

        .expected-box {{
            background: rgba(30, 41, 59, 0.6);
            border-left: 3px solid #38bdf8;
            padding: 10px 14px;
            border-radius: 6px;
            color: #e2e8f0;
            font-size: 0.85rem;
        }}

        .remediation-box {{
            background: rgba(30, 58, 138, 0.25);
            border-left: 3px solid #60a5fa;
            border: 1px solid rgba(96, 165, 250, 0.2);
            border-left-width: 3px;
            padding: 10px 14px;
            border-radius: 6px;
            color: #bfdbfe;
            font-size: 0.85rem;
            line-height: 1.5;
        }}

        .ref-list {{
            padding-left: 20px;
            color: var(--text-muted);
            font-size: 0.8rem;
        }}

        .no-matches {{
            padding: 40px;
            text-align: center;
            color: var(--text-muted);
            font-size: 1rem;
            display: none;
        }}

        footer {{
            text-align: center;
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-top: 50px;
            padding-bottom: 30px;
            border-top: 1px solid var(--border-subtle);
            padding-top: 24px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div>
                    <h1>Linux Hardening & Log Audit Report</h1>
                    <div class="subtitle">Distribution-Agnostic CIS Benchmark & Authentication Audit</div>
                </div>
            </div>
            <div class="score-card">
                <div class="score-circle">{score}%</div>
                <div class="score-info">
                    <span class="score-label">Compliance Score</span>
                    <span class="score-val-title">{score_status}</span>
                </div>
            </div>
        </header>

        <div class="grid-summary">
            <div class="card card-total">
                <div class="card-label">Total Evaluated <span>📋</span></div>
                <div class="card-value">{summary['total']}</div>
            </div>
            <div class="card card-pass">
                <div class="card-label">Compliant <span>✅</span></div>
                <div class="card-value">{summary['pass']}</div>
            </div>
            <div class="card card-fail">
                <div class="card-label">Failures <span>❌</span></div>
                <div class="card-value">{summary['fail']}</div>
            </div>
            <div class="card card-warn">
                <div class="card-label">Warnings / Review <span>⚠️</span></div>
                <div class="card-value">{summary['warn']}</div>
            </div>
            <div class="card card-na">
                <div class="card-label">Not Applicable <span>➖</span></div>
                <div class="card-value">{summary['not_applicable']}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">Target Hostname</span>
                <span class="meta-val">{html.escape(scan['host'])}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Operating System</span>
                <span class="meta-val">{html.escape(scan['distribution'])} ({html.escape(scan['distribution_version'])})</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Kernel Version</span>
                <span class="meta-val">{html.escape(scan['kernel'])}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Init System (PID 1)</span>
                <span class="meta-val">{html.escape(scan['init_system'])}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Log Subsystem</span>
                <span class="meta-val">{html.escape(scan['logging'])}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Scan Operator</span>
                <span class="meta-val">{html.escape(scan['scan_user'])} (root={scan['is_root']})</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Generated Timestamp</span>
                <span class="meta-val">{html.escape(scan['timestamp'])}</span>
            </div>
        </div>

        <div class="tool-bar">
            <span class="tool-label">Detected Tools:</span>
            {tools_badges}
        </div>

        <div class="filter-section">
            <div class="filter-top">
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="searchInput" class="search-input" placeholder="Search check ID, title, keyword...">
                </div>
                <div class="status-pills">
                    <button class="status-pill active" data-status="ALL">All Statuses</button>
                    <button class="status-pill" data-status="FAIL">Failures ({summary['fail']})</button>
                    <button class="status-pill" data-status="WARN">Warnings ({summary['warn']})</button>
                    <button class="status-pill" data-status="PASS">Passed ({summary['pass']})</button>
                    <button class="status-pill" data-status="NOT_APPLICABLE">N/A ({summary['not_applicable']})</button>
                </div>
            </div>
            <div class="category-tabs">
                {category_filters_html}
            </div>
        </div>

        <div class="table-card">
            <div class="table-header">
                <span>Security & Log Audit Findings</span>
                <span class="table-counter" id="visibleCounter">Showing all {len(findings)} checks</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Status / Severity</th>
                        <th>Details, Evidence & Remediation Guidance</th>
                    </tr>
                </thead>
                <tbody id="findingsBody">
                    {"".join(findings_rows)}
                </tbody>
            </table>
            <div id="noMatches" class="no-matches">
                No security checks match your current filter selection.
            </div>
        </div>

        <footer>
            Automated Log-Monitoring & Linux Hardening Toolkit &bull; Safe Read-Only Baseline Engine &bull; Generated {html.escape(scan['timestamp'])}
        </footer>
    </div>

    <script>
        (function() {{
            const searchInput = document.getElementById('searchInput');
            const statusPills = document.querySelectorAll('.status-pill');
            const tabButtons = document.querySelectorAll('.tab-btn');
            const rows = document.querySelectorAll('.finding-row');
            const visibleCounter = document.getElementById('visibleCounter');
            const noMatches = document.getElementById('noMatches');

            let currentStatus = 'ALL';
            let currentCategory = 'All';
            let searchQuery = '';

            function updateFilters() {{
                let visibleCount = 0;

                rows.forEach(row => {{
                    const rowStatus = row.getAttribute('data-status');
                    const rowCategory = row.getAttribute('data-category');
                    const rowSearch = row.getAttribute('data-search');

                    const matchesStatus = (currentStatus === 'ALL' || rowStatus === currentStatus);
                    const matchesCategory = (currentCategory === 'All' || rowCategory === currentCategory);
                    const matchesSearch = (!searchQuery || rowSearch.includes(searchQuery));

                    if (matchesStatus && matchesCategory && matchesSearch) {{
                        row.style.display = '';
                        visibleCount++;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                visibleCounter.textContent = `Showing ${{visibleCount}} of ${{rows.length}} checks`;
                noMatches.style.display = visibleCount === 0 ? 'block' : 'none';
            }}

            statusPills.forEach(pill => {{
                pill.addEventListener('click', () => {{
                    statusPills.forEach(p => p.classList.remove('active'));
                    pill.classList.add('active');
                    currentStatus = pill.getAttribute('data-status');
                    updateFilters();
                }});
            }});

            tabButtons.forEach(tab => {{
                tab.addEventListener('click', () => {{
                    tabButtons.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    currentCategory = tab.getAttribute('data-category');
                    updateFilters();
                }});
            }});

            searchInput.addEventListener('input', (e) => {{
                searchQuery = e.target.value.toLowerCase().trim();
                updateFilters();
            }});
        }})();
    </script>
</body>
</html>
"""
    return html_content


def write_html_report(report_data: Dict[str, Any], output_path: str) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    html_content = render_html_report(report_data)
    p.write_text(html_content, encoding="utf-8")

import argparse
import json
import sys
from pathlib import Path
from scanner.discovery import discover_system
from scanner.runner import run_all_checks
from scanner.report import build_report_data, write_json_report, write_html_report
from scanner.remediation import get_remediation_guidance


def cmd_discover(args: argparse.Namespace) -> None:
    """Print system discovery environment."""
    ctx = discover_system()
    print("==================================================")
    print("🔍 Linux Environment Discovery")
    print("==================================================")
    print(f"Platform     : {ctx.platform}")
    print(f"Distribution : {ctx.distribution} (ID: {ctx.distribution_id}, Version: {ctx.distribution_version})")
    print(f"Kernel       : {ctx.kernel}")
    print(f"Hostname     : {ctx.hostname}")
    print(f"Current User : {ctx.current_user} (root: {ctx.is_root})")
    print(f"Init System  : {ctx.init_system}")
    print(f"Logging      : {ctx.logging_mechanism}")
    print(f"Auth Log     : {ctx.auth_log_path or 'none'}")
    print(f"SSHD Config  : {ctx.sshd_config_path or 'none'}")
    print("\nDiscovered System Tools:")
    for tool, avail in sorted(ctx.available_tools.items()):
        status_str = "AVAILABLE" if avail else "unavailable"
        print(f"  - {tool:<14}: {status_str}")
    print("==================================================")


def cmd_audit(args: argparse.Namespace) -> None:
    """Execute all security and log checks, produce console output, JSON and HTML reports."""
    print("==================================================")
    print("🛡️ Starting Linux Security & Log Audit")
    print("==================================================")

    ctx = discover_system()
    findings = run_all_checks(ctx)

    # Color codes for terminal
    STATUS_COLORS = {
        "PASS": "\033[92m[PASS]\033[0m",
        "FAIL": "\033[91m[FAIL]\033[0m",
        "WARN": "\033[93m[WARN]\033[0m",
        "NOT_APPLICABLE": "\033[90m[N/A ]\033[0m"
    }

    # Print live console output grouped by category
    current_cat = None
    for f in findings:
        if f.category != current_cat:
            current_cat = f.category
            print(f"\n📂 \033[1;36mCategory: {current_cat}\033[0m")
        color_tag = STATUS_COLORS.get(f.status, f"[{f.status}]")
        print(f"  {color_tag} {f.id:<8} {f.title}")

    # Build report data
    report_data = build_report_data(ctx, findings)
    summary = report_data["summary"]

    print("\n--------------------------------------------------")
    print(f"Audit Summary: {summary['total']} total | {summary['pass']} PASS | {summary['fail']} FAIL | {summary['warn']} WARN | {summary['not_applicable']} N/A")
    print("--------------------------------------------------")

    json_path = args.json_output or "output/report.json"
    html_path = args.html_output or "output/report.html"

    write_json_report(report_data, json_path)
    write_html_report(report_data, html_path)

    print(f"Report written to:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")
    print("==================================================")


def cmd_report(args: argparse.Namespace) -> None:
    """Regenerate HTML report from an existing JSON report."""
    input_file = Path(args.input_json)
    if not input_file.exists():
        print(f"Error: JSON file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    html_out = args.output_html or str(input_file.with_suffix(".html"))
    write_html_report(data, html_out)
    print(f"Generated HTML report from '{input_file}' -> '{html_out}'")


def cmd_remediation(args: argparse.Namespace) -> None:
    """Display detailed safe remediation guidance for a specific check ID."""
    check_id = args.check.upper().strip()
    guide = get_remediation_guidance(check_id)

    if not guide:
        print(f"No specific remediation guidance registered for check ID '{check_id}'.")
        print("Available check IDs: SYS-001, ACC-001, ACC-002, ACC-003, PERM-001, PERM-002, SSH-001, SSH-002, NET-001, FW-001, LOG-001, LOG-002")
        return

    print("==================================================")
    print(f"🛠️ Remediation Guidance: {check_id} - {guide['title']}")
    print("==================================================")
    print(f"Objective : {guide['action']}")
    print("\nRecommended Step-by-Step Remediation:")
    for idx, step in enumerate(guide["steps"], start=1):
        print(f"  {idx}. {step}")

    print(f"\nSafe Verification Command:\n  $ {guide['safe_command']}")
    print(f"\n⚠️  Cautionary Warning:\n  {guide['warning']}")
    print("==================================================")


def main():
    parser = argparse.ArgumentParser(
        prog="python -m scanner.main",
        description="Automated Log-Monitoring & Linux Hardening Toolkit (Distribution-Agnostic)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Discover subcommand
    subparsers.add_parser("discover", help="Discover Linux host environment and capabilities")

    # Audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Run read-only security checks and log audit")
    audit_parser.add_argument("--json-output", "-j", default="output/report.json", help="Path to write JSON report")
    audit_parser.add_argument("--html-output", "-H", default="output/report.html", help="Path to write HTML report")

    # Report subcommand
    report_parser = subparsers.add_parser("report", help="Render HTML report from existing JSON report")
    report_parser.add_argument("input_json", help="Path to input JSON report")
    report_parser.add_argument("--output-html", "-o", default=None, help="Path for output HTML report")

    # Remediation subcommand
    rem_parser = subparsers.add_parser("remediation", help="View safe remediation guidance for a check ID")
    rem_parser.add_argument("--check", "-c", required=True, help="Check ID (e.g., SSH-001, ACC-002)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "discover":
        cmd_discover(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "remediation":
        cmd_remediation(args)


if __name__ == "__main__":
    main()

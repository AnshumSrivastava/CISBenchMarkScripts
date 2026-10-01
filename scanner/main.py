import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, List

from scanner.discovery import discover_system
from scanner.runner import run_all_checks
from scanner.report import build_report_data, write_json_report, write_html_report
from scanner.remediation import get_remediation_guidance, REMEDIATION_DATABASE

ROOT_DIR = Path(__file__).resolve().parent.parent

SCRIPTS_MAP = {
    "system": ROOT_DIR / "scripts" / "system" / "audit_system.sh",
    "accounts": ROOT_DIR / "scripts" / "accounts" / "audit_accounts.sh",
    "permissions": ROOT_DIR / "scripts" / "permissions" / "audit_permissions.sh",
    "ssh": ROOT_DIR / "scripts" / "ssh" / "audit_ssh.sh",
    "network": ROOT_DIR / "scripts" / "network" / "audit_network.sh",
    "firewall": ROOT_DIR / "scripts" / "firewall" / "audit_firewall.sh",
    "logs": ROOT_DIR / "scripts" / "logs" / "audit_logs.sh",
    "discovery": ROOT_DIR / "scripts" / "collect_system.sh"
}


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
    """Execute security and log checks, produce console output, JSON and HTML reports."""
    cat_filter = getattr(args, "category", None)
    cat_label = f" (Category: {cat_filter})" if cat_filter else " (All Categories)"

    print("==================================================")
    print(f"🛡️ Starting Linux Security & Log Audit{cat_label}")
    print("==================================================")

    ctx = discover_system()
    findings = run_all_checks(ctx, category=cat_filter)

    if not findings:
        print(f"No checks matched category '{cat_filter}'.")
        print("Available categories: System, Accounts, Permissions, SSH, Network, Firewall, Logs")
        return

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
        if getattr(args, "verbose", False):
            print(f"       \033[90mExpected : {f.expected}\033[0m")
            if f.evidence:
                ev_preview = f.evidence.strip().replace("\n", "\n       ")
                print(f"       \033[33mEvidence : {ev_preview}\033[0m")

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


def cmd_list(args: argparse.Namespace) -> None:
    """List all registered checks, descriptions, severity, and categories."""
    checks_config = ROOT_DIR / "config" / "checks.json"
    if not checks_config.exists():
        print("Configuration file config/checks.json not found.", file=sys.stderr)
        return

    with open(checks_config, "r", encoding="utf-8") as f:
        checks = json.load(f)

    cat_filter = getattr(args, "category", None)
    if cat_filter:
        checks = [c for c in checks if c.get("category", "").lower() == cat_filter.lower().strip()]

    print("================================================================================")
    print(f"📋 Registered CIS Hardening & Log Checks ({len(checks)} controls)")
    print("================================================================================")
    print(f"{'ID':<10} {'Category':<14} {'Severity':<9} {'Title'}")
    print("-" * 80)

    for c in checks:
        print(f"{c['id']:<10} {c.get('category', 'General'):<14} {c.get('severity', 'INFO'):<9} {c['title']}")

    print("================================================================================")


def cmd_script(args: argparse.Namespace) -> None:
    """Execute a standalone Bash category audit script."""
    target = args.target.lower().strip()
    script_path = SCRIPTS_MAP.get(target)

    if not script_path or not script_path.exists():
        print(f"Error: Unknown or missing script for target '{target}'.", file=sys.stderr)
        print(f"Available script targets: {', '.join(SCRIPTS_MAP.keys())}")
        return

    print(f"🚀 Executing Bash audit script: {script_path.relative_to(ROOT_DIR)}")
    print("--------------------------------------------------")
    try:
        res = subprocess.run(["bash", str(script_path)], text=True)
        sys.exit(res.returncode)
    except KeyboardInterrupt:
        print("\nScript interrupted.")
    except Exception as e:
        print(f"Error running script: {e}", file=sys.stderr)


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
    """Display detailed safe remediation guidance for a specific check ID or list all."""
    check_id = args.check.upper().strip() if args.check else None

    if not check_id:
        print("==================================================")
        print("🛠️ All Available Remediation Guidance Check IDs")
        print("==================================================")
        for cid, details in sorted(REMEDIATION_DATABASE.items()):
            print(f"  - {cid:<9}: {details['title']}")
        print("\nSpecify a check using --check <CHECK_ID> (e.g., cli.py remediation -c SSH-001)")
        print("==================================================")
        return

    guide = get_remediation_guidance(check_id)
    if not guide:
        print(f"No specific remediation guidance registered for check ID '{check_id}'.")
        print(f"Available check IDs: {', '.join(sorted(REMEDIATION_DATABASE.keys()))}")
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


def interactive_menu():
    """Display an interactive CLI dashboard menu when launched without arguments."""
    while True:
        print("\n==================================================")
        print("🛡️  Linux Hardening & Log Auditing Toolkit (CLI)")
        print("==================================================")
        print("  1. Run Full Security & Log Audit (All 21 Checks)")
        print("  2. Run Audit for Specific Category")
        print("  3. Discover Host Environment & Tool Capabilities")
        print("  4. List All Registered Checks & Baselines")
        print("  5. Run Standalone Category Bash Script")
        print("  6. View Remediation Guidance for a Check")
        print("  7. Regenerate HTML Dashboard from JSON Report")
        print("  0. Exit")
        print("--------------------------------------------------")

        try:
            choice = input("Enter choice [0-7]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            print("\n")
            cmd_audit(argparse.Namespace(category=None, verbose=False, json_output="output/report.json", html_output="output/report.html"))
        elif choice == "2":
            print("\nAvailable Categories: System, Accounts, Permissions, SSH, Network, Firewall, Logs")
            cat = input("Enter Category Name: ").strip()
            if cat:
                cmd_audit(argparse.Namespace(category=cat, verbose=True, json_output=f"output/report_{cat.lower()}.json", html_output=f"output/report_{cat.lower()}.html"))
        elif choice == "3":
            print("\n")
            cmd_discover(argparse.Namespace())
        elif choice == "4":
            print("\n")
            cmd_list(argparse.Namespace(category=None))
        elif choice == "5":
            print(f"\nAvailable Scripts: {', '.join(SCRIPTS_MAP.keys())}")
            scr = input("Enter script target name: ").strip()
            if scr:
                cmd_script(argparse.Namespace(target=scr))
        elif choice == "6":
            cid = input("Enter Check ID (or press Enter to view all): ").strip()
            cmd_remediation(argparse.Namespace(check=cid if cid else None))
        elif choice == "7":
            jfile = input("Enter path to JSON report [output/report.json]: ").strip() or "output/report.json"
            hfile = input("Enter output HTML path [output/report.html]: ").strip() or "output/report.html"
            cmd_report(argparse.Namespace(input_json=jfile, output_html=hfile))
        elif choice == "0":
            print("Goodbye.")
            break
        else:
            print("Invalid choice, please select between 0 and 7.")


def main():
    parser = argparse.ArgumentParser(
        prog="cli.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
=======================================================================
 🛡️ Linux Hardening & Log Auditing Toolkit CLI
 Distribution-Agnostic Baseline Auditing & Log Monitoring Engine
=======================================================================

Examples:
  ./cli.py audit                         # Run full audit (all 21 checks)
  ./cli.py audit --category ssh -v       # Run only SSH checks with verbose evidence
  ./cli.py list                          # List all checks, severity, & descriptions
  ./cli.py list --category permissions   # List only permissions checks
  ./cli.py discover                      # Scan environment & available tools
  ./cli.py script ssh                    # Run standalone Bash SSH audit script
  ./cli.py remediation --check ACC-002   # View safe step-by-step remediation
  ./cli.py report output/report.json     # Regenerate HTML dashboard report
  ./cli.py --menu                        # Launch interactive terminal menu
"""
    )
    parser.add_argument("--menu", "-m", action="store_true", help="Launch interactive menu mode")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Discover subcommand
    subparsers.add_parser("discover", help="Discover Linux host environment and capabilities")

    # Audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Run read-only security checks and log audit")
    audit_parser.add_argument("--category", "-c", default=None, choices=["system", "accounts", "permissions", "ssh", "network", "firewall", "logs", "System", "Accounts", "Permissions", "SSH", "Network", "Firewall", "Logs"], help="Filter audit to a specific category")
    audit_parser.add_argument("--verbose", "-v", action="store_true", help="Display expected baselines and evidence in console")
    audit_parser.add_argument("--json-output", "-j", default="output/report.json", help="Path to write JSON report")
    audit_parser.add_argument("--html-output", "-H", default="output/report.html", help="Path to write HTML report")

    # List subcommand
    list_parser = subparsers.add_parser("list", help="List all registered checks with severity and descriptions")
    list_parser.add_argument("--category", "-c", default=None, help="Filter listing by category")

    # Script subcommand
    script_parser = subparsers.add_parser("script", help="Run a standalone category Bash audit script")
    script_parser.add_argument("target", choices=list(SCRIPTS_MAP.keys()), help=f"Script category to execute ({', '.join(SCRIPTS_MAP.keys())})")

    # Report subcommand
    report_parser = subparsers.add_parser("report", help="Render HTML report from existing JSON report")
    report_parser.add_argument("input_json", help="Path to input JSON report")
    report_parser.add_argument("--output-html", "-o", default=None, help="Path for output HTML report")

    # Remediation subcommand
    rem_parser = subparsers.add_parser("remediation", help="View safe remediation guidance for a check ID")
    rem_parser.add_argument("--check", "-c", default=None, help="Check ID (e.g., SSH-001, ACC-002). Omit to list all.")

    args = parser.parse_args()

    if args.menu or len(sys.argv) == 1:
        if len(sys.argv) == 1:
            # When run with no args, check if stdin is a tty; if so, open menu, else print help
            if sys.stdin.isatty():
                interactive_menu()
                return
            else:
                parser.print_help()
                return
        interactive_menu()
        return

    if args.command == "discover":
        cmd_discover(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "script":
        cmd_script(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "remediation":
        cmd_remediation(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

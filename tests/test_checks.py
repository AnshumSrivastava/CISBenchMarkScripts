import pytest
from scanner.checks import parse_directive, parse_login_defs_directive, check_acc_001_uid_zero
from scanner.models import SystemContext
from scanner.permissions import is_permission_more_permissive

def test_parse_directive():
    text = """
    # SSH Configuration
    # PermitRootLogin yes
    Port 22
    PermitRootLogin no
    PasswordAuthentication no
    """
    assert parse_directive(text, "PermitRootLogin") == "no"
    assert parse_directive(text, "PasswordAuthentication") == "no"
    assert parse_directive(text, "Port") == "22"
    assert parse_directive(text, "X11Forwarding") is None

def test_parse_directive_case_insensitive():
    text = "permitrootlogin prohibit-password"
    assert parse_directive(text, "PermitRootLogin") == "prohibit-password"

def test_parse_login_defs_directive():
    text = """
    PASS_MAX_DAYS   90
    PASS_MIN_DAYS   1
    PASS_WARN_AGE   7
    """
    assert parse_login_defs_directive(text, "PASS_MAX_DAYS") == 90
    assert parse_login_defs_directive(text, "PASS_MIN_DAYS") == 1
    assert parse_login_defs_directive(text, "PASS_WARN_AGE") == 7

def test_permission_more_permissive():
    # 0666 is more permissive than 0644
    assert is_permission_more_permissive(0o666, 0o644) is True
    # 0644 is NOT more permissive than 0644
    assert is_permission_more_permissive(0o644, 0o644) is False
    # 0600 is NOT more permissive than 0644
    assert is_permission_more_permissive(0o600, 0o644) is False
    # 0640 is NOT more permissive than 0640
    assert is_permission_more_permissive(0o640, 0o640) is False
    # 0644 is more permissive than 0640
    assert is_permission_more_permissive(0o644, 0o640) is True
    # 0440 baseline for sudoers
    assert is_permission_more_permissive(0o640, 0o440) is True
    assert is_permission_more_permissive(0o400, 0o440) is False


def test_registered_checks_count_and_categories():
    from scanner.runner import REGISTERED_CHECKS
    from scanner.discovery import discover_system

    # Verify all 19 checks are registered
    assert len(REGISTERED_CHECKS) == 21

    ctx = discover_system()
    findings = [fn(ctx) for fn in REGISTERED_CHECKS]
    assert len(findings) == 21

    categories = {f.category for f in findings}
    expected_categories = {"System", "Accounts", "Permissions", "SSH", "Network", "Firewall", "Logs"}
    assert expected_categories.issubset(categories)


def test_report_sorting_by_category():
    from scanner.report import build_report_data
    from scanner.models import Finding, SystemContext

    ctx = SystemContext(
        platform="Linux",
        distribution="Arch Linux",
        distribution_id="arch",
        distribution_version="rolling",
        kernel="6.x",
        hostname="testbox",
        current_user="root",
        is_root=True,
        init_system="systemd",
        logging_mechanism="journald",
        available_tools={}
    )

    findings = [
        Finding(id="LOG-001", title="Log Failure", category="Logs", severity="MEDIUM", status="PASS", description="", evidence="", expected="", remediation="", references=[]),
        Finding(id="SYS-001", title="Sys Info", category="System", severity="INFO", status="PASS", description="", evidence="", expected="", remediation="", references=[]),
        Finding(id="SSH-001", title="Root Login", category="SSH", severity="HIGH", status="FAIL", description="", evidence="", expected="", remediation="", references=[]),
        Finding(id="ACC-001", title="UID 0", category="Accounts", severity="HIGH", status="PASS", description="", evidence="", expected="", remediation="", references=[])
    ]

    report = build_report_data(ctx, findings)
    reported_ids = [f["id"] for f in report["findings"]]
    # Should sort: System -> Accounts -> SSH -> Logs
    assert reported_ids == ["SYS-001", "ACC-001", "SSH-001", "LOG-001"]


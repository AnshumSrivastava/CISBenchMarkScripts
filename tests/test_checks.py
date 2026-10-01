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

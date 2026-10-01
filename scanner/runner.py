import traceback
from typing import List, Callable
from scanner.models import Finding, SystemContext
from scanner.checks import (
    check_sys_001,
    check_acc_001_uid_zero,
    check_acc_002_empty_passwords,
    check_acc_003_password_ageing,
    check_perm_001_core_account_files,
    check_perm_002_shadow_permissions,
    check_ssh_001_root_login,
    check_ssh_002_password_auth,
    check_net_001_listeners,
    check_fw_001_firewall,
    check_log_001_auth_failures,
    check_log_002_auth_success
)

REGISTERED_CHECKS: List[Callable[[SystemContext], Finding]] = [
    check_sys_001,
    check_acc_001_uid_zero,
    check_acc_002_empty_passwords,
    check_acc_003_password_ageing,
    check_perm_001_core_account_files,
    check_perm_002_shadow_permissions,
    check_ssh_001_root_login,
    check_ssh_002_password_auth,
    check_net_001_listeners,
    check_fw_001_firewall,
    check_log_001_auth_failures,
    check_log_002_auth_success
]


def make_safe_warning(check_fn_name: str, error_msg: str) -> Finding:
    """Fallback generator when a check raises an unexpected exception."""
    check_id = check_fn_name.replace("check_", "").upper().split("_")[0]
    return Finding(
        id=check_id,
        title=f"Check Execution Exception ({check_fn_name})",
        category="Execution",
        severity="MEDIUM",
        status="WARN",
        description="The check runner encountered an unexpected error during execution.",
        evidence=error_msg,
        expected="Clean check execution",
        remediation="Review system permissions or inspect check error trace.",
        references=[]
    )


def run_all_checks(ctx: SystemContext) -> List[Finding]:
    """Execute all registered checks sequentially and handle exceptions defensively."""
    findings: List[Finding] = []
    for check_fn in REGISTERED_CHECKS:
        try:
            finding = check_fn(ctx)
            findings.append(finding)
        except PermissionError as pe:
            findings.append(make_safe_warning(check_fn.__name__, f"Permission denied during check execution: {pe}"))
        except Exception as e:
            tb = traceback.format_exc()
            findings.append(make_safe_warning(check_fn.__name__, f"Unhandled error: {e}\n{tb}"))
    return findings

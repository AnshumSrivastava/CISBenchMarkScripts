import traceback
from typing import List, Callable, Optional
from scanner.models import Finding, SystemContext
from scanner.checks import (
    # System
    check_sys_001,
    check_sys_002_core_dumps,
    check_sys_003_aslr,
    # Accounts
    check_acc_001_uid_zero,
    check_acc_002_empty_passwords,
    check_acc_003_password_ageing,
    check_acc_004_umask,
    # Permissions
    check_perm_001_core_account_files,
    check_perm_002_shadow_permissions,
    check_perm_003_sudoers,
    check_perm_004_world_writable,
    # SSH
    check_ssh_001_root_login,
    check_ssh_002_password_auth,
    check_ssh_003_timeouts,
    check_ssh_004_max_auth_tries,
    # Network
    check_net_001_listeners,
    check_net_002_ip_forward,
    check_net_003_icmp_redirects,
    # Firewall
    check_fw_001_firewall,
    # Logs
    check_log_001_auth_failures,
    check_log_002_auth_success
)

REGISTERED_CHECKS: List[Callable[[SystemContext], Finding]] = [
    # Category: System
    check_sys_001,
    check_sys_002_core_dumps,
    check_sys_003_aslr,
    # Category: Accounts
    check_acc_001_uid_zero,
    check_acc_002_empty_passwords,
    check_acc_003_password_ageing,
    check_acc_004_umask,
    # Category: Permissions
    check_perm_001_core_account_files,
    check_perm_002_shadow_permissions,
    check_perm_003_sudoers,
    check_perm_004_world_writable,
    # Category: SSH
    check_ssh_001_root_login,
    check_ssh_002_password_auth,
    check_ssh_003_timeouts,
    check_ssh_004_max_auth_tries,
    # Category: Network
    check_net_001_listeners,
    check_net_002_ip_forward,
    check_net_003_icmp_redirects,
    # Category: Firewall
    check_fw_001_firewall,
    # Category: Logs
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


def run_all_checks(ctx: SystemContext, category: Optional[str] = None) -> List[Finding]:
    """Execute registered checks sequentially (or filtered by category) and handle exceptions defensively."""
    findings: List[Finding] = []
    target_category = category.lower().strip() if category else None

    for check_fn in REGISTERED_CHECKS:
        try:
            finding = check_fn(ctx)
            if target_category and finding.category.lower() != target_category:
                continue
            findings.append(finding)
        except PermissionError as pe:
            findings.append(make_safe_warning(check_fn.__name__, f"Permission denied during check execution: {pe}"))
        except Exception as e:
            tb = traceback.format_exc()
            findings.append(make_safe_warning(check_fn.__name__, f"Unhandled error: {e}\n{tb}"))
    return findings

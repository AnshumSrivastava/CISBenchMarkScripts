import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from scanner.models import Finding, SystemContext
from scanner.permissions import get_file_metadata, is_permission_more_permissive
from scanner.logs import collect_recent_logs, parse_failed_logins, parse_successful_logins
from scanner.remediation import get_remediation_guidance

# Load registry metadata
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "checks.json"


def load_check_meta(check_id: str) -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                checks = json.load(f)
                for c in checks:
                    if c.get("id") == check_id:
                        return c
        except Exception:
            pass
    return {
        "id": check_id,
        "title": check_id,
        "category": "General",
        "severity": "MEDIUM",
        "expected": "Expected secure state",
        "remediation": "Review system configuration.",
        "references": []
    }


def parse_directive(text: str, directive: str) -> Optional[str]:
    """Pure parser: extracts effective value for directive in config text."""
    found = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == directive.lower():
            found = parts[1]
    return found


def parse_login_defs_directive(text: str, directive: str) -> Optional[int]:
    """Parse integer parameters from /etc/login.defs."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() == directive.upper():
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


# -------------------------------------------------------------
# CHECK IMPLEMENTATIONS
# -------------------------------------------------------------

def check_sys_001(ctx: SystemContext) -> Finding:
    """SYS-001: System identification & inventory."""
    meta = load_check_meta("SYS-001")
    evidence = (
        f"Platform: {ctx.platform}\n"
        f"Distribution: {ctx.distribution} (ID: {ctx.distribution_id}, Version: {ctx.distribution_version})\n"
        f"Kernel: {ctx.kernel}\n"
        f"Hostname: {ctx.hostname}\n"
        f"Init System: {ctx.init_system}\n"
        f"Logging: {ctx.logging_mechanism}\n"
        f"Scan User: {ctx.current_user} (root={ctx.is_root})"
    )
    return Finding(
        id="SYS-001",
        title=meta["title"],
        category=meta["category"],
        severity="INFO",
        status="PASS",
        description="Identified host operating system, kernel, distribution, and runtime subsystems.",
        evidence=evidence,
        expected=meta["expected"],
        remediation=meta["remediation"],
        references=meta["references"]
    )


def check_acc_001_uid_zero(ctx: SystemContext) -> Finding:
    """ACC-001: UID 0 accounts."""
    meta = load_check_meta("ACC-001")
    passwd_path = Path("/etc/passwd")
    if not passwd_path.exists():
        return Finding(
            id="ACC-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="/etc/passwd not found on this system.",
            evidence="/etc/passwd does not exist.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    try:
        content = passwd_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError as e:
        return Finding(
            id="ACC-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Permission denied while attempting to read /etc/passwd.",
            evidence=str(e),
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    uid_zero_users = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid_zero_users.append(parts[0])

    if len(uid_zero_users) == 1 and uid_zero_users[0] == "root":
        return Finding(
            id="ACC-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description="Only the 'root' account possesses UID 0.",
            evidence=f"Found UID 0 accounts: {', '.join(uid_zero_users)}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        status = "FAIL" if len(uid_zero_users) > 1 else "WARN"
        return Finding(
            id="ACC-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status=status,
            description="Multiple accounts or non-root account configured with UID 0.",
            evidence=f"Observed UID 0 accounts: {', '.join(uid_zero_users) if uid_zero_users else 'None'}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_acc_002_empty_passwords(ctx: SystemContext) -> Finding:
    """ACC-002: Empty password accounts in /etc/shadow."""
    meta = load_check_meta("ACC-002")
    shadow_path = Path("/etc/shadow")
    if not shadow_path.exists():
        return Finding(
            id="ACC-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="/etc/shadow does not exist on this system.",
            evidence="/etc/shadow not present.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    try:
        content = shadow_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return Finding(
            id="ACC-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Reading /etc/shadow requires elevated privileges (root/sudo).",
            evidence="Permission denied inspecting /etc/shadow. Run audit with root privileges to inspect password hashes.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    empty_users = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            username = parts[0]
            pwd_hash = parts[1]
            # Empty password string means no password set
            if pwd_hash == "":
                empty_users.append(username)

    if not empty_users:
        return Finding(
            id="ACC-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description="No accounts with empty password fields discovered in /etc/shadow.",
            evidence="All inspected account entries contain password hashes or lock symbols (!/*).",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        return Finding(
            id="ACC-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="Discovered accounts with completely empty password fields.",
            evidence=f"Accounts with empty password fields: {', '.join(empty_users)}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_acc_003_password_ageing(ctx: SystemContext) -> Finding:
    """ACC-003: Password ageing policy in /etc/login.defs."""
    meta = load_check_meta("ACC-003")
    defs_path = Path("/etc/login.defs")
    if not defs_path.exists():
        return Finding(
            id="ACC-003",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="/etc/login.defs not found on this system.",
            evidence="/etc/login.defs missing.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    try:
        content = defs_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError as e:
        return Finding(
            id="ACC-003",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Permission denied reading /etc/login.defs.",
            evidence=str(e),
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    max_days = parse_login_defs_directive(content, "PASS_MAX_DAYS")
    min_days = parse_login_defs_directive(content, "PASS_MIN_DAYS")
    warn_age = parse_login_defs_directive(content, "PASS_WARN_AGE")

    evidence = f"PASS_MAX_DAYS={max_days}, PASS_MIN_DAYS={min_days}, PASS_WARN_AGE={warn_age}"

    # Typical CIS standard: PASS_MAX_DAYS <= 90 (or <= 365 in lax), PASS_MIN_DAYS >= 1
    failures = []
    if max_days is None:
        failures.append("PASS_MAX_DAYS undefined")
    elif max_days > 90 or max_days <= 0:
        failures.append(f"PASS_MAX_DAYS ({max_days}) exceeds 90 days recommended maximum")

    if min_days is None:
        failures.append("PASS_MIN_DAYS undefined")
    elif min_days < 1:
        failures.append(f"PASS_MIN_DAYS ({min_days}) should be at least 1 day")

    if not failures:
        return Finding(
            id="ACC-003",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description="Password ageing parameters in /etc/login.defs conform to recommended limits.",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        return Finding(
            id="ACC-003",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="Password ageing configuration does not meet security baselines.",
            evidence=f"{evidence}. Issues: {'; '.join(failures)}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_perm_001_core_account_files(ctx: SystemContext) -> Finding:
    """PERM-001: Core account file permissions (/etc/passwd, /etc/group)."""
    meta = load_check_meta("PERM-001")
    targets = ["/etc/passwd", "/etc/group"]
    issues = []
    details = []

    for t in targets:
        info = get_file_metadata(t)
        if info["status"] == "MISSING":
            issues.append(f"{t} is missing")
        elif info["status"] == "ERROR":
            details.append(f"{t}: {info['error']}")
        else:
            details.append(f"{t} (mode: {info['mode_str']} / {info['mode_octal']}, owner: {info['owner']}:{info['group']})")
            # Must be owned by root, group root (or 0)
            if info["uid"] != 0:
                issues.append(f"{t} is not owned by root (uid {info['uid']})")
            # Must not be world-writable
            if info.get("is_world_writable"):
                issues.append(f"{t} is world-writable ({info['mode_octal']})")
            # Permission check: 0644 max allowed (0o644 = 420)
            st_mode_val = int(info["mode_octal"], 8) & 0o777
            if is_permission_more_permissive(st_mode_val, 0o644):
                issues.append(f"{t} permissions ({info['mode_octal']}) more permissive than 0644")

    evidence_text = "\n".join(details)
    if issues:
        evidence_text += "\nViolations: " + "; ".join(issues)
        return Finding(
            id="PERM-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="Core account files have inappropriate permissions or ownership.",
            evidence=evidence_text,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    return Finding(
        id="PERM-001",
        title=meta["title"],
        category=meta["category"],
        severity=meta["severity"],
        status="PASS",
        description="Core account files (/etc/passwd, /etc/group) have secure root ownership and restricted permissions.",
        evidence=evidence_text,
        expected=meta["expected"],
        remediation=meta["remediation"],
        references=meta["references"]
    )


def check_perm_002_shadow_permissions(ctx: SystemContext) -> Finding:
    """PERM-002: Shadow file permissions (/etc/shadow)."""
    meta = load_check_meta("PERM-002")
    shadow_path = "/etc/shadow"
    info = get_file_metadata(shadow_path)

    if info["status"] == "MISSING":
        return Finding(
            id="PERM-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="/etc/shadow does not exist on this machine.",
            evidence="File /etc/shadow not found.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    if info["status"] == "ERROR":
        return Finding(
            id="PERM-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Unable to inspect /etc/shadow permissions due to system error or access limits.",
            evidence=info["error"],
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    evidence_text = f"{shadow_path} mode: {info['mode_str']} ({info['mode_octal']}), owner: {info['owner']}:{info['group']}"
    issues = []
    if info["uid"] != 0:
        issues.append(f"Owner is {info['owner']} (UID {info['uid']}), expected root (UID 0)")

    # Shadow group is acceptable on Debian/Ubuntu/Arch/etc., gid 0 or 'shadow'
    if info["group"] not in ["root", "shadow"]:
        issues.append(f"Group is {info['group']}, expected root or shadow")

    if info.get("is_world_writable"):
        issues.append("File is world-writable")

    # Mode should not exceed 0640 (0o640 = 416). (0600 or 0640 allowed)
    st_mode_val = int(info["mode_octal"], 8) & 0o777
    if is_permission_more_permissive(st_mode_val, 0o640):
        issues.append(f"Permissions {info['mode_octal']} are more permissive than 0640")

    if issues:
        return Finding(
            id="PERM-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="/etc/shadow permissions violate security baseline.",
            evidence=f"{evidence_text}. Issues: {'; '.join(issues)}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    return Finding(
        id="PERM-002",
        title=meta["title"],
        category=meta["category"],
        severity=meta["severity"],
        status="PASS",
        description="/etc/shadow has secure permissions and ownership.",
        evidence=evidence_text,
        expected=meta["expected"],
        remediation=meta["remediation"],
        references=meta["references"]
    )


def read_effective_sshd_config(ctx: SystemContext) -> Dict[str, Any]:
    """
    Read sshd configuration either by querying sshd -T (runtime effective config)
    or by reading sshd_config files directly.
    """
    if ctx.available_tools.get("sshd"):
        try:
            res = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip():
                return {"source": "sshd -T (effective runtime)", "content": res.stdout}
        except Exception:
            pass

    if ctx.sshd_config_path:
        p = Path(ctx.sshd_config_path)
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            # Also include drop-in files from sshd_config.d if present
            dropin_dir = p.parent / "sshd_config.d"
            if dropin_dir.is_dir():
                for dropin in sorted(dropin_dir.glob("*.conf")):
                    try:
                        content += "\n" + dropin.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        pass
            return {"source": str(p), "content": content}
        except PermissionError as pe:
            return {"source": str(p), "content": None, "error": f"Permission denied: {pe}"}
        except Exception as e:
            return {"source": str(p), "content": None, "error": str(e)}

    return {"source": "none", "content": None, "error": "OpenSSH server configuration file not found"}


def check_ssh_001_root_login(ctx: SystemContext) -> Finding:
    """SSH-001: SSH PermitRootLogin setting."""
    meta = load_check_meta("SSH-001")
    config_info = read_effective_sshd_config(ctx)

    if config_info.get("content") is None:
        if config_info.get("error") and "Permission denied" in config_info["error"]:
            return Finding(
                id="SSH-001",
                title=meta["title"],
                category=meta["category"],
                severity=meta["severity"],
                status="WARN",
                description="Unable to read SSH daemon configuration due to permissions.",
                evidence=config_info["error"],
                expected=meta["expected"],
                remediation=meta["remediation"],
                references=meta["references"]
            )
        return Finding(
            id="SSH-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="OpenSSH daemon not detected on this system.",
            evidence="No sshd executable or sshd_config file found.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    val = parse_directive(config_info["content"], "PermitRootLogin")
    evidence = f"Source: {config_info['source']}\nEffective PermitRootLogin: {val}"

    # Acceptable secure values: 'no', 'prohibit-password', 'without-password'
    # Insecure: 'yes'
    # If not specified in file, OpenSSH default in modern versions is 'prohibit-password'
    if val:
        val_clean = val.lower().strip()
        if val_clean in ["no", "prohibit-password", "without-password"]:
            return Finding(
                id="SSH-001",
                title=meta["title"],
                category=meta["category"],
                severity=meta["severity"],
                status="PASS",
                description=f"Direct SSH root login is restricted ({val}).",
                evidence=evidence,
                expected=meta["expected"],
                remediation=meta["remediation"],
                references=meta["references"]
            )
        else:
            return Finding(
                id="SSH-001",
                title=meta["title"],
                category=meta["category"],
                severity=meta["severity"],
                status="FAIL",
                description="SSH allows direct root login.",
                evidence=evidence,
                expected=meta["expected"],
                remediation=meta["remediation"],
                references=meta["references"]
            )
    else:
        # Default fallback in OpenSSH 7.0+ is prohibit-password, but explicit declaration is required by CIS
        return Finding(
            id="SSH-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="PermitRootLogin is not explicitly configured in sshd_config.",
            evidence=f"{evidence} (Defaulting to system-level daemon baseline)",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_ssh_002_password_auth(ctx: SystemContext) -> Finding:
    """SSH-002: SSH PasswordAuthentication setting."""
    meta = load_check_meta("SSH-002")
    config_info = read_effective_sshd_config(ctx)

    if config_info.get("content") is None:
        if config_info.get("error") and "Permission denied" in config_info["error"]:
            return Finding(
                id="SSH-002",
                title=meta["title"],
                category=meta["category"],
                severity=meta["severity"],
                status="WARN",
                description="Unable to read SSH daemon configuration due to permissions.",
                evidence=config_info["error"],
                expected=meta["expected"],
                remediation=meta["remediation"],
                references=meta["references"]
            )
        return Finding(
            id="SSH-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="NOT_APPLICABLE",
            description="OpenSSH daemon not detected on this system.",
            evidence="No sshd executable or sshd_config file found.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    val = parse_directive(config_info["content"], "PasswordAuthentication")
    evidence = f"Source: {config_info['source']}\nEffective PasswordAuthentication: {val}"

    if val and val.lower().strip() == "no":
        return Finding(
            id="SSH-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description="SSH password authentication is disabled (public key enforced).",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    elif val and val.lower().strip() == "yes":
        return Finding(
            id="SSH-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="SSH allows password authentication.",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        # Default in OpenSSH is 'yes' if unspecified
        return Finding(
            id="SSH-002",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="PasswordAuthentication is not explicitly set to 'no' in SSH config (OpenSSH defaults to yes).",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_net_001_listeners(ctx: SystemContext) -> Finding:
    """NET-001: Inspect listening network ports & services."""
    meta = load_check_meta("NET-001")
    tool = None
    output = None

    if ctx.available_tools.get("ss"):
        tool = "ss"
        try:
            res = subprocess.run(["ss", "-tulpen"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                output = res.stdout.strip()
        except Exception:
            pass

    if not output and ctx.available_tools.get("netstat"):
        tool = "netstat"
        try:
            res = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                output = res.stdout.strip()
        except Exception:
            pass

    if not output:
        return Finding(
            id="NET-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Neither 'ss' nor 'netstat' commands are available to inspect network listeners.",
            evidence="Tools ss and netstat unavailable or execution failed.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    # Count listening ports
    lines = [l for l in output.splitlines() if l.strip()]
    header = lines[0] if lines else ""
    listeners = lines[1:] if len(lines) > 1 else []

    # Filter out pure loopback listeners vs external listeners
    external_listeners = []
    for l in listeners:
        if not ("127.0.0.1:" in l or "[::1]:" in l or "127.0.0.53" in l):
            external_listeners.append(l)

    evidence_summary = (
        f"Collector: {tool}\n"
        f"Total Listening Sockets: {len(listeners)}\n"
        f"Non-Loopback/External Sockets: {len(external_listeners)}\n\n"
        f"Raw Listeners (first 10):\n" + "\n".join(lines[:11])
    )

    return Finding(
        id="NET-001",
        title=meta["title"],
        category=meta["category"],
        severity=meta["severity"],
        status="PASS" if len(listeners) > 0 else "WARN",
        description=f"Collected {len(listeners)} active listening socket(s). {len(external_listeners)} socket(s) exposed to non-loopback interfaces.",
        evidence=evidence_summary,
        expected=meta["expected"],
        remediation=meta["remediation"],
        references=meta["references"]
    )


def check_fw_001_firewall(ctx: SystemContext) -> Finding:
    """FW-001: Detect firewall tool and active enforcement state."""
    meta = load_check_meta("FW-001")
    tools = ctx.available_tools
    detected_fw = []
    active_fw = []
    evidence_lines = []

    # 1. UFW check
    if tools.get("ufw"):
        detected_fw.append("ufw")
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
            out = res.stdout.strip()
            evidence_lines.append(f"ufw status: {out[:120]}")
            if "status: active" in out.lower():
                active_fw.append("ufw (active)")
        except Exception as e:
            evidence_lines.append(f"ufw query error: {e}")

    # 2. Firewalld check
    if tools.get("firewall-cmd"):
        detected_fw.append("firewall-cmd")
        try:
            res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=3)
            out = res.stdout.strip()
            evidence_lines.append(f"firewall-cmd --state: {out}")
            if "running" in out.lower():
                active_fw.append("firewalld (running)")
        except Exception as e:
            evidence_lines.append(f"firewalld query error: {e}")

    # 3. nftables check
    if tools.get("nft"):
        detected_fw.append("nft")
        try:
            res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=3)
            out = res.stdout.strip()
            # If ruleset has tables/chains defined and non-empty
            if res.returncode == 0 and ("table" in out or "chain" in out):
                active_fw.append("nftables (active ruleset)")
                evidence_lines.append(f"nft: active ruleset present ({len(out.splitlines())} lines)")
            elif res.returncode == 0:
                evidence_lines.append("nft: ruleset is empty")
            else:
                evidence_lines.append(f"nft query returned code {res.returncode}: {res.stderr.strip()[:100]}")
        except Exception as e:
            evidence_lines.append(f"nft query error: {e}")

    # 4. iptables check
    if tools.get("iptables") and not active_fw:
        detected_fw.append("iptables")
        try:
            res = subprocess.run(["iptables", "-S"], capture_output=True, text=True, timeout=3)
            out = res.stdout.strip()
            rules = [r for r in out.splitlines() if not r.startswith("-P")]
            if rules:
                active_fw.append(f"iptables ({len(rules)} custom rules)")
            evidence_lines.append(f"iptables rules: {len(rules)} non-default rules")
        except Exception as e:
            evidence_lines.append(f"iptables query error: {e}")

    if not detected_fw:
        return Finding(
            id="FW-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="FAIL",
            description="No standard firewall management tools (ufw, firewalld, nft, iptables) are installed on this machine.",
            evidence="No firewall binaries identified in system PATH.",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    evidence_text = f"Installed tools: {', '.join(detected_fw)}\n" + "\n".join(evidence_lines)

    if active_fw:
        return Finding(
            id="FW-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description=f"Active firewall enforcement confirmed via {', '.join(active_fw)}.",
            evidence=evidence_text,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        return Finding(
            id="FW-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Firewall tool(s) detected, but no actively enforcing ruleset was confirmed (or permission was insufficient).",
            evidence=evidence_text,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_log_001_auth_failures(ctx: SystemContext) -> Finding:
    """LOG-001: Inspect authentication logs for failed login attempts."""
    meta = load_check_meta("LOG-001")
    log_data = collect_recent_logs(max_lines=300)

    if log_data.get("error"):
        return Finding(
            id="LOG-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description="Authentication logs could not be read or are unavailable.",
            evidence=f"Source: {log_data['source']}. Error: {log_data['error']}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    failures = parse_failed_logins(log_data["lines"])
    evidence = (
        f"Log Source: {log_data['source']}\n"
        f"Analyzed Lines: {len(log_data['lines'])}\n"
        f"Failed Login Events Detected: {len(failures)}\n"
    )
    if failures:
        evidence += "\nRecent Failed Authentication Entries:\n" + "\n".join(failures[:8])

    # Having failed attempts is normal in public or testing systems, but warrants WARN or PASS with evidence
    if len(failures) > 20:
        return Finding(
            id="LOG-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="WARN",
            description=f"High volume of recent authentication failures detected ({len(failures)} events).",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )
    else:
        return Finding(
            id="LOG-001",
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            status="PASS",
            description=f"Authentication logs inspected successfully. {len(failures)} failed login event(s) observed.",
            evidence=evidence,
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )


def check_log_002_auth_success(ctx: SystemContext) -> Finding:
    """LOG-002: Inspect authentication logs for successful logins."""
    meta = load_check_meta("LOG-002")
    log_data = collect_recent_logs(max_lines=300)

    if log_data.get("error"):
        return Finding(
            id="LOG-002",
            title=meta["title"],
            category=meta["category"],
            severity="INFO",
            status="WARN",
            description="Authentication logs could not be read or are unavailable.",
            evidence=f"Source: {log_data['source']}. Error: {log_data['error']}",
            expected=meta["expected"],
            remediation=meta["remediation"],
            references=meta["references"]
        )

    successes = parse_successful_logins(log_data["lines"])
    evidence = (
        f"Log Source: {log_data['source']}\n"
        f"Analyzed Lines: {len(log_data['lines'])}\n"
        f"Successful Login Events Detected: {len(successes)}\n"
    )
    if successes:
        evidence += "\nRecent Successful Authentication Entries:\n" + "\n".join(successes[:8])

    return Finding(
        id="LOG-002",
        title=meta["title"],
        category=meta["category"],
        severity="INFO",
        status="PASS",
        description=f"Authentication log session audit captured {len(successes)} successful login/session event(s).",
        evidence=evidence,
        expected=meta["expected"],
        remediation=meta["remediation"],
        references=meta["references"]
    )

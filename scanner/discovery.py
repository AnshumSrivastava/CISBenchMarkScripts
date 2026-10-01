import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple
from scanner.models import SystemContext


def parse_os_release(file_content: str) -> Dict[str, str]:
    """Parse /etc/os-release key=value format safely."""
    info: Dict[str, str] = {}
    for line in file_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            info[k] = v
    return info


def detect_distribution() -> Tuple[str, str, str]:
    """Detect distribution name, version, and id."""
    candidates = [
        Path("/etc/os-release"),
        Path("/usr/lib/os-release")
    ]
    for p in candidates:
        if p.exists():
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                info = parse_os_release(content)
                name = info.get("PRETTY_NAME") or info.get("NAME") or "Unknown Linux"
                version = info.get("VERSION_ID") or info.get("BUILD_ID") or info.get("VERSION") or "unknown"
                dist_id = info.get("ID") or "linux"
                return name, version, dist_id
            except Exception:
                pass
    return "Generic Linux", "unknown", "linux"


def detect_init_system() -> str:
    """Detect init system (systemd, openrc, runit, sysvinit, etc.)."""
    try:
        proc1 = Path("/proc/1/comm")
        if proc1.exists():
            comm = proc1.read_text(encoding="utf-8", errors="replace").strip()
            if comm:
                return comm
    except Exception:
        pass

    try:
        res = subprocess.run(["ps", "-p", "1", "-o", "comm="], capture_output=True, text=True, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    return "unknown"


def detect_logging() -> str:
    """Detect available logging mechanism (journald, syslog/auth.log, /var/log/secure)."""
    if shutil.which("journalctl"):
        return "journald"
    if Path("/var/log/auth.log").exists():
        return "syslog (/var/log/auth.log)"
    if Path("/var/log/secure").exists():
        return "syslog (/var/log/secure)"
    if Path("/var/log/messages").exists():
        return "syslog (/var/log/messages)"
    return "unknown/none"


def detect_auth_log_path() -> Optional[str]:
    """Return traditional auth log path if present."""
    candidates = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log",
        "/var/log/messages"
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def detect_sshd_config() -> Optional[str]:
    """Find effective main sshd_config path if present."""
    candidates = [
        "/etc/ssh/sshd_config",
        "/etc/sshd_config",
        "/usr/local/etc/ssh/sshd_config"
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def discover_tools() -> Dict[str, bool]:
    """Check existence of security-relevant system tools."""
    tools = [
        "systemctl", "journalctl", "ss", "netstat",
        "ufw", "firewall-cmd", "nft", "iptables",
        "sshd", "ssh", "awk", "grep", "sed"
    ]
    return {tool: bool(shutil.which(tool)) for tool in tools}


def discover_system() -> SystemContext:
    """Gather all discovery information into SystemContext."""
    dist_name, dist_ver, dist_id = detect_distribution()
    kernel = platform.release() or "unknown"
    hostname = socket.gethostname()
    current_user = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    init_sys = detect_init_system()
    logging_mech = detect_logging()
    tools = discover_tools()
    auth_path = detect_auth_log_path()
    sshd_path = detect_sshd_config()

    return SystemContext(
        platform=platform.system(),
        distribution=dist_name,
        distribution_version=dist_ver,
        distribution_id=dist_id,
        kernel=kernel,
        hostname=hostname,
        current_user=current_user,
        is_root=is_root,
        init_system=init_sys,
        logging_mechanism=logging_mech,
        available_tools=tools,
        auth_log_path=auth_path,
        sshd_config_path=sshd_path,
    )

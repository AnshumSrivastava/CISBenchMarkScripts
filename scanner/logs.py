import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

FAILED_AUTH_PATTERNS = [
    re.compile(r"failed password for (?:invalid user )?(\S+) from (\S+)", re.IGNORECASE),
    re.compile(r"authentication failure;.*user=(\S+)", re.IGNORECASE),
    re.compile(r"invalid user (\S+) from (\S+)", re.IGNORECASE),
    re.compile(r"pam_unix\(.*:auth\): authentication failure", re.IGNORECASE),
    re.compile(r"connection closed by (?:authenticating user )?(\S+)", re.IGNORECASE)
]

SUCCESS_AUTH_PATTERNS = [
    re.compile(r"accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+)", re.IGNORECASE),
    re.compile(r"session opened for user (\S+)", re.IGNORECASE),
    re.compile(r"successful login for (\S+)", re.IGNORECASE),
    re.compile(r"pam_unix\(.*:session\): session opened for user (\S+)", re.IGNORECASE)
]


def collect_recent_logs(max_lines: int = 500) -> Dict[str, Any]:
    """
    Collect recent auth/security logs from journald or traditional log files.
    Returns { 'source': str, 'lines': List[str], 'error': Optional[str] }
    """
    # 1. Try journalctl if available
    if shutil.which("journalctl"):
        try:
            # Query last 24 hours of auth/login/sshd activity
            cmd = ["journalctl", "--since", "24 hours ago", "--no-pager", "-n", str(max_lines)]
            # Can also specifically query units if needed, but general output is good
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.splitlines()
                return {
                    "source": "journald",
                    "lines": lines,
                    "error": None
                }
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # 2. Try file based logs
    log_candidates = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages"
    ]
    for p in log_candidates:
        path = Path(p)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    # Read last N lines
                    all_lines = f.readlines()
                    selected = [line.rstrip("\r\n") for line in all_lines[-max_lines:]]
                    return {
                        "source": p,
                        "lines": selected,
                        "error": None
                    }
            except PermissionError as pe:
                return {
                    "source": p,
                    "lines": [],
                    "error": f"Permission denied reading {p}: {pe}"
                }
            except Exception as e:
                return {
                    "source": p,
                    "lines": [],
                    "error": str(e)
                }

    return {
        "source": "none",
        "lines": [],
        "error": "No accessible auth log source found (journalctl unavailable or restricted, auth files missing or unreadable)"
    }


def parse_failed_logins(log_lines: List[str]) -> List[str]:
    """Filter and identify failed authentication entries."""
    matches = []
    for line in log_lines:
        for pat in FAILED_AUTH_PATTERNS:
            if pat.search(line):
                matches.append(line.strip())
                break
    return matches


def parse_successful_logins(log_lines: List[str]) -> List[str]:
    """Filter and identify successful authentication entries."""
    matches = []
    for line in log_lines:
        for pat in SUCCESS_AUTH_PATTERNS:
            if pat.search(line):
                matches.append(line.strip())
                break
    return matches

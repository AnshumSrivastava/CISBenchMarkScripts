# Automated Log-Monitoring & Linux Hardening Toolkit

A distribution-agnostic Linux security auditing, compliance inspection, and log monitoring toolkit written from scratch in Bash & Python.

Designed to be dropped onto any Linux server (e.g. Debian, Ubuntu, Arch, Fedora, RHEL, Alpine, Rocky, CentOS) without assuming pre-installed packages or specific distributions.

---

## 🏗️ Architecture & Philosophy

The toolkit operates strictly **read-only by default**. Remediation guidance is provided separately so that security audits never alter active machine states or inadvertently lock administrators out of SSH or firewall controls.

```
Existing Linux Machine
        │
        ▼
Environment Discovery
  ├── Distribution (/etc/os-release)
  ├── Kernel (uname -a)
  ├── Init System (/proc/1/comm or ps)
  ├── Available Tools (which check)
  └── Logging System (journald / syslog)
        │
        ▼
Security Collection Engine
  ├── Accounts & UID 0
  ├── Core Account File Permissions
  ├── Shadow File Permissions
  ├── SSH Daemon Configuration
  ├── Network Sockets & Listeners
  ├── Firewall Enforcement Status
  └── Authentication Log Events
        │
        ▼
Normalized Findings Model
  PASS / FAIL / WARN / NOT_APPLICABLE
        │
  ┌─────┴────────────────┐
  ▼                      ▼
JSON Report          HTML Report
(Machine-Readable)   (Visual Dashboard)
                         │
                         ▼
             Safe Remediation Guidance
```

---

## 📋 Implemented Checks

| Check ID | Area | Check Title | Severity | Default Target Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **SYS-001** | System | System Identification & Inventory | INFO | Platform, OS, distribution ID, kernel & init |
| **ACC-001** | Accounts | Ensure UID 0 is Assigned Only to Root | HIGH | Only `root` has UID 0 in `/etc/passwd` |
| **ACC-002** | Accounts | Ensure No Accounts Have Empty Passwords | HIGH | No account in `/etc/shadow` has empty password hash |
| **ACC-003** | Accounts | Verify Password Ageing Configuration | MEDIUM | `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1` in `/etc/login.defs` |
| **PERM-001**| Permissions | Core Account Files Permissions | MEDIUM | `/etc/passwd`, `/etc/group` mode `<= 0644`, owner `root:root` |
| **PERM-002**| Permissions | Shadow File Permissions | HIGH | `/etc/shadow` mode `<= 0640` or `0600`, root/shadow owned |
| **SSH-001** | SSH | SSH Direct Root Login Configuration | HIGH | `PermitRootLogin no` or `prohibit-password` |
| **SSH-002** | SSH | SSH Password Authentication Configuration| MEDIUM | `PasswordAuthentication no` (keys preferred) |
| **NET-001** | Network | Inspect Listening Network Sockets | MEDIUM | Non-loopback listening sockets cataloged via `ss` or `netstat` |
| **FW-001**  | Firewall | Detect Firewall Tool and Active State | HIGH | Active enforcement verified via `ufw`, `firewalld`, or `nft` |
| **LOG-001** | Logs | Authentication Failures Monitoring | MEDIUM | Recent failed logins parsed from journald / `/var/log` |
| **LOG-002** | Logs | Successful Authentication Audit | INFO | Recent user logins & sessions cataloged |

---

## 🚀 Quickstart & Usage

### 1. Requirements
- Python 3.8+
- Standard Linux utilities (any POSIX shell, optional: `ss`, `journalctl`, `ufw`, `nft`, etc.)

Install testing dependencies (optional):
```bash
python3 -m pip install -r requirements.txt
```

### 2. Environment Discovery
Identify what tools and subsystems exist on the host machine:
```bash
# Via Python:
python3 -m scanner.main discover

# Or via pure Bash:
./scripts/collect_system.sh
```

### 3. Run Security & Log Audit
Execute all 12 controls and generate JSON and HTML reports:
```bash
python3 -m scanner.main audit
```
Output files will be generated in `output/report.json` and `output/report.html`.

You can also specify custom output targets:
```bash
python3 -m scanner.main audit --json-output custom.json --html-output custom.html
```

### 4. Regenerate HTML Report from Existing JSON
```bash
python3 -m scanner.main report output/report.json --output-html output/report.html
```

### 5. Inspect Safe Remediation Guidance
View non-destructive, step-by-step remediation procedures and warnings:
```bash
python3 -m scanner.main remediation --check SSH-001
python3 -m scanner.main remediation --check ACC-002
python3 -m scanner.main remediation --check PERM-001
```

---

## 🧪 Running Unit Tests

Run test suites for parsers, permissions evaluation, and log regular expressions:
```bash
python3 -m pytest -v
```

---

## 🛡️ Safe Remediation Principles

1. **Read-Only by Default**: The scanner never modifies configuration files or restarts daemons on its own.
2. **Lockout Prevention**: Warnings are prominently displayed for SSH and Firewall modifications.
3. **Safe Verification**: Every remediation step includes a syntax-check or non-destructive verification command (e.g. `sshd -t`, `ufw status`).

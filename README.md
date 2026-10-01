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

## 📋 Implemented Checks (Organized by Category)

| Check ID | Category | Check Title | Severity | Default Target Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **SYS-001** | System | System Identification & Inventory | INFO | Platform, OS, distribution ID, kernel & init |
| **SYS-002** | System | Kernel Core Dumps Restriction | MEDIUM | `fs.suid_dumpable = 0` (prevent memory leakage) |
| **SYS-003** | System | ASLR Randomization Enabled | HIGH | `kernel.randomize_va_space = 2` (full ASLR) |
| **ACC-001** | Accounts | Ensure UID 0 is Assigned Only to Root | HIGH | Only `root` has UID 0 in `/etc/passwd` |
| **ACC-002** | Accounts | Ensure No Accounts Have Empty Passwords | HIGH | No account in `/etc/shadow` has empty password hash |
| **ACC-003** | Accounts | Verify Password Ageing Configuration | MEDIUM | `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1` in `/etc/login.defs` |
| **ACC-004** | Accounts | Default User Umask Configuration | MEDIUM | `UMASK 027` or more restrictive in `/etc/login.defs` |
| **PERM-001**| Permissions | Core Account Files Permissions | MEDIUM | `/etc/passwd`, `/etc/group` mode `<= 0644`, owner `root:root` |
| **PERM-002**| Permissions | Shadow File Permissions | HIGH | `/etc/shadow` mode `<= 0640` or `0600`, root/shadow owned |
| **PERM-003**| Permissions | Sudoers Configuration Permissions | HIGH | `/etc/sudoers` mode `0440` or `0400`, owned by `root:root` |
| **PERM-004**| Permissions | World-Writable Files Inspection | HIGH | No world-writable files in `/etc` |
| **SSH-001** | SSH | SSH Direct Root Login Configuration | HIGH | `PermitRootLogin no` or `prohibit-password` |
| **SSH-002** | SSH | SSH Password Authentication Configuration| MEDIUM | `PasswordAuthentication no` (keys preferred) |
| **SSH-003** | SSH | SSH Session Idle Timeout & KeepAlive | LOW | `ClientAliveInterval 300` and `ClientAliveCountMax <= 3` |
| **SSH-004** | SSH | SSH Maximum Authentication Tries | MEDIUM | `MaxAuthTries <= 4` |
| **NET-001** | Network | Inspect Listening Network Sockets | MEDIUM | Non-loopback listening sockets cataloged via `ss` or `netstat` |
| **NET-002** | Network | IPv4 Packet Forwarding Disabled | MEDIUM | `net.ipv4.ip_forward = 0` (unless dedicated router) |
| **NET-003** | Network | ICMP Redirect Acceptance Disabled | MEDIUM | `net.ipv4.conf.all.accept_redirects = 0` |
| **FW-001**  | Firewall | Detect Firewall Tool and Active State | HIGH | Active enforcement verified via `ufw`, `firewalld`, or `nft` |
| **LOG-001** | Logs | Authentication Failures Monitoring | MEDIUM | Recent failed logins parsed from journald / `/var/log` |
| **LOG-002** | Logs | Successful Authentication Audit | INFO | Recent user logins & sessions cataloged |

---

## 📂 Category-Specific Audit Scripts

In addition to the unified Python engine, standalone POSIX Bash audit scripts are organized by category under `scripts/`. These scripts require **no external Python dependencies** and can be run directly on any POSIX-compliant Linux system.

```
scripts/
├── collect_system.sh               # Comprehensive host discovery & tool availability
├── system/
│   └── audit_system.sh            # OS, kernel, ASLR, and coredump inspector
├── accounts/
│   └── audit_accounts.sh          # UID 0, empty passwords, ageing, and umask
├── permissions/
│   └── audit_permissions.sh       # /etc/passwd, shadow, sudoers, world-writable
├── ssh/
│   └── audit_ssh.sh               # Root login, password auth, timeouts, max auth tries
├── network/
│   └── audit_network.sh           # Listening ports, IP forward, ICMP redirects
├── firewall/
│   └── audit_firewall.sh          # UFW, Firewalld, NFTables, IPTables enforcement
└── logs/
    └── audit_logs.sh              # Failed attempts, accepted sessions, logins
```

---

### Detailed Breakdown of Each Script

#### 1. `scripts/collect_system.sh` (Root Discovery Script)
- **Purpose**: Collects a rapid diagnostic profile of the target system to understand its distribution family, kernel version, init manager, and installed utilities.
- **What it does**:
  - Parses `/etc/os-release` and `/usr/lib/os-release` for distribution name, ID, and release version.
  - Runs `uname -a` to print kernel architecture and release flags.
  - Queries `id` to determine current execution privileges (root vs. non-root).
  - Inspects `/proc/1/comm` or `ps -p 1` to identify the active init manager (`systemd`, `init`, `openrc`).
  - Probes for presence of 12 core networking and security utilities (`systemctl`, `journalctl`, `ss`, `ufw`, `firewall-cmd`, `nft`, `iptables`, `awk`, `grep`, `sed`, `sshd`).
- **Usage**:
  ```bash
  ./scripts/collect_system.sh
  ```

#### 2. `scripts/system/audit_system.sh` (System & Kernel Audit)
- **Purpose**: Verifies low-level kernel security protections and host identification parameters.
- **What it does**:
  - Displays standard distribution identification attributes (`NAME`, `VERSION`, `ID`).
  - Checks **Core Dump Restriction**: Queries `fs.suid_dumpable` via `sysctl` and `/proc/sys/fs/suid_dumpable`. Prevents memory content disclosure when setuid binaries crash.
  - Checks **ASLR (Address Space Layout Randomization)**: Queries `kernel.randomize_va_space` (expects `2` for full heap, stack, and mmap randomization).
- **Usage**:
  ```bash
  ./scripts/system/audit_system.sh
  ```

#### 3. `scripts/accounts/audit_accounts.sh` (User Accounts Security)
- **Purpose**: Audits local account definitions to ensure superuser privileges and password policies meet baseline standards.
- **What it does**:
  - **UID 0 Verification**: Uses `awk` to scan `/etc/passwd` field 3 for any non-root account granted UID `0` (super-user privileges).
  - **Empty Password Audit**: If run with sufficient read permissions, checks field 2 of `/etc/shadow` to ensure no active accounts lack a password hash.
  - **Password Ageing Policy**: Checks `/etc/login.defs` for `PASS_MAX_DAYS` ($\le 90$), `PASS_MIN_DAYS` ($\ge 1$), and `PASS_WARN_AGE` ($\ge 7$).
  - **Default User UMASK**: Inspects `/etc/login.defs` for `UMASK` (verifies standard `027` or more restrictive policy).
- **Usage**:
  ```bash
  ./scripts/accounts/audit_accounts.sh
  # Run with sudo to permit /etc/shadow inspection:
  sudo ./scripts/accounts/audit_accounts.sh
  ```

#### 4. `scripts/permissions/audit_permissions.sh` (File Ownership & Permissions)
- **Purpose**: Ensures system configuration and credential files cannot be modified or read by unauthorized users.
- **What it does**:
  - Inspects permissions and ownership of core account files (`/etc/passwd` and `/etc/group` should be mode $\le 0644$ and owned by `root:root`).
  - Inspects `/etc/shadow` permissions (mode $\le 0640$, owned by `root:root` or `root:shadow`).
  - Inspects `/etc/sudoers` and all drop-in files in `/etc/sudoers.d/` (mode `0440` or `0400`, owned by `root:root`).
  - Scans `/etc/` using `find -perm -0002` to detect any rogue world-writable regular files.
- **Usage**:
  ```bash
  ./scripts/permissions/audit_permissions.sh
  ```

#### 5. `scripts/ssh/audit_ssh.sh` (SSH Daemon Security)
- **Purpose**: Audits the OpenSSH server configuration against CIS hardening guidelines to prevent remote brute-force attacks and unauthorized root access.
- **What it does**:
  - If `sshd` binary is present, queries live runtime effective configuration using `sshd -T`.
  - Scans `/etc/ssh/sshd_config` and modular files in `/etc/ssh/sshd_config.d/*.conf`.
  - Checks `PermitRootLogin` (prohibits direct root login over SSH).
  - Checks `PasswordAuthentication` (verifies key-based authentication enforcement).
  - Checks `ClientAliveInterval` and `ClientAliveCountMax` (validates idle session disconnect).
  - Checks `MaxAuthTries` (verifies maximum brute-force tries per connection $\le 4$).
- **Usage**:
  ```bash
  ./scripts/ssh/audit_ssh.sh
  ```

#### 6. `scripts/network/audit_network.sh` (Sockets & Network Stack)
- **Purpose**: Audits external exposure of listening sockets and verifies kernel network packet handling.
- **What it does**:
  - Catalogs all active TCP and UDP listening sockets and associated process names using `ss -tulpen` (falling back to `netstat`).
  - Checks **IPv4 Forwarding**: Evaluates `net.ipv4.ip_forward` via `sysctl`. Verifies forwarding is disabled unless the server is intentionally designated as a router or container bridge host.
  - Checks **ICMP Redirect Acceptance**: Evaluates `net.ipv4.conf.all.accept_redirects` and `default.accept_redirects` to guard against route manipulation attacks.
- **Usage**:
  ```bash
  ./scripts/network/audit_network.sh
  ```

#### 7. `scripts/firewall/audit_firewall.sh` (Firewall Status)
- **Purpose**: Detects which host-based firewall subsystem is installed and verifies active enforcement.
- **What it does**:
  - Probes for **UFW** (`ufw status`) and checks if status is `active`.
  - Probes for **Firewalld** (`firewall-cmd --state`) and checks if status is `running`.
  - Probes for **NFTables** (`nft list ruleset`) and checks for loaded filtering chains.
  - Probes for legacy **IPTables** (`iptables -L -n -v`).
- **Usage**:
  ```bash
  ./scripts/firewall/audit_firewall.sh
  # Run with sudo for full ruleset inspection:
  sudo ./scripts/firewall/audit_firewall.sh
  ```

#### 8. `scripts/logs/audit_logs.sh` (Authentication Log Monitor)
- **Purpose**: Surfaces recent authentication security events to detect brute-force attacks or verify authorized sessions.
- **What it does**:
  - Dynamically checks `journald` (`journalctl --since "24 hours ago"`) or traditional log files (`/var/log/auth.log`, `/var/log/secure`).
  - Filters and displays recent **failed authentication events** (`failed password`, `authentication failure`, `invalid user`).
  - Displays recent **successful login sessions** via `last -n 10` for audit verification.
- **Usage**:
  ```bash
  ./scripts/logs/audit_logs.sh
  ```

---

## 🚀 Quickstart & CLI Interface

The toolkit provides an all-in-one command-line interface via [`cli.py`](file:///mnt/projects/trialFinalModule1/cli.py) (or `python3 -m scanner.main`), supporting both rich subcommands and an interactive menu.

### 1. Requirements
- Python 3.8+
- Standard POSIX utilities (`awk`, `grep`, `sed`, and optional utilities like `ss`, `journalctl`, `ufw`, `nft`, etc.)

Install testing dependencies (optional):
```bash
python3 -m pip install -r requirements.txt
```

### 2. Interactive Terminal Dashboard
Launch the interactive terminal interface:
```bash
./cli.py
# or explicitly:
./cli.py --menu
```
This presents a menu to run audits, filter by category, list controls, run shell scripts, or inspect remediation guidance.

### 3. Running Audits via CLI

#### Full Audit (All 21 Checks Across All Categories)
```bash
./cli.py audit
```
*Generates console output and writes reports to `output/report.json` and `output/report.html`.*

#### Category-Filtered Audit with Detailed Evidence
```bash
# Audit only SSH checks with full evidence and expected baseline:
./cli.py audit --category ssh --verbose

# Audit only Permissions checks:
./cli.py audit --category permissions

# Customize output targets:
./cli.py audit --json-output myreport.json --html-output myreport.html
```

### 4. Listing Registered Checks & Baselines
List all 21 checks, their severity, categories, and titles:
```bash
# List all checks
./cli.py list

# List checks for a specific category
./cli.py list --category accounts
```

### 5. Running Standalone Bash Category Scripts
Run any category Bash script directly through the CLI entrypoint:
```bash
./cli.py script system
./cli.py script accounts
./cli.py script permissions
./cli.py script ssh
./cli.py script network
./cli.py script firewall
./cli.py script logs
./cli.py script discovery
```

### 6. Host Environment Discovery
Scan the host platform, distribution, kernel, init system, and installed security tools:
```bash
./cli.py discover
```

### 7. Inspect Safe Remediation Guidance
View safe, non-destructive step-by-step instructions, warnings, and verification commands:
```bash
# List all available remediation guides:
./cli.py remediation

# View specific remediation guide:
./cli.py remediation --check SSH-001
./cli.py remediation --check ACC-002
./cli.py remediation --check PERM-003
```

### 8. Regenerate HTML Dashboard from JSON
```bash
./cli.py report output/report.json --output-html output/report.html
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

from typing import Dict, Any, Optional

REMEDIATION_DATABASE: Dict[str, Dict[str, Any]] = {
    "SYS-001": {
        "title": "System Identification & Inventory",
        "action": "Maintain system identification records and review kernel/OS currency.",
        "steps": [
            "Check current OS version and kernel support status.",
            "Schedule regular system upgrades using the official package manager.",
            "Verify all hardware architecture and virtualization parameters match baseline."
        ],
        "safe_command": "uname -r; cat /etc/os-release",
        "warning": "None - purely informational."
    },
    "ACC-001": {
        "title": "UID 0 Accounts",
        "action": "Ensure root is the sole user possessing UID 0.",
        "steps": [
            "Inspect /etc/passwd for any secondary users defined with UID 0 (e.g., awk -F: '($3 == 0) {print $1}' /etc/passwd).",
            "If an unauthorized user has UID 0, edit /etc/passwd or run usermod -u <new_uid> <username>.",
            "Lock or remove unauthorized superuser accounts: passwd -l <username>.",
            "Confirm only 'root' remains with UID 0."
        ],
        "safe_command": "awk -F: '($3 == 0) {print $1, $3}' /etc/passwd",
        "warning": "Do not delete or change UID of root itself. Doing so will break system authentication."
    },
    "ACC-002": {
        "title": "Empty Password Accounts",
        "action": "Lock or set passwords for accounts with empty password fields.",
        "steps": [
            "Identify accounts with empty password hashes in /etc/shadow (fields where password hash is '').",
            "Lock the vulnerable account: sudo passwd -l <username>.",
            "Or set a strong password if legitimate: sudo passwd <username>.",
            "Verify /etc/shadow reflects a locked status (e.g. '!' or '*') or a valid hash."
        ],
        "safe_command": "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow",
        "warning": "Executing passwd -l on an active service account may impact daemon authentication if it relies on local PAM."
    },
    "ACC-003": {
        "title": "Password Ageing Policy",
        "action": "Configure password expiration limits in /etc/login.defs.",
        "steps": [
            "Backup /etc/login.defs before editing: cp /etc/login.defs /etc/login.defs.bak",
            "Ensure PASS_MAX_DAYS is set to 90 or lower.",
            "Ensure PASS_MIN_DAYS is set to 1 or higher.",
            "Ensure PASS_WARN_AGE is set to 7.",
            "Apply the policy to existing users if needed using: chage --maxdays 90 <username>."
        ],
        "safe_command": "grep -E '^PASS_(MAX|MIN|WARN)_' /etc/login.defs",
        "warning": "Applying password expiry to service or automated accounts may disrupt unattended batch operations."
    },
    "PERM-001": {
        "title": "Account File Permissions (/etc/passwd, /etc/group)",
        "action": "Restrict ownership and permissions on /etc/passwd and /etc/group.",
        "steps": [
            "Set ownership to root:root: sudo chown root:root /etc/passwd /etc/group",
            "Set permissions to 0644 (rw-r--r--): sudo chmod 644 /etc/passwd /etc/group",
            "Verify with ls -l /etc/passwd /etc/group."
        ],
        "safe_command": "ls -l /etc/passwd /etc/group",
        "warning": "Do NOT remove world-read (r) from /etc/passwd or /etc/group; standard system utilities (ls, id, ps) require reading them."
    },
    "PERM-002": {
        "title": "Shadow File Permissions (/etc/shadow)",
        "action": "Enforce strict root ownership and permissions on /etc/shadow.",
        "steps": [
            "Set ownership to root:root or root:shadow: sudo chown root:root /etc/shadow",
            "Set permissions to 0600 or 0640: sudo chmod 600 /etc/shadow (or 0640 if shadow group exists)",
            "Verify with ls -l /etc/shadow."
        ],
        "safe_command": "ls -l /etc/shadow",
        "warning": "Never make /etc/shadow world-readable. Doing so exposes all password hashes to unprivileged users."
    },
    "SSH-001": {
        "title": "SSH Direct Root Login",
        "action": "Disable direct SSH login for root.",
        "steps": [
            "Create a backup of SSH configuration: sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "Edit /etc/ssh/sshd_config (or appropriate drop-in in /etc/ssh/sshd_config.d/): set 'PermitRootLogin no'",
            "Validate configuration syntax before reloading: sudo sshd -t",
            "Ensure an administrative user with sudo privileges can log in before restarting sshd.",
            "Reload the SSH service: sudo systemctl reload sshd (or service ssh reload)."
        ],
        "safe_command": "sudo sshd -t",
        "warning": "CRITICAL: Incorrect SSH configuration can lock administrators out. ALWAYS maintain an active terminal session and test in another session before logging out."
    },
    "SSH-002": {
        "title": "SSH Password Authentication",
        "action": "Enforce SSH public-key authentication and disable passwords.",
        "steps": [
            "Confirm that SSH authorized_keys are configured and functioning for all admin accounts.",
            "Backup SSH configuration: sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config (or drop-in file).",
            "Validate syntax: sudo sshd -t",
            "Reload SSH daemon: sudo systemctl reload sshd (or service ssh reload)."
        ],
        "safe_command": "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config",
        "warning": "Ensure your SSH public key is deployed and verified before disabling password authentication, or you will be locked out."
    },
    "NET-001": {
        "title": "Listening Network Services",
        "action": "Review and terminate unneeded network listeners.",
        "steps": [
            "Inspect listening sockets: ss -tulpen",
            "Identify daemons bound to 0.0.0.0 or ::: instead of 127.0.0.1.",
            "Disable unnecessary background daemons via systemctl: sudo systemctl stop <service> && sudo systemctl disable <service>."
        ],
        "safe_command": "ss -tulpen",
        "warning": "Do not terminate critical infrastructure services (SSH, DNS, WireGuard, DB) without verifying system dependency graphs."
    },
    "FW-001": {
        "title": "Firewall Detection & Enforcement",
        "action": "Enable and configure a host-based firewall.",
        "steps": [
            "Detect which firewall utility is available (ufw, firewalld, nftables, or iptables).",
            "If using UFW: ensure SSH is allowed ('sudo ufw allow ssh') before enabling ('sudo ufw enable').",
            "If using Firewalld: ensure ssh is added ('sudo firewall-cmd --permanent --add-service=ssh && sudo firewall-cmd --reload').",
            "If using nftables: enable the service and load rules: sudo systemctl enable --now nftables.",
            "Verify active status: sudo ufw status OR sudo firewall-cmd --state OR sudo nft list ruleset."
        ],
        "safe_command": "sudo ufw status 2>/dev/null || sudo firewall-cmd --state 2>/dev/null || sudo nft list ruleset 2>/dev/null || sudo iptables -L -n -v",
        "warning": "Never enable a firewall without explicitly permitting SSH first, or the active connection will be severed."
    },
    "LOG-001": {
        "title": "Authentication Failures",
        "action": "Investigate suspicious login failures and configure brute-force mitigation.",
        "steps": [
            "Inspect source IP addresses for repeated failed attempts.",
            "Deploy Fail2ban, sshguard, or nftables rate-limiting rules.",
            "Enforce key-based authentication to render password brute-force attacks ineffective."
        ],
        "safe_command": "journalctl -u sshd --since '24 hours ago' | grep -i 'fail'",
        "warning": "Verify firewall bans do not inadvertently block legitimate internal monitoring agents or administrator IPs."
    },
    "LOG-002": {
        "title": "Successful Logins Audit",
        "action": "Audit successful login sessions for anomalous activity.",
        "steps": [
            "Review session timestamps and originating IPs using 'last -a' or 'who'.",
            "Investigate any off-hours or unfamiliar IP addresses.",
            "Ensure multi-factor authentication (MFA/2FA) is used for administrative logins."
        ],
        "safe_command": "last -n 20",
        "warning": "None - audit only."
    },
    "SYS-002": {
        "title": "Kernel Core Dumps Restriction",
        "action": "Disable core dumps for setuid executables to prevent memory leakage.",
        "steps": [
            "Create or edit /etc/sysctl.d/50-coredump.conf.",
            "Add line: fs.suid_dumpable = 0",
            "Reload sysctl settings: sudo sysctl -p /etc/sysctl.d/50-coredump.conf",
            "Add '* hard core 0' to /etc/security/limits.conf if persistent user limits are desired."
        ],
        "safe_command": "sysctl fs.suid_dumpable",
        "warning": "Disabling core dumps prevents developers from post-mortem debugging crashed programs on production nodes."
    },
    "SYS-003": {
        "title": "Address Space Layout Randomization (ASLR)",
        "action": "Enable full memory address space randomization.",
        "steps": [
            "Create or edit /etc/sysctl.d/50-aslr.conf.",
            "Add line: kernel.randomize_va_space = 2",
            "Apply immediately: sudo sysctl -w kernel.randomize_va_space=2",
            "Verify effective setting: sysctl kernel.randomize_va_space"
        ],
        "safe_command": "sysctl kernel.randomize_va_space",
        "warning": "None - full ASLR is the industry standard default across modern Linux kernels."
    },
    "ACC-004": {
        "title": "Default User UMASK",
        "action": "Enforce a restrictive default file creation mask (027 or 077).",
        "steps": [
            "Edit /etc/login.defs.",
            "Set UMASK 027 (prevents group write and all permissions for other users).",
            "Verify shell profile defaults (/etc/profile or /etc/bash.bashrc) do not override with 022."
        ],
        "safe_command": "grep -i '^UMASK' /etc/login.defs",
        "warning": "A restrictive umask like 027 prevents other non-group users from reading newly created files; ensure shared folder group permissions are adjusted if needed."
    },
    "PERM-003": {
        "title": "Sudoers File Permissions",
        "action": "Enforce 0440 mode and root:root ownership on sudoers files.",
        "steps": [
            "Ensure ownership: sudo chown root:root /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
            "Set permissions: sudo chmod 0440 /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
            "Validate syntax before closing session: sudo visudo -c"
        ],
        "safe_command": "ls -l /etc/sudoers /etc/sudoers.d",
        "warning": "Always use visudo -c to check syntax; corrupt sudoers files can prevent any sudo elevation."
    },
    "PERM-004": {
        "title": "World-Writable Files in /etc",
        "action": "Remove write permissions for others on configuration files.",
        "steps": [
            "Identify world-writable files: find /etc -xdev -type f -perm -0002",
            "Remove other write bit: sudo chmod o-w <filename>",
            "Verify file permissions with ls -l."
        ],
        "safe_command": "find /etc -maxdepth 3 -type f -perm -0002",
        "warning": "Ensure symlinks to /tmp or shared sockets are not modified unintentionally."
    },
    "SSH-003": {
        "title": "SSH Idle Timeout Configuration",
        "action": "Enforce disconnect timeouts on idle SSH sessions.",
        "steps": [
            "Edit /etc/ssh/sshd_config (or /etc/ssh/sshd_config.d/timeout.conf).",
            "Add: ClientAliveInterval 300",
            "Add: ClientAliveCountMax 3",
            "Test syntax: sudo sshd -t",
            "Reload SSH daemon: sudo systemctl reload sshd"
        ],
        "safe_command": "sudo sshd -t",
        "warning": "Active connections will terminate after 15 minutes of inactivity; adjust ClientAliveInterval to balance security and usability."
    },
    "SSH-004": {
        "title": "SSH Max Authentication Tries",
        "action": "Restrict per-connection authentication attempts to reduce brute-force effectiveness.",
        "steps": [
            "Edit /etc/ssh/sshd_config (or sshd_config.d/auth.conf).",
            "Add: MaxAuthTries 4",
            "Test syntax: sudo sshd -t",
            "Reload SSH daemon: sudo systemctl reload sshd"
        ],
        "safe_command": "grep -i 'MaxAuthTries' /etc/ssh/sshd_config",
        "warning": "If users have multiple SSH keys loaded in their agent, they may hit the 4-try limit before finding the right key. Configure IdentityFile in client configs if necessary."
    },
    "NET-002": {
        "title": "IPv4 Forwarding",
        "action": "Disable IPv4 packet forwarding on standard host systems.",
        "steps": [
            "Create /etc/sysctl.d/50-netforward.conf.",
            "Add line: net.ipv4.ip_forward = 0",
            "Apply immediately: sudo sysctl -w net.ipv4.ip_forward=0",
            "Verify: sysctl net.ipv4.ip_forward"
        ],
        "safe_command": "sysctl net.ipv4.ip_forward",
        "warning": "Do NOT disable if host is a VPN gateway, Docker/Kubernetes container host, or network router."
    },
    "NET-003": {
        "title": "ICMP Redirect Acceptance",
        "action": "Disable ICMP redirect acceptance to prevent malicious routing alterations.",
        "steps": [
            "Create /etc/sysctl.d/50-redirects.conf.",
            "Add lines:\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0",
            "Apply: sudo sysctl -p /etc/sysctl.d/50-redirects.conf",
            "Verify: sysctl net.ipv4.conf.all.accept_redirects"
        ],
        "safe_command": "sysctl net.ipv4.conf.all.accept_redirects",
        "warning": "Disabling ICMP redirects may require static routes in complex multi-homed network topologies."
    }
}


def get_remediation_guidance(check_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve explicit remediation steps and warnings for a check ID."""
    return REMEDIATION_DATABASE.get(check_id.upper())

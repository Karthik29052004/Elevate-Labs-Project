#!/usr/bin/env python3

"""
Linux Hardening Audit Tool

Runs several security configuration audits on a Linux system, calculates a weighted
compliance score, prints a console summary, and saves a detailed JSON report.

Usage:
  sudo python3 linux_audit.py --report

Only built-in libraries are used as required.
"""

import os
import stat
import pwd
import grp
import json
import shlex
import argparse
from datetime import datetime
import subprocess
from typing import Any, Dict, List, Optional, Tuple


# -------------------------------
# Utility helpers
# -------------------------------

def run_command(command: List[str], timeout_seconds: int = 20) -> Tuple[int, str, str]:
    """Run a command safely, returning (returncode, stdout, stderr).

    - Does not raise on failure; returns non-zero codes and captured output.
    - Uses a timeout to avoid hanging on slow commands.
    - If the command is missing, return code 127 to indicate not found.
    """
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            text=True,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {' '.join(shlex.quote(x) for x in command)}"
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "").strip(), f"Timeout ({timeout_seconds}s) running: {' '.join(shlex.quote(x) for x in command)}"
    except Exception as exc:  # Fallback catch-all to avoid crashing
        return 1, "", f"Error running command: {exc}"


def which(binary: str) -> Optional[str]:
    """Simple variant of `which` using PATH.
    Returns absolute path if found, None otherwise.
    """
    paths = os.environ.get("PATH", "").split(os.pathsep)
    for p in paths:
        candidate = os.path.join(p, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def is_root() -> bool:
    """Return True if running as root (uid 0)."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        # os.geteuid is not available on some platforms (e.g., Windows).
        return False


def safe_read_file(path: str, max_bytes: int = 512_000) -> Tuple[bool, str]:
    """Safely read a file, returning (success, content or error)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read(max_bytes)
        return True, data
    except Exception as exc:
        return False, f"Error reading {path}: {exc}"


# -------------------------------
# Scoring and result structure
# -------------------------------

class CheckResult:
    def __init__(self, name: str, max_score: int):
        self.name = name
        self.max_score = max_score
        self.score = 0
        self.passed = False
        self.details: Dict[str, Any] = {}
        self.remediation: List[str] = []
        # Issue codes to drive standardized recommendations output
        self.issue_codes: List[str] = []

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "max_score": self.max_score,
            "passed": self.passed,
            "details": self.details,
            "remediation": self.remediation,
            "issue_codes": self.issue_codes,
        }


def mark_pass_if_threshold(result: CheckResult, threshold: float = 0.8) -> None:
    """Mark a check as passed if it meets a ratio threshold of its max score."""
    if result.max_score <= 0:
        result.passed = True
    else:
        result.passed = (result.score / result.max_score) >= threshold


# -------------------------------
# Remediation catalog & helpers
# -------------------------------

# Central mapping from issue code -> recommendation metadata. Short, actionable commands.
REMEDIATION_CATALOG: Dict[str, Dict[str, str]] = {
    # Firewall
    "firewall_inactive": {
        "category": "Firewall Configuration",
        "risk": "High",
        "text": "Enable a host firewall (e.g., 'sudo ufw enable' or start firewalld).",
    },
    "firewall_default_allow": {
        "category": "Firewall Configuration",
        "risk": "High",
        "text": "Set default inbound policy to deny (e.g., 'sudo ufw default deny incoming').",
    },
    # Services
    "unnecessary_services_enabled": {
        "category": "Services",
        "risk": "Medium",
        "text": "Disable unnecessary services (e.g., 'sudo systemctl disable --now <service>').",
    },
    # SSH
    "root_login_enabled": {
        "category": "SSH Configuration",
        "risk": "High",
        "text": "Set 'PermitRootLogin no' and reload SSH ('sudo systemctl reload sshd').",
    },
    "password_auth_enabled": {
        "category": "SSH Configuration",
        "risk": "High",
        "text": "Disable password auth: set 'PasswordAuthentication no' and use SSH keys.",
    },
    "max_auth_tries_high": {
        "category": "SSH Configuration",
        "risk": "Medium",
        "text": "Reduce 'MaxAuthTries' to 4 or fewer and reload SSH.",
    },
    "empty_passwords_permitted": {
        "category": "SSH Configuration",
        "risk": "High",
        "text": "Ensure 'PermitEmptyPasswords no' is configured and reload SSH.",
    },
    "client_alive_interval_missing_or_high": {
        "category": "SSH Configuration",
        "risk": "Low",
        "text": "Set 'ClientAliveInterval' to 600s or less (e.g., 300) and reload SSH.",
    },
    # Key files
    "passwd_permissions_insecure": {
        "category": "Key File Permissions",
        "risk": "High",
        "text": "Set /etc/passwd to root:root and 0644 ('sudo chmod 0644 /etc/passwd').",
    },
    "shadow_permissions_insecure": {
        "category": "Key File Permissions",
        "risk": "High",
        "text": "Set /etc/shadow to root:shadow (or root) and 0640.",
    },
    "group_permissions_insecure": {
        "category": "Key File Permissions",
        "risk": "Medium",
        "text": "Set /etc/group to root:root and 0644.",
    },
    "gshadow_permissions_insecure": {
        "category": "Key File Permissions",
        "risk": "High",
        "text": "Set /etc/gshadow to root:shadow (or root) and 0640.",
    },
    "insecure_backup_files_present": {
        "category": "Key File Permissions",
        "risk": "Medium",
        "text": "Remove or secure backup files in /etc (e.g., *.bak, *.old).",
    },
    # Rootkit
    "rootkit_scanner_missing": {
        "category": "Rootkit Indicators",
        "risk": "Medium",
        "text": "Install a scanner (e.g., rkhunter) and run regular checks.",
    },
    "rootkit_scan_failed": {
        "category": "Rootkit Indicators",
        "risk": "Medium",
        "text": "Fix scanner execution and run a system check (rkhunter/chkrootkit).",
    },
}


def record_issue(result: CheckResult, code: str) -> None:
    """Attach an issue code to a check result, avoiding duplicates."""
    if code and code not in result.issue_codes:
        result.issue_codes.append(code)


# -------------------------------
# Firewall audit
# -------------------------------

def audit_firewall() -> CheckResult:
    """Audit firewall presence and default deny posture for common Linux firewalls.

    Weight allocation (max 20):
      - Firewall tool detected and active: up to 10
      - Default deny inbound policy (or equivalent): up to 10
    """
    res = CheckResult("Firewall configuration", max_score=20)

    ufw_path = which("ufw")
    firewalld_path = which("firewall-cmd")
    iptables_path = which("iptables")
    nft_path = which("nft")

    res.details["detected"] = {
        "ufw": bool(ufw_path),
        "firewalld": bool(firewalld_path),
        "iptables": bool(iptables_path),
        "nftables": bool(nft_path),
    }

    active = False
    default_deny = False
    active_via = None
    default_policy_info: Dict[str, Any] = {}

    # Check UFW
    if ufw_path:
        code, out, _ = run_command([ufw_path, "status"])
        if code == 0 and "Status: active" in out:
            active = True
            active_via = "ufw"
            # Default policy lines like: "Default: deny (incoming), allow (outgoing), disabled (routed)"
            for line in out.splitlines():
                if line.lower().startswith("default:"):
                    default_policy_info["ufw_default"] = line.strip()
                    default_deny = "deny (incoming)" in line.lower()

    # Check firewalld
    if not active and firewalld_path:
        code, out, _ = run_command([firewalld_path, "--state"])
        if code == 0 and out.strip() == "running":
            active = True
            active_via = "firewalld"
            # Check default zone, ensure no broad allows; best-effort check
            zc, zout, _ = run_command([firewalld_path, "--get-default-zone"])
            if zc == 0:
                zone = zout.strip()
                default_policy_info["default_zone"] = zone
                sc, sout, _ = run_command([firewalld_path, "--list-all", "--zone", zone])
                # Consider default deny if there are no services/ports open in default zone
                if sc == 0:
                    has_services = any(
                        s.strip().startswith("services:") and len(s.split()) > 1 for s in sout.splitlines()
                    )
                    has_ports = any(
                        s.strip().startswith("ports:") and len(s.split()) > 1 for s in sout.splitlines()
                    )
                    default_deny = not (has_services or has_ports)

    # Check iptables policies
    if not active and iptables_path:
        # If iptables has policies set to DROP for INPUT, that can count as active + default deny
        code, out, _ = run_command([iptables_path, "-S"])  # ruleset
        if code == 0 and out:
            active = True
            active_via = "iptables"
            # Look for policy lines like: -P INPUT DROP
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "-P" and parts[1] == "INPUT" and parts[2] == "DROP":
                    default_deny = True
            default_policy_info["iptables_policies"] = [l for l in out.splitlines() if l.startswith("-P ")]

    # Check nftables
    if not active and nft_path:
        code, out, _ = run_command([nft_path, "list", "ruleset"])
        if code == 0 and out:
            active = True
            active_via = "nftables"
            # Heuristic: if there is a rule that drops input by default
            # This is heuristic only; nftables syntax varies.
            low = out.lower()
            default_deny = "hook input" in low and ("policy drop" in low or "counter drop" in low)
            default_policy_info["nftables_has_input_hook"] = "hook input" in low

    # Scoring
    if active:
        res.score += 10
    else:
        res.remediation.append("Enable and configure a host firewall (ufw, firewalld, or nftables).")
        record_issue(res, "firewall_inactive")

    if default_deny:
        res.score += 10
    else:
        res.remediation.append("Set default inbound policy to deny and allow only required services.")
        record_issue(res, "firewall_default_allow")

    res.details["active"] = active
    res.details["active_via"] = active_via
    res.details["default_deny"] = default_deny
    res.details["policy_info"] = default_policy_info

    mark_pass_if_threshold(res)
    return res


# -------------------------------
# Services audit
# -------------------------------

def audit_services() -> CheckResult:
    """Audit enabled systemd services, flag potentially unnecessary or insecure ones.

    Weight allocation (max 20):
      - Able to enumerate enabled services: 5
      - No flagged unnecessary/insecure services enabled: 15
    """
    res = CheckResult("Enabled services", max_score=20)

    systemctl = which("systemctl")
    if not systemctl:
        res.details["error"] = "systemctl not found"
        res.remediation.append("Use systemd-based system for this check or ensure systemctl is available.")
        # Partial credit not possible without listing services
        mark_pass_if_threshold(res)
        return res

    code, out, err = run_command([systemctl, "list-unit-files", "--type=service", "--state=enabled"])
    enabled_services: List[str] = []
    if code == 0:
        for line in out.splitlines():
            # Typical format: ssh.service                             enabled
            if ".service" in line and "enabled" in line:
                name = line.split()[0]
                enabled_services.append(name)
        res.score += 5  # Enumerated successfully
    else:
        res.details["error"] = err or "Failed to list enabled services"

    # A conservative list of services often unnecessary on servers; adjust as needed.
    flagged_keywords = [
        "telnet", "rlogin", "rsh", "rexec", "vsftpd", "ftp", "tftp", "talk", "ntalk",
        "avahi", "cups", "smb", "samba", "rpcbind", "nfs", "bluetooth", "xinetd",
        "snmp", "portmap", "finger", "nis", "bind9", "named",
    ]

    flagged_found = sorted({svc for svc in enabled_services if any(k in svc.lower() for k in flagged_keywords)})
    res.details["enabled_services_count"] = len(enabled_services)
    res.details["flagged_enabled_services"] = flagged_found

    if code == 0 and not flagged_found:
        res.score += 15
    else:
        if flagged_found:
            res.remediation.append(
                "Disable unnecessary or insecure services: " + ", ".join(flagged_found)
            )
            record_issue(res, "unnecessary_services_enabled")

    mark_pass_if_threshold(res)
    return res


# -------------------------------
# SSH configuration audit
# -------------------------------

def parse_sshd_config_text(cfg_text: str) -> Dict[str, str]:
    """Parse sshd configuration text into a simple key->value mapping.

    - Ignores comments and Match blocks complexity; for baseline options this is sufficient.
    - Last occurrence of a key wins, similar to sshd behavior.
    """
    conf: Dict[str, str] = {}
    for raw in cfg_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Split on whitespace; handle forms like "Key value" or "Key=value"
        if "=" in line:
            k, v = line.split("=", 1)
        else:
            parts = line.split()
            if not parts:
                continue
            k = parts[0]
            v = " ".join(parts[1:]) if len(parts) > 1 else ""
        conf[k.strip().lower()] = v.strip()
    return conf


def get_sshd_effective_config() -> Dict[str, str]:
    """Retrieve effective sshd settings using `sshd -T` if available, otherwise parse sshd_config.
    Returns a lowercase-key dictionary of settings.
    """
    sshd = which("sshd")
    if sshd:
        code, out, _ = run_command([sshd, "-T"])  # effective configuration
        if code == 0 and out:
            conf: Dict[str, str] = {}
            for line in out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    conf[parts[0].strip().lower()] = parts[1].strip()
            return conf

    # Fallback to parsing file
    ok, text = safe_read_file("/etc/ssh/sshd_config")
    if ok:
        return parse_sshd_config_text(text)
    return {}


def audit_ssh() -> CheckResult:
    """Audit SSH daemon configuration for common hardening settings.

    Weight allocation (max 25):
      - PermitRootLogin no: 6
      - PasswordAuthentication no: 6
      - MaxAuthTries <= 4: 5
      - PermitEmptyPasswords no: 4
      - ClientAliveInterval set and <= 600: 4
    """
    res = CheckResult("SSH configuration", max_score=25)
    conf = get_sshd_effective_config()
    res.details["source"] = "sshd -T" if "port" in conf else "sshd_config (parsed)"

    # Define expectations
    # Using lowercase keys for consistent lookup
    expected = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "maxauthtries": 4,  # integer threshold
        "permitemptypasswords": "no",
        "clientaliveinterval": 600,  # integer threshold (seconds)
    }

    # Track actuals
    actual: Dict[str, Any] = {}
    for k in [
        "permitrootlogin",
        "passwordauthentication",
        "maxauthtries",
        "permitemptypasswords",
        "clientaliveinterval",
    ]:
        v = conf.get(k)
        actual[k] = v

    # Scoring with remediation messages
    # PermitRootLogin
    if str(actual.get("permitrootlogin", "")).lower() == "no":
        res.score += 6
    else:
        res.remediation.append("Set 'PermitRootLogin no' in sshd_config and reload sshd.")
        record_issue(res, "root_login_enabled")

    # PasswordAuthentication
    if str(actual.get("passwordauthentication", "")).lower() == "no":
        res.score += 6
    else:
        res.remediation.append("Disable password auth: set 'PasswordAuthentication no' and use SSH keys.")
        record_issue(res, "password_auth_enabled")

    # MaxAuthTries
    try:
        mat = int(str(actual.get("maxauthtries", "")).strip())
        if mat <= expected["maxauthtries"]:
            res.score += 5
        else:
            res.remediation.append("Reduce 'MaxAuthTries' to 4 or fewer.")
            record_issue(res, "max_auth_tries_high")
    except Exception:
        res.remediation.append("Set 'MaxAuthTries 4' to limit authentication attempts.")
        record_issue(res, "max_auth_tries_high")

    # PermitEmptyPasswords
    if str(actual.get("permitemptypasswords", "")).lower() == "no":
        res.score += 4
    else:
        res.remediation.append("Ensure 'PermitEmptyPasswords no' is configured.")
        record_issue(res, "empty_passwords_permitted")

    # ClientAliveInterval
    try:
        cai = int(str(actual.get("clientaliveinterval", "")).strip())
        if cai > 0 and cai <= expected["clientaliveinterval"]:
            res.score += 4
        else:
            res.remediation.append("Set 'ClientAliveInterval' to 600 seconds or less.")
            record_issue(res, "client_alive_interval_missing_or_high")
    except Exception:
        res.remediation.append("Set 'ClientAliveInterval 600' to disconnect idle sessions.")
        record_issue(res, "client_alive_interval_missing_or_high")

    res.details["actual"] = actual
    mark_pass_if_threshold(res)
    return res


# -------------------------------
# Key files permissions audit
# -------------------------------

def check_file_ownership_mode(path: str, expected_owner: str, expected_group: str, max_mode_octal: int) -> Dict[str, Any]:
    """Check a file's existence, owner, group, and mode compared to expectations.

    Returns a dict with results. Success criteria:
      - File exists
      - Owner == expected_owner
      - Group == expected_group (or acceptable alternatives when noted by caller)
      - Mode is not more permissive than max_mode_octal
    """
    result: Dict[str, Any] = {
        "path": path,
        "exists": False,
        "owner_ok": False,
        "group_ok": False,
        "mode_ok": False,
        "owner": None,
        "group": None,
        "mode_octal": None,
    }
    try:
        st = os.stat(path)
        result["exists"] = True
        owner = pwd.getpwuid(st.st_uid).pw_name
        group_name = grp.getgrgid(st.st_gid).gr_name
        mode_bits = stat.S_IMODE(st.st_mode)
        result["owner"] = owner
        result["group"] = group_name
        result["mode_octal"] = f"{mode_bits:04o}"

        result["owner_ok"] = (owner == expected_owner)
        result["group_ok"] = (group_name == expected_group)
        result["mode_ok"] = (mode_bits <= max_mode_octal)
    except FileNotFoundError:
        result["error"] = "file not found"
    except Exception as exc:
        result["error"] = f"error: {exc}"
    return result


def audit_key_files() -> CheckResult:
    """Audit core account/group files and common backups for secure ownership and permissions.

    Weight allocation (max 20):
      - Core files ownership/mode correct: 16 (4 files x 4 points)
      - No insecure backup files present: 4
    """
    res = CheckResult("Key file permissions", max_score=20)

    checks: List[Tuple[str, str, str, int]] = [
        ("/etc/passwd", "root", "root", 0o644),
        ("/etc/shadow", "root", "shadow", 0o640),  # group may be shadow or root on some systems
        ("/etc/group", "root", "root", 0o644),
        ("/etc/gshadow", "root", "shadow", 0o640),
    ]

    per_file_points = 4
    file_results: List[Dict[str, Any]] = []
    for path, owner, group_name, max_mode in checks:
        r = check_file_ownership_mode(path, owner, group_name, max_mode)
        # Accept shadow owned by group root in some distros
        if path in ("/etc/shadow", "/etc/gshadow") and r.get("exists") and not r.get("group_ok"):
            if r.get("group") == "root":
                r["group_ok"] = True
        file_results.append(r)
        if r.get("exists") and r.get("owner_ok") and r.get("group_ok") and r.get("mode_ok"):
            res.score += per_file_points
        else:
            res.remediation.append(
                f"Fix {path}: owner=root, group={group_name}, mode <= {oct(max_mode)}."
            )
            # Add specific issue codes per file
            if path == "/etc/passwd":
                record_issue(res, "passwd_permissions_insecure")
            elif path == "/etc/shadow":
                record_issue(res, "shadow_permissions_insecure")
            elif path == "/etc/group":
                record_issue(res, "group_permissions_insecure")
            elif path == "/etc/gshadow":
                record_issue(res, "gshadow_permissions_insecure")

    # Look for insecure backups in /etc matching core files
    insecure_backups: List[str] = []
    try:
        for entry in os.listdir("/etc"):
            lower = entry.lower()
            if any(lower.startswith(p) for p in ["passwd", "shadow", "group", "gshadow"]):
                if any(lower.endswith(s) for s in ["~", ".bak", ".old", "-", ".orig", ".backup"]):
                    insecure_backups.append(os.path.join("/etc", entry))
    except Exception:
        # best-effort only
        pass

    if not insecure_backups:
        res.score += 4
    else:
        res.remediation.append("Remove or secure backup files in /etc containing account data: " + ", ".join(insecure_backups))
        record_issue(res, "insecure_backup_files_present")

    res.details["files"] = file_results
    res.details["insecure_backups"] = insecure_backups

    mark_pass_if_threshold(res)
    return res


# -------------------------------
# Rootkit tools audit
# -------------------------------

def audit_rootkit() -> CheckResult:
    """Detect rootkit scanners and run a lightweight scan if installed.

    Weight allocation (max 15):
      - Tool installed: 5
      - Lightweight scan runs without critical errors: 10
    """
    res = CheckResult("Rootkit indicators", max_score=15)

    tools = [
        ("chkrootkit", ["chkrootkit", "-q"], 60),
        ("rkhunter", ["rkhunter", "--check", "--sk", "--rwo"], 120),
        ("lynis", ["lynis", "audit", "system", "--quick", "--no-colors"], 120),
    ]

    installed: Optional[Tuple[str, List[str], int]] = None
    for name, cmd, timeout in tools:
        if which(name):
            installed = (name, cmd, timeout)
            break

    if not installed:
        res.remediation.append("Install and periodically run a rootkit scanner (e.g., rkhunter).")
        record_issue(res, "rootkit_scanner_missing")
        mark_pass_if_threshold(res)
        return res

    tool_name, cmd, timeout = installed
    res.details["detected_tool"] = tool_name
    res.score += 5  # tool present

    code, out, err = run_command(cmd, timeout_seconds=timeout)
    # Consider a scan successful if command executed and returned (even with non-zero code), capture limited output
    preview = (out or err or "").splitlines()[:50]
    res.details["scan_returncode"] = code
    res.details["scan_output_preview"] = preview

    if code in (0, 1, 2, 3, 4, 5, 8, 10, 11, 12):
        # Many scanners use non-zero codes for warnings/findings; treat as ran successfully
        res.score += 10
    else:
        res.remediation.append(f"Investigate scanner execution issues for {tool_name} and run periodic checks.")
        record_issue(res, "rootkit_scan_failed")

    mark_pass_if_threshold(res)
    return res


# -------------------------------
# Orchestration, scoring, and output
# -------------------------------

def compute_overall(checks: List[CheckResult]) -> Dict[str, Any]:
    total_max = sum(c.max_score for c in checks)
    total_score = sum(c.score for c in checks)
    percent = 0.0 if total_max == 0 else (total_score / total_max) * 100.0
    if percent >= 85.0:
        status = "PASS"
    elif percent >= 60.0:
        status = "WARN"
    else:
        status = "FAIL"
    return {
        "total_score": total_score,
        "total_max": total_max,
        "percent": round(percent, 2),
        "status": status,
    }


def print_console_summary(checks: List[CheckResult], overall: Dict[str, Any]) -> None:
    print("\nLinux Hardening Audit Summary")
    print("=" * 34)
    for c in checks:
        ratio = 0 if c.max_score == 0 else int(round((c.score / c.max_score) * 100))
        state = "PASS" if c.passed else ("WARN" if ratio >= 60 else "FAIL")
        print(f"- {c.name}: {c.score}/{c.max_score} ({ratio}%) [{state}]")
    print("-" * 34)
    print(f"Overall: {overall['total_score']}/{overall['total_max']} ({overall['percent']}%) [{overall['status']}]")
    # Recommendations section
    recs = collate_recommendations(checks)
    if recs:
        print("\nRecommendations:")
        print("=" * 40)
        for category, items in recs.items():
            for item in items:
                risk = item.get("risk")
                text = item.get("text", "")
                if risk:
                    print(f"[{category}] ({risk}) -> {text}")
                else:
                    print(f"[{category}] -> {text}")


def save_json_report(checks: List[CheckResult], overall: Dict[str, Any], output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"linux_audit_report_{timestamp}.json"
    path = os.path.join(output_dir, filename)
    data = {
        "generated_at_utc": timestamp,
        "ran_as_root": is_root(),
        "checks": [c.as_dict() for c in checks],
        "overall": overall,
        "recommendations": collate_recommendations(checks),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def run_audit() -> Tuple[List[CheckResult], Dict[str, Any]]:
    checks: List[CheckResult] = []

    checks.append(audit_firewall())
    checks.append(audit_services())
    checks.append(audit_ssh())
    checks.append(audit_key_files())
    checks.append(audit_rootkit())

    overall = compute_overall(checks)
    return checks, overall


def collate_recommendations(checks: List[CheckResult]) -> Dict[str, List[Dict[str, str]]]:
    """Build a category->list of recommendations from issue codes across checks.

    Each item contains: {category, text, risk, issue_code}.
    Duplicates (same issue_code) are collapsed.
    """
    seen: set = set()
    grouped: Dict[str, List[Dict[str, str]]] = {}
    for c in checks:
        for code in getattr(c, "issue_codes", []) or []:
            if code in seen:
                continue
            seen.add(code)
            meta = REMEDIATION_CATALOG.get(code)
            if not meta:
                continue
            category = meta.get("category", c.name)
            item = {
                "issue_code": code,
                "category": category,
                "text": meta.get("text", ""),
                "risk": meta.get("risk", ""),
            }
            grouped.setdefault(category, []).append(item)
    return grouped


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Linux Hardening Audit Tool")
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a JSON report under the reports/ directory",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Warn if not root; many checks require elevated privileges for full coverage.
    if not is_root():
        print("[WARN] Running without root privileges may limit audit coverage. Consider using sudo.")

    checks, overall = run_audit()
    print_console_summary(checks, overall)

    if args.report:
        path = save_json_report(checks, overall)
        print(f"Detailed report saved to: {path}")


if __name__ == "__main__":
    main()



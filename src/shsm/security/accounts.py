"""Structural analysis and diffing for system accounts and groups (/etc/passwd, /etc/group).

Prevents blind CRITICAL alert fatigue by classifying system service accounts (e.g. clamav,
shsm, redis) as INFO, while catching real security threats (UID 0 backdoors, interactive shells
on system accounts, or unauthorized additions to privileged groups like sudo/wheel/docker).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

from shsm.core.context import Context
from shsm.core.findings import Severity

NON_LOGIN_SHELLS: Set[str] = {
    "/bin/false",
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/sync",
    "/usr/bin/false",
    "/usr/bin/nologin",
}

INTERACTIVE_SHELLS: Set[str] = {
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
    "/bin/dash",
    "/bin/csh",
    "/bin/tcsh",
}

PRIVILEGED_GROUPS: Set[str] = {
    "sudo",
    "wheel",
    "root",
    "docker",
    "shadow",
    "adm",
}

KNOWN_SYSTEM_ACCOUNTS: Set[str] = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "systemd-network", "systemd-resolve", "messagebus", "systemd-timesync", "syslog",
    "_apt", "tss", "uuidd", "tcpdump", "sshd", "pollinate", "clamav", "mysql",
    "redis", "shsm", "postfix", "nginx", "bind", "named", "dovecot", "dovenull",
    "ftp", "lsws", "cyberpanel",
}


def parse_passwd_content(content: str) -> Dict[str, Dict[str, Any]]:
    """Parse /etc/passwd content into a structured dict: username -> account attributes."""
    users: Dict[str, Dict[str, Any]] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            uname = parts[0]
            try:
                uid = int(parts[2])
                gid = int(parts[3])
            except ValueError:
                continue
            users[uname] = {
                "username": uname,
                "uid": uid,
                "gid": gid,
                "gecos": parts[4],
                "home": parts[5],
                "shell": parts[6],
            }
    return users


def parse_group_content(content: str) -> Dict[str, Dict[str, Any]]:
    """Parse /etc/group content into a structured dict: group_name -> group attributes."""
    groups: Dict[str, Dict[str, Any]] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            gname = parts[0]
            try:
                gid = int(parts[2])
            except ValueError:
                continue
            members = [m.strip() for m in parts[3].split(",") if m.strip()] if len(parts) > 3 else []
            groups[gname] = {
                "group": gname,
                "gid": gid,
                "members": members,
            }
    return groups


def find_auth_log_evidence(ctx: Context, name: str, is_group: bool = False) -> Optional[str]:
    """Search recent auth.log / secure candidates for installer evidence (useradd or groupadd)."""
    candidates = list(ctx.config.get("security.ssh_log_candidates", ["/var/log/auth.log", "/var/log/secure"]))
    # Add .1 candidate if it exists
    extended: List[str] = []
    for c in candidates:
        extended.append(c)
        if os.path.exists(c + ".1"):
            extended.append(c + ".1")

    target_pattern = (
        re.compile(rf"groupadd\[\d+\]:.*name={re.escape(name)}\b")
        if is_group
        else re.compile(rf"useradd\[\d+\]:.*name={re.escape(name)}\b")
    )

    for log_path in extended:
        if not os.path.isfile(log_path):
            continue
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                # Read last 500 lines to avoid high I/O
                lines = fh.readlines()[-500:]
                for line in reversed(lines):
                    if target_pattern.search(line):
                        return line.strip()
        except OSError:
            continue
    return None


def diff_passwd(
    old_users: Dict[str, Dict[str, Any]],
    new_users: Dict[str, Dict[str, Any]],
    ctx: Optional[Context] = None,
) -> List[Dict[str, Any]]:
    """Diff two /etc/passwd snapshots and categorize events with precise security severities."""
    events: List[Dict[str, Any]] = []

    # 1. Added users
    for uname, u in new_users.items():
        if uname not in old_users:
            uid = u["uid"]
            shell = u["shell"]
            home = u["home"]
            evidence = find_auth_log_evidence(ctx, uname, is_group=False) if ctx else None
            evidence_str = f" (Evidence: {evidence})" if evidence else ""

            # Rule A: Any UID 0 account other than root is a critical backdoor
            if uid == 0 and uname != "root":
                events.append({
                    "event_type": "BACKDOOR_UID_ZERO",
                    "name": uname,
                    "severity": Severity.CRITICAL,
                    "title": f"Unauthorized root-equivalent account detected: {uname} (UID: 0)",
                    "details": f"Account '{uname}' has UID 0 (root privileges), shell '{shell}', home '{home}'.",
                    "recommendation": "IMMEDIATELY investigate server. An unauthorized UID 0 account is a classic backdoor indicator.",
                    "is_system_only": False,
                })
            # Rule B: System service account (UID < 1000 and non-login shell, or known service account)
            elif (uid < 1000 and shell in NON_LOGIN_SHELLS) or (uname in KNOWN_SYSTEM_ACCOUNTS and shell in NON_LOGIN_SHELLS):
                events.append({
                    "event_type": "SYSTEM_USER_ADDED",
                    "name": uname,
                    "severity": Severity.INFO,
                    "title": f"System service account added: {uname} (UID: {uid}, Shell: {shell})",
                    "details": f"Service account '{uname}' added with non-login shell '{shell}' and UID {uid}.{evidence_str}",
                    "recommendation": "Normal package or service installation. No administrator action required.",
                    "is_system_only": True,
                })
            # Rule C: System account with interactive login shell
            elif uid < 1000 and shell in INTERACTIVE_SHELLS:
                events.append({
                    "event_type": "SYSTEM_USER_INTERACTIVE",
                    "name": uname,
                    "severity": Severity.CRITICAL,
                    "title": f"Suspicious system account created with interactive shell: {uname} (UID: {uid}, Shell: {shell})",
                    "details": f"Account '{uname}' has system UID {uid} but was given an interactive login shell '{shell}'.",
                    "recommendation": "Verify why this system account was assigned an interactive shell instead of /bin/false or /usr/sbin/nologin.",
                    "is_system_only": False,
                })
            # Rule D: New interactive regular user (UID >= 1000)
            elif uid >= 1000 and shell in INTERACTIVE_SHELLS:
                events.append({
                    "event_type": "INTERACTIVE_USER_ADDED",
                    "name": uname,
                    "severity": Severity.MEDIUM,
                    "title": f"New interactive login user detected: {uname} (UID: {uid}, Shell: {shell})",
                    "details": f"A new login-capable user '{uname}' (UID {uid}) was created with shell '{shell}' and home '{home}'.{evidence_str}",
                    "recommendation": "Confirm whether this user was created intentionally by a server administrator.",
                    "is_system_only": False,
                })
            else:
                # Regular non-login user
                events.append({
                    "event_type": "USER_ADDED",
                    "name": uname,
                    "severity": Severity.INFO,
                    "title": f"Non-login user account added: {uname} (UID: {uid})",
                    "details": f"Account '{uname}' added with shell '{shell}'.{evidence_str}",
                    "recommendation": "Confirm account creation was intentional.",
                    "is_system_only": True,
                })

    # 2. Modified users
    for uname, old_u in old_users.items():
        if uname in new_users:
            new_u = new_users[uname]
            # Check UID change to 0
            if old_u["uid"] != 0 and new_u["uid"] == 0:
                events.append({
                    "event_type": "PRIVILEGE_ESCALATION_UID_ZERO",
                    "name": uname,
                    "severity": Severity.CRITICAL,
                    "title": f"Privilege escalation: User '{uname}' modified to UID 0",
                    "details": f"User '{uname}' previously had UID {old_u['uid']}, now modified to UID 0.",
                    "recommendation": "IMMEDIATELY investigate for system compromise.",
                    "is_system_only": False,
                })
            # Check shell changed from non-login to interactive
            elif old_u["shell"] in NON_LOGIN_SHELLS and new_u["shell"] in INTERACTIVE_SHELLS:
                events.append({
                    "event_type": "SHELL_ESCALATION",
                    "name": uname,
                    "severity": Severity.CRITICAL,
                    "title": f"Shell escalation: '{uname}' changed to interactive shell ({new_u['shell']})",
                    "details": f"Account '{uname}' shell changed from '{old_u['shell']}' to interactive '{new_u['shell']}'.",
                    "recommendation": "Verify whether interactive access for this service account was authorized.",
                    "is_system_only": False,
                })
            elif old_u["shell"] != new_u["shell"] or old_u["home"] != new_u["home"]:
                events.append({
                    "event_type": "USER_ATTRIBUTES_MODIFIED",
                    "name": uname,
                    "severity": Severity.INFO,
                    "title": f"User attributes updated for '{uname}'",
                    "details": f"Old: shell={old_u['shell']}, home={old_u['home']}. New: shell={new_u['shell']}, home={new_u['home']}.",
                    "recommendation": "Review user changes if not performed intentionally.",
                    "is_system_only": True,
                })

    # 3. Deleted users
    for uname, old_u in old_users.items():
        if uname not in new_users:
            if uname == "root":
                events.append({
                    "event_type": "ROOT_DELETED",
                    "name": uname,
                    "severity": Severity.CRITICAL,
                    "title": "CRITICAL: 'root' account removed from /etc/passwd!",
                    "details": "The standard root account was deleted or missing from /etc/passwd.",
                    "recommendation": "IMMEDIATELY restore /etc/passwd from backup.",
                    "is_system_only": False,
                })
            else:
                events.append({
                    "event_type": "USER_DELETED",
                    "name": uname,
                    "severity": Severity.INFO,
                    "title": f"User account removed: {uname} (former UID: {old_u['uid']})",
                    "details": f"Account '{uname}' was removed from /etc/passwd.",
                    "recommendation": "Verify removal was intended.",
                    "is_system_only": True,
                })

    return events


def diff_group(
    old_groups: Dict[str, Dict[str, Any]],
    new_groups: Dict[str, Dict[str, Any]],
    ctx: Optional[Context] = None,
) -> List[Dict[str, Any]]:
    """Diff two /etc/group snapshots and categorize events with precise security severities."""
    events: List[Dict[str, Any]] = []

    # 1. Added groups
    for gname, g in new_groups.items():
        if gname not in old_groups:
            gid = g["gid"]
            evidence = find_auth_log_evidence(ctx, gname, is_group=True) if ctx else None
            evidence_str = f" (Evidence: {evidence})" if evidence else ""
            is_sys = gid < 1000 or gname in KNOWN_SYSTEM_ACCOUNTS

            events.append({
                "event_type": "GROUP_ADDED",
                "name": gname,
                "severity": Severity.INFO,
                "title": f"{'System group' if is_sys else 'Group'} added: {gname} (GID: {gid})",
                "details": f"Group '{gname}' (GID {gid}) added with members: {g['members']}.{evidence_str}",
                "recommendation": "Normal package or administration operation.",
                "is_system_only": True,
            })

    # 2. Membership modifications
    for gname, old_g in old_groups.items():
        if gname in new_groups:
            new_g = new_groups[gname]
            old_members = set(old_g["members"])
            new_members = set(new_g["members"])

            added_members = new_members - old_members
            if added_members:
                if gname in PRIVILEGED_GROUPS:
                    events.append({
                        "event_type": "PRIVILEGED_GROUP_MEMBERSHIP",
                        "name": gname,
                        "severity": Severity.CRITICAL,
                        "title": f"User(s) added to privileged group '{gname}': {', '.join(sorted(added_members))}",
                        "details": f"Users {sorted(added_members)} were granted membership in administrative group '{gname}'.",
                        "recommendation": "Ensure these users are authorized administrators with sudo / root access.",
                        "is_system_only": False,
                    })
                else:
                    events.append({
                        "event_type": "GROUP_MEMBERSHIP_ADDED",
                        "name": gname,
                        "severity": Severity.INFO,
                        "title": f"User(s) added to group '{gname}': {', '.join(sorted(added_members))}",
                        "details": f"Users {sorted(added_members)} added to group '{gname}'.",
                        "recommendation": "Verify group membership assignment if unexpected.",
                        "is_system_only": True,
                    })

    # 3. Deleted groups
    for gname, old_g in old_groups.items():
        if gname not in new_groups:
            events.append({
                "event_type": "GROUP_DELETED",
                "name": gname,
                "severity": Severity.INFO,
                "title": f"Group removed: {gname} (former GID: {old_g['gid']})",
                "details": f"Group '{gname}' was removed from /etc/group.",
                "recommendation": "Verify removal was intended.",
                "is_system_only": True,
            })

    return events

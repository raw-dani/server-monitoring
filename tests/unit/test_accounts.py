"""Unit tests for system account and group structural diffing."""

from shsm.core.findings import Severity
from shsm.security import accounts

SAMPLE_PASSWD_BASELINE = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""

SAMPLE_GROUP_BASELINE = """
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:ubuntu
tty:x:5:
disk:x:6:
sudo:x:27:ubuntu
docker:x:999:ubuntu
ubuntu:x:1000:
"""


def test_parse_passwd_content():
    users = accounts.parse_passwd_content(SAMPLE_PASSWD_BASELINE)
    assert "root" in users
    assert users["root"]["uid"] == 0
    assert users["root"]["shell"] == "/bin/bash"
    assert "ubuntu" in users
    assert users["ubuntu"]["uid"] == 1000
    assert users["ubuntu"]["home"] == "/home/ubuntu"


def test_parse_group_content():
    groups = accounts.parse_group_content(SAMPLE_GROUP_BASELINE)
    assert "sudo" in groups
    assert groups["sudo"]["gid"] == 27
    assert groups["sudo"]["members"] == ["ubuntu"]


def test_diff_passwd_benign_system_user_added():
    base_users = accounts.parse_passwd_content(SAMPLE_PASSWD_BASELINE)
    new_users = dict(base_users)
    # Add clamav and shsm system accounts with non-login shells
    new_users["clamav"] = {
        "username": "clamav",
        "uid": 122,
        "gid": 131,
        "gecos": "ClamAV",
        "home": "/var/lib/clamav",
        "shell": "/bin/false",
    }
    new_users["shsm"] = {
        "username": "shsm",
        "uid": 996,
        "gid": 998,
        "gecos": "SHSM Service",
        "home": "/home/shsm",
        "shell": "/bin/false",
    }

    events = accounts.diff_passwd(base_users, new_users)
    assert len(events) == 2
    assert all(e["severity"] == Severity.INFO for e in events)
    assert all(e["is_system_only"] is True for e in events)
    names = [e["name"] for e in events]
    assert "clamav" in names
    assert "shsm" in names


def test_diff_passwd_backdoor_uid_zero_detected():
    base_users = accounts.parse_passwd_content(SAMPLE_PASSWD_BASELINE)
    new_users = dict(base_users)
    # Hacker creates a backdoor user with UID 0
    new_users["toor"] = {
        "username": "toor",
        "uid": 0,
        "gid": 0,
        "gecos": "Backdoor",
        "home": "/root",
        "shell": "/bin/bash",
    }

    events = accounts.diff_passwd(base_users, new_users)
    crit_events = [e for e in events if e["severity"] == Severity.CRITICAL]
    assert len(crit_events) == 1
    assert crit_events[0]["event_type"] == "BACKDOOR_UID_ZERO"
    assert crit_events[0]["name"] == "toor"
    assert crit_events[0]["is_system_only"] is False


def test_diff_passwd_interactive_user_added():
    base_users = accounts.parse_passwd_content(SAMPLE_PASSWD_BASELINE)
    new_users = dict(base_users)
    # New regular user with bash shell
    new_users["newadmin"] = {
        "username": "newadmin",
        "uid": 1007,
        "gid": 1007,
        "gecos": "New Admin",
        "home": "/home/newadmin",
        "shell": "/bin/bash",
    }

    events = accounts.diff_passwd(base_users, new_users)
    warn_events = [e for e in events if e["severity"] == Severity.MEDIUM]
    assert len(warn_events) == 1
    assert warn_events[0]["event_type"] == "INTERACTIVE_USER_ADDED"
    assert warn_events[0]["name"] == "newadmin"


def test_diff_passwd_shell_escalation_on_system_account():
    base_users = accounts.parse_passwd_content(SAMPLE_PASSWD_BASELINE)
    new_users = dict(base_users)
    # System account www-data modified to have /bin/bash
    new_users["www-data"] = dict(base_users["www-data"])
    new_users["www-data"]["shell"] = "/bin/bash"

    events = accounts.diff_passwd(base_users, new_users)
    crit_events = [e for e in events if e["severity"] == Severity.CRITICAL]
    assert len(crit_events) == 1
    assert crit_events[0]["event_type"] == "SHELL_ESCALATION"
    assert crit_events[0]["name"] == "www-data"


def test_diff_group_privileged_membership_change():
    base_groups = accounts.parse_group_content(SAMPLE_GROUP_BASELINE)
    new_groups = dict(base_groups)
    # Add unauthorized user to sudo and docker
    new_groups["sudo"] = {
        "group": "sudo",
        "gid": 27,
        "members": ["ubuntu", "unauthorized_user"],
    }

    events = accounts.diff_group(base_groups, new_groups)
    crit_events = [e for e in events if e["severity"] == Severity.CRITICAL]
    assert len(crit_events) == 1
    assert crit_events[0]["event_type"] == "PRIVILEGED_GROUP_MEMBERSHIP"
    assert "unauthorized_user" in crit_events[0]["title"]


def test_diff_group_benign_system_group_added():
    base_groups = accounts.parse_group_content(SAMPLE_GROUP_BASELINE)
    new_groups = dict(base_groups)
    # Add clamav and shsm groups
    new_groups["clamav"] = {
        "group": "clamav",
        "gid": 131,
        "members": [],
    }
    new_groups["shsm"] = {
        "group": "shsm",
        "gid": 998,
        "members": [],
    }

    events = accounts.diff_group(base_groups, new_groups)
    assert len(events) == 2
    assert all(e["severity"] == Severity.INFO for e in events)
    assert all(e["is_system_only"] is True for e in events)

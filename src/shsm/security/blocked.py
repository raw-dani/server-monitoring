"""Centralized blocked IP aggregator and manager (Fail2Ban + iptables)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from shsm.core.context import Context
from shsm.security import fail2ban
from shsm.security.fail2ban import is_valid_ip, _run_with_sudo_fallback


def get_fail2ban_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve all blocked IPs across all active Fail2Ban jails."""
    client_bin = ctx.runner.which("fail2ban-client")
    if not client_bin:
        return []

    jails = fail2ban.get_active_jails(ctx)
    results: List[Dict[str, Any]] = []

    for jail in jails:
        res = _run_with_sudo_fallback(ctx, [client_bin, "status", jail], timeout=10)
        if not res.ok:
            continue

        for line in res.stdout.splitlines():
            if "Banned IP list:" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ips = parts[1].strip().split()
                    for ip in ips:
                        if ip.strip():
                            results.append({
                                "source": "fail2ban",
                                "target": ip.strip(),
                                "jail_or_chain": jail,
                                "packets": "-",
                                "bytes": "-",
                                "note": f"Fail2Ban ({jail})",
                            })
    return results


def get_iptables_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve all DROP rules from iptables INPUT chain (including hits/packets)."""
    ipt_bin = ctx.runner.which("iptables") or ctx.runner.which("/sbin/iptables") or ctx.runner.which("/usr/sbin/iptables")
    if not ipt_bin:
        return []

    res = _run_with_sudo_fallback(ctx, [ipt_bin, "-L", "INPUT", "-n", "-v"], timeout=10)
    if not res.ok or not res.stdout:
        return []

    results: List[Dict[str, Any]] = []
    # Lines typically look like:
    # 287 13604 DROP all -- * * 35.192.0.0/12 0.0.0.0/0
    # 2265 107K DROP all -- * * 0.0.0.0/0 0.0.0.0/0 -m geoip --source-country CN,RU
    for line in res.stdout.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("Chain") or line_clean.startswith("pkts"):
            continue

        parts = line_clean.split()
        if len(parts) >= 8 and parts[2] == "DROP":
            pkts = parts[0]
            byte_cnt = parts[1]
            source_ip = parts[7]
            destination = parts[8] if len(parts) > 8 else "0.0.0.0/0"
            extra = " ".join(parts[9:]) if len(parts) > 9 else ""

            # Check if this is a Fail2Ban dynamic chain rule or geoip/generic
            if source_ip == "0.0.0.0/0":
                if extra:
                    results.append({
                        "source": "iptables",
                        "target": f"0.0.0.0/0 ({extra})",
                        "jail_or_chain": "INPUT",
                        "packets": pkts,
                        "bytes": byte_cnt,
                        "note": extra,
                    })
                continue

            results.append({
                "source": "iptables",
                "target": source_ip,
                "jail_or_chain": "INPUT",
                "packets": pkts,
                "bytes": byte_cnt,
                "note": "Direct DROP" if not extra else extra,
            })

    return results


def list_all_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Return unified list of all blocked IPs/subnets from both Fail2Ban and iptables."""
    f2b_list = get_fail2ban_blocked(ctx)
    ipt_list = get_iptables_blocked(ctx)
    return f2b_list + ipt_list


def check_ip_blocked(ctx: Context, ip: str) -> Dict[str, Any]:
    """Check whether a specific IP address is blocked in Fail2Ban, iptables, or subnet."""
    clean_ip = ip.strip()
    is_valid = is_valid_ip(clean_ip)
    
    target_ip_obj = None
    if is_valid:
        try:
            target_ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            target_ip_obj = None

    all_blocked = list_all_blocked(ctx)
    matches: List[Dict[str, Any]] = []

    for entry in all_blocked:
        target_str = entry["target"]
        # Exact match
        if target_str == clean_ip:
            matches.append(entry)
            continue

        # Subnet / CIDR match (e.g. 35.192.0.0/12)
        if "/" in target_str and target_ip_obj is not None:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                if target_ip_obj in net:
                    matches.append({
                        **entry,
                        "matched_subnet": target_str,
                    })
            except ValueError:
                pass

    return {
        "ip": clean_ip,
        "is_blocked": len(matches) > 0,
        "matches": matches,
    }


def unban_ip_unified(ctx: Context, ip: str, jail: Optional[str] = None) -> Tuple[bool, List[str]]:
    """Unban an IP from both Fail2Ban AND iptables DROP rules simultaneously."""
    clean_ip = ip.strip()
    messages: List[str] = []
    any_success = False

    # 1. Unban from Fail2Ban
    f2b_bin = ctx.runner.which("fail2ban-client")
    if f2b_bin:
        f_ok, f_msg = fail2ban.unban_ip(ctx, clean_ip, jail=jail)
        if f_ok:
            any_success = True
            messages.append(f"Fail2Ban: {f_msg}")
        else:
            messages.append(f"Fail2Ban: {f_msg}")
    else:
        messages.append("Fail2Ban: client not installed, skipped")

    # 2. Check and remove from iptables INPUT DROP rules
    ipt_bin = ctx.runner.which("iptables") or ctx.runner.which("/sbin/iptables") or ctx.runner.which("/usr/sbin/iptables")
    if ipt_bin:
        # Check if rule exists
        c_cmd = [ipt_bin, "-C", "INPUT", "-s", clean_ip, "-j", "DROP"]
        res_c = _run_with_sudo_fallback(ctx, c_cmd, timeout=10)
        if res_c.ok:
            # Delete rule
            d_cmd = [ipt_bin, "-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
            res_d = _run_with_sudo_fallback(ctx, d_cmd, timeout=10)
            if res_d.ok:
                any_success = True
                messages.append(f"iptables: Deleted DROP rule for {clean_ip} from INPUT chain")
            else:
                messages.append(f"iptables: Failed to delete rule: {res_d.stderr or res_d.stdout}")
        else:
            messages.append(f"iptables: No direct DROP rule found for {clean_ip}")
    else:
        messages.append("iptables: binary not found, skipped")

    return any_success, messages


def ban_ip_unified(ctx: Context, ip: str, jail: Optional[str] = None, use_iptables: bool = False) -> Tuple[bool, str]:
    """Ban an IP either via iptables directly or via Fail2Ban with iptables fallback."""
    clean_ip = ip.strip()
    if not is_valid_ip(clean_ip):
        # Check if valid subnet
        try:
            ipaddress.ip_network(clean_ip, strict=False)
        except ValueError:
            return False, f"Invalid IP address or CIDR format: {ip}"

    # Protect loopback and whitelist
    whitelist = set(ctx.config.get("security.ip_whitelist", ["127.0.0.1", "::1"]))
    if clean_ip in whitelist:
        return False, f"IP {clean_ip} is in whitelist; refusing to ban"

    if use_iptables:
        ipt_bin = ctx.runner.which("iptables") or ctx.runner.which("/sbin/iptables") or ctx.runner.which("/usr/sbin/iptables")
        if not ipt_bin:
            return False, "iptables binary not found"
        # Check if already dropped
        res_c = _run_with_sudo_fallback(ctx, [ipt_bin, "-C", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_c.ok:
            return True, f"IP {clean_ip} is already blocked in iptables"
        res_i = _run_with_sudo_fallback(ctx, [ipt_bin, "-I", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_i.ok:
            return True, f"Successfully inserted DROP rule for {clean_ip} in iptables"
        return False, f"Failed to insert iptables DROP rule: {res_i.stderr or res_i.stdout}"

    # Default: Try Fail2Ban first, fallback to iptables if Fail2Ban is not available
    f_ok, f_msg = fail2ban.ban_ip(ctx, clean_ip, jail=jail)
    if f_ok:
        return True, f_msg

    # Fallback to direct iptables drop
    ipt_bin = ctx.runner.which("iptables") or ctx.runner.which("/sbin/iptables") or ctx.runner.which("/usr/sbin/iptables")
    if ipt_bin:
        res_c = _run_with_sudo_fallback(ctx, [ipt_bin, "-C", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_c.ok:
            return True, f"{f_msg}. Already dropped in iptables"
        res_i = _run_with_sudo_fallback(ctx, [ipt_bin, "-I", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_i.ok:
            return True, f"{f_msg}. Fallback: Successfully dropped in iptables"
        return False, f"Fail2Ban failed ({f_msg}) and iptables fallback failed: {res_i.stderr}"

    return False, f_msg

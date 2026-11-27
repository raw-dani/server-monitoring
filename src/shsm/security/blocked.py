"""Centralized blocked IP aggregator and manager (Fail2Ban + CSF + ipset + iptables)."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from shsm.core.context import Context
from shsm.core.subprocesses import Runner
from shsm.security import fail2ban
from shsm.security.fail2ban import _run_with_sudo_fallback, is_valid_ip
from shsm.security.firewall import detect_active_firewall, find_firewall_binary

log = logging.getLogger(__name__)
_IPSET_INIT_CACHE: Dict[str, float] = {}

# Official Cloudflare IPv4/IPv6 edge ranges so local firewall never blocks proxy traffic.
_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)
_CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(c) for c in _CLOUDFLARE_CIDRS)
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

_IPSET_V4 = "shsm_blacklist"
_IPSET_V6 = "shsm_blacklist_v6"


def _read_csf_whitelist_entries(paths: Tuple[str, ...] = ("/etc/csf/csf.allow", "/etc/csf/csf.ignore")) -> Set[str]:
    """Read IP/CIDR entries from CSF allow/ignore files when readable."""
    entries: Set[str] = set()
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    # Ignore advanced CSF filter syntax like 'tcp|in|d=22|s=1.2.3.4' unless simple IP/CIDR
                    token = line.split()[0]
                    if "|" not in token:
                        entries.add(token)
        except OSError:
            continue
    return entries


def get_protected_whitelist(ctx: Context) -> Set[str]:
    """Build full set of protected local, configured, and CSF-whitelisted IPs/CIDRs."""
    whitelist = set(str(x).strip() for x in ctx.config.get("security.ip_whitelist", ["127.0.0.1", "::1"]))
    cfg_ip = ctx.config.get("security.server_public_ip")
    if cfg_ip:
        whitelist.add(str(cfg_ip).strip())
    if type(ctx.runner) is Runner:
        whitelist.update(_read_csf_whitelist_entries())
    try:
        hostname = socket.gethostname()
        for host_ip in socket.gethostbyname_ex(hostname)[2]:
            whitelist.add(host_ip)
    except Exception:
        pass
    return whitelist


def is_protected_ip(ctx: Context, ip: str, whitelist: Optional[Set[str]] = None) -> Tuple[bool, str]:
    """Return (True, reason) if IP must never be locally banned (loopback, whitelist/CIDR, RFC1918, Cloudflare)."""
    clean_ip = ip.strip()
    wl = whitelist if whitelist is not None else get_protected_whitelist(ctx)
    if clean_ip in wl or clean_ip.startswith("127."):
        return True, "in whitelist or loopback"

    try:
        target = ipaddress.ip_network(clean_ip, strict=False) if "/" in clean_ip else ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, ""

    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        # Check CIDR subnets stored in security.ip_whitelist or csf.allow (e.g. 182.253.122.0/24)
        for entry in wl:
            if "/" in entry:
                try:
                    wl_net = ipaddress.ip_network(entry, strict=False)
                    if target.version == wl_net.version and target in wl_net:
                        return True, f"in whitelisted subnet {entry}"
                except ValueError:
                    continue
        if target.is_loopback:
            return True, "loopback address"
        for priv_net in _RFC1918_NETWORKS:
            if target.version == priv_net.version and target in priv_net:
                return True, "private/link-local network"
        if bool(ctx.config.get("security.protect_cloudflare_ips", True)):
            for cf_net in _CLOUDFLARE_NETWORKS:
                if target.version == cf_net.version and target in cf_net:
                    return True, "Cloudflare edge proxy IP"

    return False, ""


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


def get_ipset_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve blocked IPs stored in SHSM ipset hash tables."""
    ipset_bin = ctx.runner.which("ipset") or ctx.runner.which("/sbin/ipset") or ctx.runner.which("/usr/sbin/ipset")
    if not ipset_bin:
        return []

    results: List[Dict[str, Any]] = []
    for set_name in (_IPSET_V4, _IPSET_V6):
        res = _run_with_sudo_fallback(ctx, [ipset_bin, "list", set_name], timeout=6)
        if not res.ok or not res.stdout:
            continue
        in_members = False
        for line in res.stdout.splitlines():
            s = line.strip()
            if s == "Members:":
                in_members = True
                continue
            if not in_members or not s:
                continue
            parts = s.split()
            ip_val = parts[0]
            if is_valid_ip(ip_val):
                ttl_note = " ".join(parts[1:]) if len(parts) > 1 else "ipset"
                results.append({
                    "source": "ipset",
                    "target": ip_val,
                    "jail_or_chain": set_name,
                    "packets": "-",
                    "bytes": "-",
                    "note": ttl_note,
                })
    return results


def get_ufw_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve DENY rules from UFW if active."""
    ufw_bin = ctx.runner.which("ufw") or ctx.runner.which("/usr/sbin/ufw")
    if not ufw_bin:
        return []
    res = _run_with_sudo_fallback(ctx, [ufw_bin, "status"], timeout=8)
    if not res.ok or not res.stdout or "status: active" not in res.stdout.lower():
        return []
    results: List[Dict[str, Any]] = []
    for line in res.stdout.splitlines():
        if "DENY" not in line:
            continue
        parts = line.split()
        # Format: "Anywhere  DENY  1.2.3.4" or "Anywhere (v6)  DENY  2001:..."
        for tok in parts:
            cand = tok.strip()
            if "/" in cand:
                try:
                    ipaddress.ip_network(cand, strict=False)
                    results.append({
                        "source": "ufw",
                        "target": cand,
                        "jail_or_chain": "ufw",
                        "packets": "-",
                        "bytes": "-",
                        "note": "UFW DENY",
                    })
                    break
                except ValueError:
                    continue
            elif is_valid_ip(cand):
                results.append({
                    "source": "ufw",
                    "target": cand,
                    "jail_or_chain": "ufw",
                    "packets": "-",
                    "bytes": "-",
                    "note": "UFW DENY",
                })
                break
    return results


def get_firewalld_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve drop/reject rich rules from Firewalld if running."""
    fw_bin = ctx.runner.which("firewall-cmd") or ctx.runner.which("/usr/bin/firewall-cmd")
    if not fw_bin:
        return []
    res = _run_with_sudo_fallback(ctx, [fw_bin, "--list-rich-rules"], timeout=8)
    if not res.ok or not res.stdout:
        return []
    results: List[Dict[str, Any]] = []
    for line in res.stdout.splitlines():
        if ("drop" in line or "reject" in line) and "source address=" in line:
            m = re.search(r'source address="([^"]+)"', line)
            if m:
                results.append({
                    "source": "firewalld",
                    "target": m.group(1),
                    "jail_or_chain": "firewalld",
                    "packets": "-",
                    "bytes": "-",
                    "note": "Firewalld rich rule",
                })
    return results


def get_csf_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Retrieve permanently/temporarily blocked IPs & CIDRs from CSF (DENYIN/LOCALINPUT & deny files)."""
    csf_bin = find_firewall_binary(ctx, "csf", ("/usr/sbin/csf", "/usr/local/sbin/csf", "/sbin/csf"))
    if not csf_bin:
        return []

    results: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    # 1. Inspect CSF iptables/ip6tables chains (DENYIN = permanent, LOCALINPUT = tempban)
    # Works for user 'shsm' via sudoers ('iptables -L *' / 'ip6tables -L *') without invoking slow Perl 'csf -l'.
    for tool_name in ("iptables", "ip6tables"):
        ipt_bin = find_firewall_binary(ctx, tool_name, (f"/sbin/{tool_name}", f"/usr/sbin/{tool_name}", f"/usr/bin/{tool_name}"))
        if not ipt_bin:
            continue
        for chain in ("DENYIN", "LOCALINPUT"):
            res = _run_with_sudo_fallback(ctx, [ipt_bin, "-L", chain, "-n", "-v"], timeout=8)
            if not res.ok or not res.stdout:
                continue
            lines = res.stdout.splitlines()
            if not any(ln.strip().startswith(f"Chain {chain}") for ln in lines[:3]):
                continue
            for line in lines:
                s = line.strip()
                if not s or s.startswith("Chain") or s.startswith("pkts"):
                    continue
                parts = s.split()
                if len(parts) >= 8 and parts[2] == "DROP":
                    source_ip = parts[7]
                    if source_ip in ("0.0.0.0/0", "::/0"):
                        continue
                    key = (source_ip, chain)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "source": "csf",
                        "target": source_ip,
                        "jail_or_chain": chain,
                        "packets": parts[0],
                        "bytes": parts[1],
                        "note": "CSF perm deny" if chain == "DENYIN" else "CSF temp deny",
                    })

    # 2. Fallback/supplement from CSF deny files when readable (e.g. when running as root)
    if type(ctx.runner) is Runner:
        existing_targets = {x["target"] for x in results}
        for path, chain_label, note in (
            ("/etc/csf/csf.deny", "csf.deny", "CSF perm deny"),
            ("/var/lib/csf/csf.tempban", "csf.tempban", "CSF temp deny"),
        ):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        line = raw.split("#", 1)[0].strip()
                        if not line or line.lower().startswith("include "):
                            continue
                        token = line.split("|", 1)[0].split()[0].strip()
                        if not token or token in existing_targets:
                            continue
                        if is_valid_ip(token) or "/" in token:
                            existing_targets.add(token)
                            results.append({
                                "source": "csf",
                                "target": token,
                                "jail_or_chain": chain_label,
                                "packets": "-",
                                "bytes": "-",
                                "note": note,
                            })
            except OSError:
                continue

    return results


def list_all_blocked(ctx: Context) -> List[Dict[str, Any]]:
    """Return unified list of all blocked IPs/subnets from Fail2Ban, CSF, ipset, UFW, Firewalld, and iptables."""
    f2b_list = get_fail2ban_blocked(ctx)
    csf_list = get_csf_blocked(ctx)
    ipt_list = get_iptables_blocked(ctx)
    ipset_list = get_ipset_blocked(ctx)
    ufw_list = get_ufw_blocked(ctx)
    fwd_list = get_firewalld_blocked(ctx)
    return f2b_list + csf_list + ipset_list + ufw_list + fwd_list + ipt_list


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

    # 2. Check and remove from ipset if present
    ipset_bin = find_firewall_binary(ctx, "ipset", ("/sbin/ipset", "/usr/sbin/ipset", "/usr/bin/ipset"))
    if ipset_bin and "/" not in clean_ip:
        set_name = _IPSET_V6 if ":" in clean_ip else _IPSET_V4
        res_del = _run_with_sudo_fallback(ctx, [ipset_bin, "del", set_name, clean_ip], timeout=6)
        if res_del.ok:
            any_success = True
            messages.append(f"ipset: Removed {clean_ip} from {set_name}")

    # 3. Check and remove from CSF deny/tempban if available
    csf_bin = find_firewall_binary(ctx, "csf", ("/usr/sbin/csf", "/usr/local/sbin/csf", "/sbin/csf"))
    if csf_bin:
        res_tr = _run_with_sudo_fallback(ctx, [csf_bin, "-tr", clean_ip], timeout=10)
        res_dr = _run_with_sudo_fallback(ctx, [csf_bin, "-dr", clean_ip], timeout=10)
        if res_tr.ok or res_dr.ok:
            any_success = True
            messages.append(f"CSF: Removed {clean_ip} from temp/permanent deny")

    # 4. Check and remove from UFW / Firewalld if active
    ufw_bin = find_firewall_binary(ctx, "ufw", ("/usr/sbin/ufw", "/usr/bin/ufw"))
    if ufw_bin:
        res_ufw = _run_with_sudo_fallback(ctx, [ufw_bin, "delete", "deny", "from", clean_ip], timeout=10)
        if res_ufw.ok and "deleted" in (res_ufw.stdout or "").lower():
            any_success = True
            messages.append(f"UFW: Deleted deny rule for {clean_ip}")

    fw_bin = find_firewall_binary(ctx, "firewall-cmd", ("/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"))
    if fw_bin:
        fam = "ipv6" if ":" in clean_ip else "ipv4"
        rich_rule = f'rule family="{fam}" source address="{clean_ip}" drop'
        res_fw = _run_with_sudo_fallback(ctx, [fw_bin, f"--remove-rich-rule={rich_rule}"], timeout=10)
        if res_fw.ok and "success" in (res_fw.stdout or "").lower():
            any_success = True
            messages.append(f"Firewalld: Removed rich rule for {clean_ip}")

    # 5. Check and remove from iptables/ip6tables INPUT DROP rules
    is_v6_u = ":" in clean_ip
    u_tool = "ip6tables" if is_v6_u else "iptables"
    ipt_bin = ctx.runner.which(u_tool) or ctx.runner.which(f"/sbin/{u_tool}") or ctx.runner.which(f"/usr/sbin/{u_tool}")
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
                messages.append(f"{u_tool}: Deleted DROP rule for {clean_ip} from INPUT chain")
            else:
                messages.append(f"{u_tool}: Failed to delete rule: {res_d.stderr or res_d.stdout}")
        else:
            messages.append(f"{u_tool}: No direct DROP rule found for {clean_ip}")
    else:
        messages.append(f"{u_tool}: binary not found, skipped")

    return any_success, messages


def _ban_via_csf(ctx: Context, clean_ip: str, ttl_seconds: int, reason: str) -> Tuple[bool, str]:
    """Apply block via CSF tempban (-td) or permanent deny (-d)."""
    backend = str(ctx.config.get("security.firewall_backend", "auto")).lower()
    if backend not in ("auto", "csf"):
        return False, "csf backend disabled"
    csf_bin = find_firewall_binary(ctx, "csf", ("/usr/sbin/csf", "/usr/local/sbin/csf", "/sbin/csf"))
    if not csf_bin:
        return False, "csf binary not found"
    if ttl_seconds > 0:
        cmd = [csf_bin, "-td", clean_ip, str(ttl_seconds), reason]
    else:
        cmd = [csf_bin, "-d", clean_ip, reason]
    res = _run_with_sudo_fallback(ctx, cmd, timeout=10)
    if res.ok:
        return True, f"CSF blocked {clean_ip} (TTL: {ttl_seconds}s)"
    return False, f"CSF ban failed: {res.stderr or res.stdout}"


def _ipset_insert_position(ctx: Context, ipt_bin: str) -> str:
    """Return iptables INPUT insert index: right after CSF LOCALINPUT/ALLOWIN if present, else '1'."""
    if type(ctx.runner) is not Runner:
        return "1"
    res = _run_with_sudo_fallback(ctx, [ipt_bin, "-L", "INPUT", "--line-numbers", "-n"], timeout=6)
    if res.ok and res.stdout:
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit() and parts[1] in ("LOCALINPUT", "ALLOWIN"):
                return str(int(parts[0]) + 1)
    return "1"


def _ban_via_ipset(ctx: Context, clean_ip: str, ttl_seconds: int) -> Tuple[bool, str]:
    """Insert IP into O(1) kernel ipset hash table and ensure iptables match rule exists."""
    if not bool(ctx.config.get("security.ipset_enabled", True)) or "/" in clean_ip:
        return False, "ipset disabled or CIDR target"
    ipset_bin = find_firewall_binary(ctx, "ipset", ("/sbin/ipset", "/usr/sbin/ipset", "/usr/bin/ipset"))
    if not ipset_bin:
        return False, "ipset binary not found"

    is_v6 = ":" in clean_ip
    set_name = _IPSET_V6 if is_v6 else _IPSET_V4
    family = "inet6" if is_v6 else "inet"
    tool_name = "ip6tables" if is_v6 else "iptables"
    ipt_bin = find_firewall_binary(ctx, tool_name, (f"/sbin/{tool_name}", f"/usr/sbin/{tool_name}", f"/usr/bin/{tool_name}"))
    if not ipt_bin:
        return False, f"{tool_name} binary not found"

    # Cache ipset table creation & iptables hook verification for 60s on real hosts
    # so burst bans execute only a single O(1) 'ipset add' (~2ms).
    now_mono = time.monotonic()
    need_init = type(ctx.runner) is not Runner or (now_mono - _IPSET_INIT_CACHE.get(set_name, 0.0)) >= 60.0
    if need_init:
        create_cmd = [ipset_bin, "create", set_name, "hash:ip", "family", family, "timeout", str(max(60, ttl_seconds)), "-exist"]
        res_create = _run_with_sudo_fallback(ctx, create_cmd, timeout=6)
        if not res_create.ok:
            return False, f"ipset create failed: {res_create.stderr or res_create.stdout}"

        chk_cmd = [ipt_bin, "-C", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP"]
        if not _run_with_sudo_fallback(ctx, chk_cmd, timeout=6).ok:
            pos = _ipset_insert_position(ctx, ipt_bin)
            ins_cmd = [ipt_bin, "-I", "INPUT", pos, "-m", "set", "--match-set", set_name, "src", "-j", "DROP"]
            res_ins = _run_with_sudo_fallback(ctx, ins_cmd, timeout=6)
            if not res_ins.ok:
                return False, f"iptables ipset hook failed: {res_ins.stderr or res_ins.stdout}"
        if type(ctx.runner) is Runner:
            _IPSET_INIT_CACHE[set_name] = now_mono

    add_cmd = [ipset_bin, "add", set_name, clean_ip, "timeout", str(max(60, ttl_seconds)), "-exist"]
    res_add = _run_with_sudo_fallback(ctx, add_cmd, timeout=6)
    if res_add.ok:
        return True, f"Inserted {clean_ip} into O(1) ipset '{set_name}' (TTL: {ttl_seconds}s)"
    return False, f"ipset add failed: {res_add.stderr or res_add.stdout}"


def _ban_via_ufw(ctx: Context, clean_ip: str, reason: str) -> Tuple[bool, str]:
    """Insert top-priority DENY rule in UFW if UFW is active."""
    backend = str(ctx.config.get("security.firewall_backend", "auto")).lower()
    if backend not in ("auto", "ufw"):
        return False, "ufw backend disabled"
    ufw_bin = find_firewall_binary(ctx, "ufw", ("/usr/sbin/ufw", "/usr/bin/ufw"))
    if not ufw_bin:
        return False, "ufw binary not found"
    st = _run_with_sudo_fallback(ctx, [ufw_bin, "status"], timeout=6)
    if not st.ok or "status: active" not in (st.stdout or "").lower():
        return False, "ufw not active"
    res = _run_with_sudo_fallback(ctx, [ufw_bin, "insert", "1", "deny", "from", clean_ip, "comment", reason[:64]], timeout=10)
    if res.ok:
        return True, f"UFW inserted DENY rule for {clean_ip}"
    return False, f"UFW ban failed: {res.stderr or res.stdout}"


def _ban_via_firewalld(ctx: Context, clean_ip: str, ttl_seconds: int) -> Tuple[bool, str]:
    """Insert temporary rich drop rule in Firewalld if active."""
    backend = str(ctx.config.get("security.firewall_backend", "auto")).lower()
    if backend not in ("auto", "firewalld"):
        return False, "firewalld backend disabled"
    fw_bin = find_firewall_binary(ctx, "firewall-cmd", ("/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"))
    if not fw_bin:
        return False, "firewall-cmd binary not found"
    st = _run_with_sudo_fallback(ctx, [fw_bin, "--state"], timeout=6)
    if not st.ok or "running" not in (st.stdout or "").lower():
        return False, "firewalld not running"
    fam = "ipv6" if ":" in clean_ip else "ipv4"
    rich_rule = f'rule family="{fam}" source address="{clean_ip}" drop'
    cmd = [fw_bin, f"--add-rich-rule={rich_rule}"]
    if ttl_seconds > 0:
        cmd.append(f"--timeout={ttl_seconds}s")
    res = _run_with_sudo_fallback(ctx, cmd, timeout=10)
    if res.ok:
        return True, f"Firewalld blocked {clean_ip} (TTL: {ttl_seconds}s)"
    return False, f"Firewalld ban failed: {res.stderr or res.stdout}"


def ban_ip_cloudflare(ctx: Context, clean_ip: str, reason: str = "SHSM Auto-Block") -> Tuple[bool, str]:
    """Push IP block rule to Cloudflare WAF Access Rules if enabled and configured."""
    if not bool(ctx.config.get("security.cloudflare_enabled", False)):
        return False, "cloudflare integration disabled"
    zone_id = str(ctx.config.get("security.cloudflare_zone_id", "")).strip()
    token = ctx.config.secret("cloudflare_token")
    if not zone_id or not token:
        return False, "cloudflare zone_id or token missing"
    try:
        import requests
        resp = requests.post(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"mode": "block", "configuration": {"target": "ip", "value": clean_ip}, "notes": reason[:120]},
            timeout=5,
        )
        if resp.status_code in (200, 201):
            return True, f"Cloudflare WAF blocked {clean_ip}"
        return False, f"Cloudflare API HTTP {resp.status_code}"
    except Exception as exc:
        return False, f"Cloudflare API error: {exc}"


def ban_ip_unified(
    ctx: Context,
    ip: str,
    jail: Optional[str] = None,
    use_iptables: bool = False,
    ttl_seconds: Optional[int] = None,
    reason: Optional[str] = None,
) -> Tuple[bool, str]:
    """Ban an IP via CSF/ipset/iptables (kernel fast drop) or Fail2Ban with fallback."""
    clean_ip = ip.strip()
    if not is_valid_ip(clean_ip):
        try:
            ipaddress.ip_network(clean_ip, strict=False)
        except ValueError:
            return False, f"Invalid IP address or CIDR format: {ip}"

    protected, prot_reason = is_protected_ip(ctx, clean_ip)
    if protected:
        return False, f"IP {clean_ip} is protected ({prot_reason}); refusing to ban"

    ttl = int(ctx.config.get("security.ddos_ban_ttl_seconds", 3600)) if ttl_seconds is None else int(ttl_seconds)
    ban_reason = reason or "SHSM auto-mitigation"
    is_v6 = ":" in clean_ip
    tool_name = "ip6tables" if is_v6 else "iptables"

    def _apply_kernel_ban(prefix: str = "") -> Tuple[bool, str]:
        # Prefer O(1) C-speed ipset (~2ms) before Perl/Python firewall CLIs (~1000ms CSF Perl CPU burn)
        attempts: List[Any] = [lambda: _ban_via_ipset(ctx, clean_ip, ttl)]
        fw_name, fw_active, _ = detect_active_firewall(ctx)
        if fw_name == "csf" and fw_active:
            attempts.append(lambda: _ban_via_csf(ctx, clean_ip, ttl, ban_reason))
        elif fw_name == "ufw" and fw_active:
            attempts.append(lambda: _ban_via_ufw(ctx, clean_ip, ban_reason))
        elif fw_name == "firewalld" and fw_active:
            attempts.append(lambda: _ban_via_firewalld(ctx, clean_ip, ttl))
        else:
            attempts.extend([
                lambda: _ban_via_csf(ctx, clean_ip, ttl, ban_reason),
                lambda: _ban_via_ufw(ctx, clean_ip, ban_reason),
                lambda: _ban_via_firewalld(ctx, clean_ip, ttl),
            ])

        for fn in attempts:
            ok_b, msg_b = fn()
            if ok_b:
                return True, f"{prefix}{msg_b}"

        ipt_bin = find_firewall_binary(ctx, tool_name, (f"/sbin/{tool_name}", f"/usr/sbin/{tool_name}", f"/usr/bin/{tool_name}"))
        if not ipt_bin:
            return False, f"{tool_name} binary not found"
        res_c = _run_with_sudo_fallback(ctx, [ipt_bin, "-C", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_c.ok:
            return True, f"{prefix}IP {clean_ip} is already blocked in {tool_name}"
        res_i = _run_with_sudo_fallback(ctx, [ipt_bin, "-I", "INPUT", "-s", clean_ip, "-j", "DROP"])
        if res_i.ok:
            return True, f"{prefix}Successfully inserted DROP rule for {clean_ip} in {tool_name}"
        return False, f"Failed to insert {tool_name} DROP rule: {res_i.stderr or res_i.stdout}"

    if use_iptables:
        return _apply_kernel_ban()

    # Default: Try Fail2Ban first, fallback to detected firewall / ipset / iptables
    f_ok, f_msg = fail2ban.ban_ip(ctx, clean_ip, jail=jail)
    if f_ok:
        return True, f_msg

    ok_fb, msg_fb = _apply_kernel_ban(prefix=f"{f_msg}. Fallback: ")
    if ok_fb:
        return True, msg_fb
    return False, f"Fail2Ban failed ({f_msg}) and {msg_fb}"

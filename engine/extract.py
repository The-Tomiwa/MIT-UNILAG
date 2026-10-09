"""Regex-based indicator extraction from analysis text."""

import ipaddress
import re

RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
RE_MD5 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
RE_IPV4 = re.compile(
    r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::(\d{1,5}))?(?![\d.])"
)
RE_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'<>|;`)]+", re.I)
RE_DOMAIN = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|cn|io|info|xyz|top|biz|cc|tk|pw|su|me|in|de|uk|fr|nl|br|ir|kr|jp|tw|vn|online|site|club|live|app|dev|link))\b",
    re.I,
)
RE_HTTP_REQ = re.compile(r"\b(GET|POST|PUT|HEAD)\s+(/\S*)\s+HTTP/1\.[01]")
RE_PATH = re.compile(
    r"(?<![\w.:/])(/(?:etc|tmp|var|data|system|proc|root|dev|usr|mnt|sys|bin|sbin|home|lib)(?:/[\w.%\-]+)*/?)"
)
RE_CRON = re.compile(r"^\s*((?:[\d*/,\-]+\s+){5}(?:wget|curl|cd|/|sh|busybox)[^\n]*)", re.M)
RE_UA = re.compile(r"(Mozilla/5\.0 \([^)]*\)[^\n]*|User-Agent:\s*\(\)\s*\{[^\n]*)")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_SIZE = re.compile(r"file size:\s*([\d,]+)\s*bytes", re.I)
RE_ENTRY = re.compile(r"entry point address:\s*(0x[0-9a-f]+)", re.I)

# Infrastructure seen in sandbox/lab environments that must NOT become IOCs.
NOISE_NETS = {
    "185.125.190.0/24": "Ubuntu NTP / Canonical connectivity-check",
    "91.189.91.0/24": "Canonical connectivity-check",
    "151.101.0.0/16": "Fastly CDN (fwupd)",
    "142.250.0.0/15": "Google infrastructure",
    "216.239.32.0/19": "Google NTP",
    "8.8.8.8/32": "Google public DNS (reachability check, not C2)",
    "8.8.4.4/32": "Google public DNS",
    "1.1.1.1/32": "Cloudflare public DNS",
}
NOISE_DOMAINS = (
    "microsoft.com", "windowsupdate.com", "digicert.com", "msftconnecttest.com",
    "schemas.xmlsoap.org", "launchpad.net", "ubuntu.com", "canonical.com",
    "fwupd.org", "google.com", "gstatic.com", "googleapis.com", "any.run",
    "virustotal.com", "mitre.org", "github.com",
)

KNOWN_DEFAULT_CREDS = (
    "xc3511", "vizxv", "xmhdipc", "888888", "7ujMko0admin", "7ujMko0vizxv", "smcadmin",
    "admin1234", "root1234", "juantech", "anko", "hi3518", "klv1234",
    "Zte521", "zlxx.", "GM8182", "realtek", "ikwb", "dreambox", "54321", "666666",
    "1001chin", "tl789", "hunt5759", "Administrator",
)


def _uniq(seq):
    seen, out = set(), []
    for item in seq:
        key = item.lower() if isinstance(item, str) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def classify_ip(ip):
    """Return (kind, note). kind in {'public', 'private', 'noise'}."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid", ""
    if addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_reserved:
        return "private", "lab / private address"
    for net, note in NOISE_NETS.items():
        if addr in ipaddress.ip_network(net):
            return "noise", note
    return "public", ""


def _is_noise_domain(host):
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in NOISE_DOMAINS)


def extract(text):
    """Extract indicators from free text. Returns a dict of lists."""
    sha256 = _uniq(h.lower() for h in RE_SHA256.findall(text))
    build_ids = {b.lower() for b in re.findall(r"BuildID\[\w+\]=([a-fA-F0-9]+)", text)}
    sha1 = _uniq(h.lower() for h in RE_SHA1.findall(text)
                 if h.lower() not in "".join(sha256) and h.lower() not in build_ids)
    md5 = _uniq(h.lower() for h in RE_MD5.findall(text) if h.lower() not in "".join(sha256 + sha1))

    ips, excluded = [], []
    seen_ip = {}
    for ip, port in RE_IPV4.findall(text):
        kind, note = classify_ip(ip)
        if kind == "invalid":
            continue
        key = (ip, port)
        if key in seen_ip:
            continue
        seen_ip[key] = True
        entry = {"ip": ip, "port": int(port) if port else None}
        if kind == "public":
            ips.append(entry)
        else:
            excluded.append({"value": ip + (f":{port}" if port else ""), "reason": note})

    urls, noise_urls = [], []
    for u in RE_URL.findall(text):
        u = u.rstrip(".,)]}'\"")
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0]
        kind, note = classify_ip(host) if RE_IPV4.fullmatch(host) else ("public", "")
        if kind in ("private", "noise") or _is_noise_domain(host):
            noise_urls.append({"value": u, "reason": note or "sandbox / benign service"})
        else:
            urls.append(u)
    urls = _uniq(urls)

    domains = _uniq(
        d.lower() for d in RE_DOMAIN.findall(text) if not _is_noise_domain(d)
    )

    http_requests = _uniq(f"{m} {p}" for m, p in RE_HTTP_REQ.findall(text))
    paths = _uniq(p.rstrip("/") or p for p in RE_PATH.findall(text))
    cron = _uniq(c.strip() for c in RE_CRON.findall(text))
    user_agents = _uniq(u.strip() for u in RE_UA.findall(text))
    cves = _uniq(c.upper() for c in RE_CVE.findall(text))
    creds = [c for c in KNOWN_DEFAULT_CREDS if re.search(r"(?<![\w])" + re.escape(c) + r"(?![\w])", text)]

    size = RE_SIZE.search(text)
    entry = RE_ENTRY.search(text)

    for n in noise_urls:
        excluded.append(n)

    return {
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "ips": ips,
        "urls": urls,
        "domains": domains,
        "http_requests": http_requests,
        "paths": paths,
        "cron": cron,
        "user_agents": user_agents,
        "cves": cves,
        "default_creds": creds,
        "file_size": int(size.group(1).replace(",", "")) if size else None,
        "entry_point": entry.group(1) if entry else None,
        "excluded": _uniq_dicts(excluded),
    }


def _uniq_dicts(items):
    seen, out = set(), []
    for d in items:
        if d["value"] not in seen:
            seen.add(d["value"])
            out.append(d)
    return out


def parse_elf(text):
    """Pull architecture facts out of `file` / `readelf -h` output."""
    t = text
    info = {"format": None, "bits": None, "endian": None, "arch": None,
            "linking": None, "stripped": None, "platform": "Embedded Linux / IoT",
            "pie": False, "interpreter": None}
    m = re.search(r"ELF (32|64)-bit (LSB|MSB)", t)
    if m or re.search(r"\bELF(32|64)\b", t):
        info["format"] = "ELF"
    if m:
        info["bits"] = int(m.group(1))
        info["endian"] = "little" if m.group(2) == "LSB" else "big"
    else:
        c = re.search(r"Class:\s*ELF(32|64)", t)
        if c:
            info["bits"] = int(c.group(1))
        if re.search(r"little endian", t, re.I):
            info["endian"] = "little"
        elif re.search(r"big endian", t, re.I):
            info["endian"] = "big"

    arch_map = [
        (r"\bAArch64\b", "ARM64"), (r"\bARM\b", "ARM"), (r"PowerPC", "PowerPC"),
        (r"\bMIPS\b", "MIPS"), (r"x86-64|X86-64|Advanced Micro Devices X86-64", "x86-64"),
        (r"Intel 80386|\bi386\b", "x86"), (r"\bSPARC\b", "SPARC"), (r"Motorola m?68k|\bm68k\b", "m68k"),
        (r"Renesas SH|SuperH", "SuperH"), (r"\bARC\b", "ARC"),
    ]
    mach = re.search(r"Machine:\s*([^\n]+)", t)
    haystack = (mach.group(1) if mach else "") + "\n" + (m.string[m.start():m.start() + 120] if m else "")
    for pat, name in arch_map:
        if re.search(pat, haystack):
            info["arch"] = name
            break
    if not info["arch"]:
        for pat, name in arch_map:
            if re.search(pat, t):
                info["arch"] = name
                break

    if re.search(r"statically linked", t, re.I):
        info["linking"] = "static"
    elif re.search(r"dynamically linked", t, re.I):
        info["linking"] = "dynamic"
    if re.search(r"not stripped", t, re.I):
        info["stripped"] = False
    elif re.search(r"\bstripped\b", t, re.I):
        info["stripped"] = True
    if re.search(r"\bpie executable\b|Position-Independent", t, re.I):
        info["pie"] = True
    interp = re.search(r"interpreter\s+(\S+?),?\s", t)
    if interp:
        info["interpreter"] = interp.group(1).rstrip(",")
    if (info["interpreter"] or "").startswith("/system/bin/linker") or re.search(r"android-tv|/data/local/tmp", t):
        info["platform"] = "Android (TV box / set-top)"
    return info

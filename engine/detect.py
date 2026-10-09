"""Detection package: YARA, Suricata and host-hunting commands."""

import re
import zlib

from . import rules


def _esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _rule_name(fw):
    fam = re.sub(r"[^A-Za-z0-9]", "", fw["identity"]["family"] or "Unknown") or "Unknown"
    tag = (fw["identity"]["sha256"] or "nohash")[:8]
    return f"GPONFW_{fam}_{tag}"


def _sid_base(fw):
    # deterministic per sample so regenerated rules keep their SIDs
    return 9100000 + (zlib.crc32((fw["identity"]["sha256"] or fw["identity"]["name"]).encode()) % 8900) * 100


def build_yara(fw):
    strings = []
    for i in fw["iocs"]:
        t, v = i["type"], i["value"]
        if t == "IP":
            strings.append(("ip", v.split(":")[0]))
            if ":" in v:
                strings.append(("c2", v))
        elif t in ("URL", "Domain"):
            strings.append(("net", v))
        elif t == "Exploit URI":
            strings.append(("exp", v.split("?")[0] if "invokefunction" not in v else "invokefunction"))
        elif t == "String":
            strings.append(("id", v))
        elif t == "Cron entry":
            strings.append(("cron", v[:60].strip()))
        elif t == "User-Agent" and v.lower().startswith("user-agent"):
            strings.append(("ua", "() { :; };"))
    for sym in re.findall(r"\b(telnet_scanner|killer_loop|install_persistence|spoof_process_name|l4resattack)\b",
                          " ".join(f["value"] for f in fw["static"]["findings"])):
        strings.append(("sym", sym))

    seen, uniq = set(), []
    for k, v in strings:
        if v not in seen and len(v) >= 4:
            seen.add(v)
            uniq.append((k, v))
    uniq = uniq[:24]
    if not uniq:
        return "// Not enough static strings recovered to build a meaningful YARA rule for this sample."

    counters, lines = {}, []
    for k, v in uniq:
        counters[k] = counters.get(k, 0) + 1
        lines.append(f'        ${k}{counters[k]} = "{_esc(v)}" ascii')
    n = len(uniq)
    need = n if n <= 2 else max(2, n // 3)
    ident = fw["identity"]
    body = "\n".join(lines)
    return f'''rule {_rule_name(fw)}
{{
    meta:
        description = "{_esc(ident['family'])} ({', '.join(ident['roles'])}) - generated from analysis notes"
        author = "GPON Malware Framework Generator"
        date = "{fw['meta']['generated_at'][:10]}"
        sha256 = "{ident['sha256'] or 'n/a'}"
        arch = "{ident['arch'] or 'unknown'}"
        confidence = "{ident['family_confidence']}"
    strings:
{body}
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and {"all of them" if need == n else f"{need} of them"}
}}'''


GENERIC_YARA = r'''rule GPONFW_Generic_GPON_Exploit_Template
{
    meta:
        description = "ELF carrying a GPON diag_Form exploit template (CVE-2018-10561/10562)"
        author = "GPON Malware Framework Generator"
    strings:
        $uri = "/GponForm/diag_Form" ascii nocase
        $img = "images/" ascii
        $inj1 = "XWebPageName=diag" ascii
        $inj2 = "dest_host=" ascii
        $dl1 = "wget" ascii
        $dl2 = "curl" ascii
    condition:
        uint32(0) == 0x464c457f and $uri and ($img or any of ($inj*)) and any of ($dl*)
}

rule GPONFW_Generic_MultiArch_Downloader
{
    meta:
        description = "ELF/script that fetches per-architecture bot binaries"
        author = "GPON Malware Framework Generator"
    strings:
        $a1 = ".arm7" ascii
        $a2 = ".mips" ascii
        $a3 = ".mpsl" ascii
        $a4 = ".x86" ascii
        $a5 = ".ppc" ascii
        $a6 = ".arm5" ascii
        $w1 = "wget " ascii
        $w2 = "tftp " ascii
        $w3 = "busybox" ascii
    condition:
        filesize < 2MB and 3 of ($a*) and any of ($w*)
}'''


def build_suricata(fw):
    sid = _sid_base(fw)
    out = []

    def rule(txt):
        nonlocal sid
        sid += 1
        out.append(txt.replace("__SID__", str(sid)))

    for v in fw["vector"]["vectors"]:
        rv = next(r for r in rules.VECTORS if r["id"] == v["id"])
        refs = "".join(f" reference:cve,{c[4:]};" for c in v["cves"])
        if rv.get("suricata_uri"):
            contents = " ".join(f'content:"{_esc(c)}"; nocase;' for c in rv["suricata_uri"])
            rule(f'alert http any any -> any any (msg:"GPONFW Exploit attempt - {v["name"]}"; '
                 f'flow:established,to_server; http.uri; {contents}{refs} '
                 f'classtype:attempted-admin; sid:__SID__; rev:1;)')
        if rv.get("header"):
            rule(f'alert http any any -> any any (msg:"GPONFW Exploit attempt - {v["name"]}"; '
                 f'flow:established,to_server; http.user_agent; content:"() {{"; {refs} '
                 f'classtype:attempted-admin; sid:__SID__; rev:1;)')
        if rv.get("suricata_body"):
            rule(f'alert http any any -> any any (msg:"GPONFW Exploit attempt - {v["name"]}"; '
                 f'flow:established,to_server; http.request_body; content:"{_esc(rv["suricata_body"])}";{refs} '
                 f'classtype:attempted-admin; sid:__SID__; rev:1;)')
        if rv.get("telnet"):
            rule('alert tcp $HOME_NET any -> $EXTERNAL_NET [23,2323] (msg:"GPONFW Outbound Telnet scanning from subscriber device"; '
                 'flags:S,12; threshold:type both, track by_src, count 30, seconds 60; '
                 'classtype:network-scan; sid:__SID__; rev:1;)')

    for i in fw["iocs"]:
        if i["type"] == "IP":
            ip, _, port = i["value"].partition(":")
            if port:
                rule(f'alert tcp $HOME_NET any -> {ip} {port} (msg:"GPONFW Connection to C2 {i["value"]}"; '
                     f'flow:to_server; classtype:trojan-activity; sid:__SID__; rev:1;)')
            else:
                rule(f'alert ip $HOME_NET any -> {ip} any (msg:"GPONFW Traffic to malware host {ip}"; '
                     f'classtype:trojan-activity; sid:__SID__; rev:1;)')
        elif i["type"] == "URL":
            m = re.match(r"^\w+://([^/:]+)(?::\d+)?(/[^?#]*)?", i["value"])
            if m and m.group(2):
                rule(f'alert http $HOME_NET any -> any any (msg:"GPONFW Payload download {_esc(m.group(2))}"; '
                     f'flow:established,to_server; http.host; content:"{_esc(m.group(1))}"; '
                     f'http.uri; content:"{_esc(m.group(2))}"; classtype:trojan-activity; sid:__SID__; rev:1;)')
        elif i["type"] == "Domain":
            rule(f'alert dns $HOME_NET any -> any any (msg:"GPONFW DNS lookup of {i["value"]}"; '
                 f'dns.query; content:"{_esc(i["value"])}"; nocase; classtype:trojan-activity; sid:__SID__; rev:1;)')

    ids = {b["id"] for b in fw["attack"]}
    if "ingress" in ids or "fileless" in ids:
        rule('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPONFW Embedded device fetching multi-arch bot binary"; '
             'flow:established,to_server; http.uri; pcre:"/\\.(arm[4-7]?|mips|mpsl|x86|x86_64|ppc|m68k|sh4|spc|arc)$/i"; '
             'classtype:trojan-activity; sid:__SID__; rev:1;)')
        rule('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPONFW ELF binary delivered over HTTP"; '
             'flow:established,to_client; file.data; content:"|7F 45 4C 46|"; startswith; '
             'classtype:trojan-activity; sid:__SID__; rev:1;)')
    return out


def build_hunt(fw):
    cmds = []
    android = fw["identity"]["platform"].startswith("Android")
    paths = [i["value"] for i in fw["iocs"] if i["type"] == "File path"]
    ips = [i["value"].split(":")[0] for i in fw["iocs"] if i["type"] == "IP"]
    if android:
        cmds.append("adb shell ls -la /data/local/tmp/")
        cmds.append("adb shell ps -A | grep -v -E '^(root|system|shell) .*(zygote|servicemanager)'")
        cmds.append("adb shell getprop | grep -i -E 'sysboot|preboot'")
        cmds.append("adb shell ls -la /proc/*/exe 2>/dev/null | grep -E 'data/local/tmp|deleted'")
    else:
        if paths:
            cmds.append("ls -la " + " ".join(sorted(set(paths))) + " 2>/dev/null")
        cmds.append("cat /var/spool/cron/crontabs/root /etc/crontabs/root /etc/cron.d/* 2>/dev/null | grep -E 'wget|curl|\\| *sh'")
        cmds.append("ls -la /proc/*/exe 2>/dev/null | grep -E '(deleted)|/tmp/|/var/run/|/dev/shm/'")
        cmds.append("ps w | grep -E 'kworker|\\.s$|/tmp/' | grep -v grep")
        cmds.append("netstat -antp 2>/dev/null | grep -E ':23 |:2323 |ESTABLISHED'")
    for ip in ips:
        cmds.append(f"netstat -an 2>/dev/null | grep {ip}")
    return cmds


def build_detections(fw):
    yara = build_yara(fw)
    if fw["vector"]["gpon_relevance"] == "direct" or any(b["id"] == "ingress" for b in fw["attack"]):
        yara += "\n\n" + GENERIC_YARA
    return {"yara": yara, "suricata": build_suricata(fw), "hunt": build_hunt(fw)}

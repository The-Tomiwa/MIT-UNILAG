"""Turns analysis notes into the 8-section GPON malware framework."""

import re
from datetime import datetime, timezone

from . import rules
from .detect import build_detections
from .extract import extract, parse_elf
from .playbook import build_playbook

VERSION = "1.0"

NOTABLE_STRINGS = [
    (r"\bklv123\b", "Mozi-style node identifier"),
    (r"\bLotus\b", "Possible campaign/build identifier"),
    (r"android-tv-[a-z]+", "Vo1d stage identifier"),
    (r"\.kworker\b", "Masquerade file name (fake kernel worker)"),
    (r"\bS99bot\b", "Init-script persistence name"),
    (r"\bbot\.service\b", "systemd persistence unit"),
    (r"[\w\-]+bins?\.sh\b|payload_v\d+\.sh", "Second-stage shell script name"),
]

PERSIST_PATH = re.compile(
    r"^/(etc/(rc\.local|init\.d|systemd|cron|crontabs|config|profile\.d)|var/spool/cron|root/\.|tmp/\.|tmp/bot|data/local/tmp|system/?$)"
)


def _lines_matching(text, pattern, limit=3):
    out = []
    for line in text.splitlines():
        if re.search(pattern, line, re.I):
            s = line.strip()
            out.append(s if len(s) <= 180 else s[:177] + "...")
            if len(out) >= limit:
                break
    return out


def _source(pattern, static, dynamic):
    s = bool(re.search(pattern, static, re.I))
    d = bool(re.search(pattern, dynamic, re.I))
    return "static + dynamic" if s and d else "static" if s else "dynamic" if d else None


def _match_vectors(static, dynamic):
    found = []
    for v in rules.VECTORS:
        pat = "|".join(v["patterns"])
        src = _source(pat, static, dynamic)
        if not src:
            continue
        found.append({
            "id": v["id"], "name": v["name"], "target": v["target"], "cves": v["cves"],
            "note": v.get("note"), "gpon": v.get("gpon", False), "telnet": v.get("telnet", False),
            "source": src, "evidence": _lines_matching(static + "\n" + dynamic, pat, 2),
        })
    return found


def _score_families(text, exploit_count):
    t = text + ("\n__MULTI_EXPLOIT__" if exploit_count >= 5 else "")
    scores = []
    for fam, sigs in rules.FAMILIES.items():
        total, why = 0, []
        for pat, weight, label in sigs:
            if re.search(pat, t, re.I):
                total += weight
                why.append({"signal": label, "weight": weight})
        if total:
            scores.append({"family": fam, "score": total, "evidence": why})
    scores.sort(key=lambda s: -s["score"])
    return scores


def _family_verdict(scores):
    if not scores:
        return "Unknown", "low", "No family signatures matched."
    top = scores[0]
    second = scores[1]["score"] if len(scores) > 1 else 0
    conf = "high" if top["score"] >= 6 else "moderate" if top["score"] >= 3 else "low"
    note = f"Top score {top['score']} vs next {second}."
    if top["score"] - second < 2 and second:
        conf = "low" if conf == "moderate" else "moderate"
        note += " Close runner-up - treat as ambiguous."
    if top["family"] == "Mirai" and top["score"] <= 1:
        note += " Only a sandbox reputation tag supports this; such tags are applied broadly to IoT bots."
    return top["family"], conf, note


def _behaviours(static, dynamic, ctx):
    hits = []
    for b in rules.BEHAVIOURS:
        derived = b.get("derived")
        src, evidence = None, []
        if derived == "vectors_exploit":
            if ctx["exploit_vectors"]:
                src = "static"
                evidence = [f"{len(ctx['exploit_vectors'])} exploit template(s): " +
                            ", ".join(v["name"].split(" ")[0] for v in ctx["exploit_vectors"][:6])]
        elif derived == "nonstd_port":
            ports = [f"{i['ip']}:{i['port']}" for i in ctx["iocs"]["ips"] if i["port"] and i["port"] not in (80, 443, 8080)]
            if ports:
                src, evidence = "static", ports
        elif derived == "worm":
            if ctx["exploit_vectors"] or ctx["telnet"]:
                src = "static"
                evidence = ["Embedded scanner/exploit logic targets other devices"]
        elif derived == "resource_hijack":
            if ctx["roles"] and ("Worm" in " ".join(ctx["roles"])) and not ctx["ddos"]:
                src = "inferred"
                evidence = ["Botnet enrolment; payload function unknown (low confidence)"]
        else:
            pat = "|".join(b["patterns"])
            src = _source(pat, static, dynamic)
            if src:
                evidence = _lines_matching(static + "\n" + dynamic, pat, 2)
        if not src:
            continue
        tactic, technique, tid = b["tactic"], b["technique"], b["tid"]
        if ctx["android"] and b.get("mobile"):
            technique, tid = b["mobile"]
        hits.append({"id": b["id"], "behaviour": b["name"], "tactic": tactic, "technique": technique,
                     "tid": tid, "source": src, "evidence": evidence})

    # A loader with a C2-looking IP implies (but does not prove) C2 + second-stage retrieval.
    ids = {h["id"] for h in hits}
    if any("loader" in r for r in ctx["roles"]) and ctx["iocs"]["ips"]:
        if "http_c2" not in ids:
            hits.append({"id": "http_c2", "behaviour": "C2 contact (hypothesised)", "tactic": "Command and Control",
                         "technique": "Application Layer Protocol (hypothesised)", "tid": "T1071", "source": "inferred",
                         "evidence": ["Embedded IP " + ctx["iocs"]["ips"][0]["ip"] + "; no traffic observed"]})
        if "ingress" not in ids:
            hits.append({"id": "ingress", "behaviour": "Second-stage retrieval (hypothesised)",
                         "tactic": "Command and Control", "technique": "Ingress Tool Transfer (hypothesised)",
                         "tid": "T1105", "source": "inferred",
                         "evidence": ["Small stripped binary + CPU fingerprinting = loader profile"]})
    order =["Initial Access", "Execution", "Persistence", "Defense Evasion", "Discovery",
             "Lateral Movement", "Command and Control", "Impact"]
    hits.sort(key=lambda h: order.index(h["tactic"]) if h["tactic"] in order else 99)
    return hits


def _roles(elf, iocs, vectors, beh_ids, text):
    roles = []
    exploit = [v for v in vectors if not v["telnet"]]
    if len(exploit) >= 2:
        roles.append("Multi-exploit worm")
    if any(v["telnet"] for v in vectors):
        roles.append("Telnet brute-force bot")
    if "ddos" in beh_ids:
        roles.append("DDoS bot")
    if "backdoor_listener" in beh_ids or (elf["platform"].startswith("Android") and "shell_exec" in beh_ids):
        roles.append("Backdoor")
    small = iocs["file_size"] and iocs["file_size"] < 60000
    if small and elf.get("stripped") and "sysinfo" in beh_ids and not {"cron", "initd", "systemd"} & beh_ids:
        roles.append("First-stage loader / dropper")
    if not roles:
        roles.append("Unclassified payload")
    return roles


def _dynamic_summary(dynamic):
    signals = []
    for sid, pat, label in rules.DYNAMIC_SIGNALS:
        if re.search(pat, dynamic, re.I):
            signals.append({"id": sid, "label": label, "evidence": _lines_matching(dynamic, pat, 1)})
    envs = []
    lines = dynamic.splitlines()
    for n, line in enumerate(lines):
        m = re.match(r"\s*((?:Local|Cloud)[^:]{0,80}):\s*(.*)", line)
        if m:
            note = m.group(2).strip()
            if not note:  # note is on the following lines - take the first meaningful one
                block = [l.strip() for l in lines[n + 1:n + 10] if l.strip()]
                block = block[:next((k for k, l in enumerate(block) if re.match(r"(Local|Cloud)", l)), len(block))]
                note = next((l for l in block if l.startswith("Result:")), None) or \
                    next((l[1:].strip() for l in block if l.startswith("-")), None) or \
                    next((l for l in block if not l.startswith(("$", "sudo", "timeout"))), "")
            envs.append({"environment": m.group(1).strip(), "note": note})
    ids = {s["id"] for s in signals}
    if not dynamic.strip():
        verdict = "No dynamic analysis supplied - all findings are static/inferred."
        level = "none"
    elif "no_traffic" in ids and "gating" in ids:
        verdict = ("Sample ran but produced no malicious network traffic; behaviour is most likely gated "
                   "(reachability/anti-emulation). Network IOCs remain static-derived.")
        level = "partial"
    elif "no_traffic" in ids or "failed_exec" in ids:
        verdict = "Dynamic runs did not confirm network behaviour; treat C2/payload IOCs as unconfirmed."
        level = "partial"
    elif "instability" in ids:
        verdict = "Execution was too aggressive to observe cleanly - itself a behavioural indicator."
        level = "partial"
    else:
        verdict = "Dynamic observations available."
        level = "observed"
    return {"signals": signals, "environments": envs, "verdict": verdict, "level": level}


def _build_iocs(static, dynamic, iocs, vectors, meta):
    out = []
    full = static + "\n" + dynamic

    def add(t, v, ctx, conf, src="static"):
        if not any(o["type"] == t and o["value"] == v for o in out):
            out.append({"type": t, "value": v, "context": ctx, "confidence": conf, "source": src})

    for h in iocs["sha256"]:
        line = next((l for l in full.splitlines() if h in l.lower()), "")
        if re.search(r"archive|\.zip", line, re.I):
            add("SHA256 (archive)", h, "Distribution archive", "high")
        else:
            add("SHA256 (sample)", h, "Analysed ELF sample", "high")
    for h in iocs["md5"]:
        add("MD5", h, "Hash from analysis notes", "high")

    for ip in iocs["ips"]:
        val = ip["ip"] + (f":{ip['port']}" if ip["port"] else "")
        in_url = any(ip["ip"] in u for u in iocs["urls"])
        ctx = "C2 endpoint (IP:port in binary)" if ip["port"] else "Payload host" if in_url else "IP string in binary"
        neg = re.search(re.escape(ip["ip"]) + r"[^\n]*", dynamic)
        dyn_lines = [l for l in dynamic.splitlines() if ip["ip"] in l]
        observed = any(not re.search(r"\bno\b|none|not|0 packets|grep", l, re.I) for l in dyn_lines)
        if observed:
            add("IP", val, ctx + " - observed in dynamic run", "high", "static + dynamic")
        else:
            note = " - not observed in dynamic runs" if neg else ""
            add("IP", val, ctx + note, "medium", "static")
    if meta.get("c2"):
        add("IP/Domain (analyst)", meta["c2"].strip(), "C2 supplied by analyst", "medium", "analyst")

    for u in iocs["urls"]:
        add("URL", u, "Second-stage payload URL", "medium")
    for d in iocs["domains"]:
        add("Domain", d, "Domain string in analysis", "medium")
    for v in vectors:
        if v["telnet"]:
            continue
        rv = next(r for r in rules.VECTORS if r["id"] == v["id"])
        if rv.get("uri"):
            add("Exploit URI", rv["uri"], v["name"] + (f" ({', '.join(v['cves'])})" if v["cves"] else ""), "high")
    for c in iocs["cron"]:
        add("Cron entry", c, "Persistence / auto re-infection", "high")
    for p in iocs["paths"]:
        if PERSIST_PATH.search(p):
            add("File path", p, "Persistence or staging location", "high")
    for ua in iocs["user_agents"]:
        if ua.lower().startswith("user-agent"):
            add("User-Agent", ua, "ShellShock exploit header", "high")
        else:
            add("User-Agent", ua, "Hard-coded UA (HTTP flood / scanning)", "low")
    for pat, label in NOTABLE_STRINGS:
        for m in sorted(set(re.findall(pat, static))):
            add("String", m, label, "medium")
    if iocs["default_creds"]:
        add("Credential list", ", ".join(iocs["default_creds"]), "Default credentials used for brute force", "high")
    return out


def _risk(vectors, beh_ids, iocs_list, family_conf, roles):
    factors = []

    def f(name, pts):
        if pts:
            factors.append({"factor": name, "points": pts})

    exploit = [v for v in vectors if not v["telnet"]]
    f(f"{len(exploit)} remote-exploit vector(s)", min(30, 4 * len(exploit)))
    f("GPON ONT exploit present", 10 if any(v["gpon"] for v in vectors) else 0)
    f("Telnet brute-force propagation", 15 if any(v["telnet"] for v in vectors) else 0)
    f("Self-propagating (worm)", 10 if "worm" in beh_ids else 0)
    persist = len({"cron", "initd", "systemd", "shell_profile", "openwrt_cfg", "boot_android"} & beh_ids)
    f(f"{persist} persistence mechanism(s)", min(15, 5 * persist))
    f("DDoS capability", 15 if "ddos" in beh_ids else 0)
    evasion = len({"anti_emu", "obfuscation", "masquerade", "fileless", "cleanup"} & beh_ids)
    f(f"{evasion} evasion technique(s)", min(10, 3 * evasion))
    f("Remote backdoor / command execution", 15 if "Backdoor" in roles else 0)
    f("Loader stage (enables later payloads)", 10 if any("loader" in r for r in roles) else 0)
    f("Network C2/payload IOC known", 5 if any(i["type"] in ("IP", "URL") for i in iocs_list) else 0)
    score = min(100, sum(x["points"] for x in factors))
    level = "Critical" if score >= 70 else "High" if score >= 50 else "Medium" if score >= 30 else "Low"
    return {"score": score, "level": level, "factors": factors,
            "note": f"Family confidence: {family_conf}. Score reflects capability, not observed impact."}


def generate(static_text="", dynamic_text="", meta=None):
    meta = {k: (v or "").strip() if isinstance(v, str) else v for k, v in (meta or {}).items()}
    static = static_text or ""
    dynamic = dynamic_text or ""
    if meta.get("exploit_url"):
        static += "\n" + meta["exploit_url"]
    full = static + "\n" + dynamic

    iocs = extract(full)
    elf = parse_elf(static)
    if meta.get("arch"):
        elf["arch_analyst"] = meta["arch"]
    vectors = _match_vectors(static, dynamic)
    exploit_vectors = [v for v in vectors if not v["telnet"]]
    android = elf["platform"].startswith("Android")

    scores = _score_families(full, len(exploit_vectors))
    family, fconf, fnote = _family_verdict(scores)

    ctx = {"exploit_vectors": exploit_vectors, "telnet": any(v["telnet"] for v in vectors),
           "iocs": iocs, "android": android, "roles": [], "ddos": False}
    beh = _behaviours(static, dynamic, ctx)
    beh_ids = {b["id"] for b in beh}
    roles = _roles(elf, iocs, vectors, beh_ids, full)
    ctx.update(roles=roles, ddos="ddos" in beh_ids)
    beh = _behaviours(static, dynamic, ctx)  # second pass for role-dependent rules
    beh_ids = {b["id"] for b in beh}

    sample_sha = meta.get("sha256") or next(
        (h for h in iocs["sha256"]
         if not re.search(r"archive|\.zip", next((l for l in full.splitlines() if h in l.lower()), ""), re.I)),
        iocs["sha256"][0] if iocs["sha256"] else None)

    gpon_direct = any(v["gpon"] for v in vectors)
    router_vectors = [v for v in vectors if not v["gpon"]]
    if gpon_direct:
        relevance = ("direct", "Carries the GPON diag_Form exploit - can compromise vulnerable ONTs directly.")
    elif android:
        relevance = ("none", "Targets Android TV boxes, not ISP CPE. Relevant only as a subscriber-side threat behind the ONT.")
    elif router_vectors:
        relevance = ("indirect", "No GPON exploit, but targets the same embedded/router class - ONTs with Telnet or "
                                 "web management exposed are at risk.")
    else:
        relevance = ("indirect", "No infection vector recovered (loader stage) - may deliver GPON-capable payloads.")

    iocs_list = _build_iocs(static, dynamic, iocs, vectors, meta)
    dyn = _dynamic_summary(dynamic)
    risk = _risk(vectors, beh_ids, iocs_list, fconf, roles)

    symbols = sorted(set(re.findall(
        r"\b(telnet_scanner|getRandomIP|killer_loop|start_killer|spoof_process_name|install_persistence|"
        r"initConnection|processCmd|l4resattack|vseattack|r6attack|SendUDP|SendHTTPHex|SendSTDHEX|sendHTTPtwo|"
        r"socket|bind|listen|accept|connect|fork|setsid|prctl|execl|system|dlopen|uname)\b", static)))
    file_line = next((l.strip() for l in static.splitlines() if re.search(r"\bELF (32|64)-bit", l)), None)

    static_findings = [f for f in [
        {"label": "File type", "value": file_line} if file_line else None,
        {"label": "Architecture", "value": " / ".join(str(x) for x in [elf["arch"], f"{elf['bits']}-bit" if elf["bits"] else None,
                                                                       f"{elf['endian']}-endian" if elf["endian"] else None] if x)},
        {"label": "Linking", "value": (elf["linking"] or "unknown") + (" (PIE)" if elf["pie"] else "")},
        {"label": "Symbols", "value": "stripped" if elf["stripped"] else "present (not stripped)" if elf["stripped"] is False else "unknown"},
        {"label": "Interpreter", "value": elf["interpreter"]} if elf["interpreter"] else None,
        {"label": "Entry point", "value": iocs["entry_point"]} if iocs["entry_point"] else None,
        {"label": "File size", "value": f"{iocs['file_size']:,} bytes"} if iocs["file_size"] else None,
        {"label": "Packer", "value": "UPX detected" if re.search(r"\bUPX!?\b", static) else "none detected in notes"},
        {"label": "Capability symbols/imports", "value": ", ".join(symbols)} if symbols else None,
        {"label": "Exploit request templates", "value": str(len(iocs["http_requests"]))} if iocs["http_requests"] else None,
        {"label": "CVE references", "value": ", ".join(sorted(set(iocs["cves"] + [c for v in vectors for c in v["cves"]])))}
        if (iocs["cves"] or any(v["cves"] for v in vectors)) else None,
        {"label": "Default credentials", "value": f"{len(iocs['default_creds'])} known defaults matched"} if iocs["default_creds"] else None,
    ] if f and f.get("value")]

    fw = {
        "meta": {"generator": "GPON Malware Framework Generator", "version": VERSION,
                 "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                 "source_report": meta.get("source_report")},
        "identity": {
            "name": meta.get("name") or (f"Sample {sample_sha[:12]}" if sample_sha else "Unnamed sample"),
            "sha256": sample_sha,
            "hashes": {"sha256": iocs["sha256"], "sha1": iocs["sha1"], "md5": iocs["md5"]},
            "platform": elf["platform"], "arch": elf.get("arch_analyst") or elf["arch"], "bits": elf["bits"],
            "endian": elf["endian"], "linking": elf["linking"], "stripped": elf["stripped"],
            "file_size": iocs["file_size"],
            "family": family, "family_confidence": fconf, "family_note": fnote, "family_scores": scores,
            "family_analyst": meta.get("family") or None,
            "roles": roles,
        },
        "vector": {
            "gpon_relevance": relevance[0], "gpon_summary": relevance[1],
            "vectors": vectors,
        },
        "static": {"findings": static_findings, "http_requests": iocs["http_requests"]},
        "dynamic": dyn,
        "iocs": iocs_list,
        "excluded": iocs["excluded"],
        "attack": beh,
        "risk": risk,
    }
    fw["detections"] = build_detections(fw)
    fw["operator"] = build_playbook(fw)
    return fw


# ---------------------------------------------------------------------------
# Cross-sample correlation (campaign view)
# ---------------------------------------------------------------------------
def correlate(frameworks):
    """frameworks: list of (sample_id, framework). Finds shared infrastructure/code."""
    keyed = {}
    for sid, fw in frameworks:
        keys = {}
        for i in fw["iocs"]:
            if i["type"] in ("IP", "URL", "Domain", "Cron entry", "String", "Exploit URI") and \
                    i["value"] not in ("/tmp/.kworker",):
                keys.setdefault(i["type"], set()).add(i["value"].split(":")[0] if i["type"] == "IP" else i["value"])
        if fw["identity"]["family"] != "Unknown":
            keys["Family"] = {fw["identity"]["family"]}
        keys["Architecture"] = {f'{fw["identity"]["arch"]} ({fw["identity"]["platform"]})'}
        keyed[sid] = keys

    ids = [sid for sid, _ in frameworks]
    links = []
    for a_i, a in enumerate(ids):
        for b in ids[a_i + 1:]:
            shared = {}
            for t in set(keyed[a]) & set(keyed[b]):
                common = sorted(keyed[a][t] & keyed[b][t])
                if common:
                    shared[t] = common
            if shared:
                strength = "strong" if ("IP" in shared or "URL" in shared or "Cron entry" in shared) else "weak"
                links.append({"a": a, "b": b, "shared": shared, "strength": strength})

    # union-find on strong links -> campaign clusters
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for l in links:
        if l["strength"] == "strong":
            parent[find(l["a"])] = find(l["b"])
    clusters = {}
    for i in ids:
        clusters.setdefault(find(i), []).append(i)

    vector_ids = [v["id"] for v in rules.VECTORS]
    matrix = []
    for vid in vector_ids:
        row = {"vector": next(v["name"] for v in rules.VECTORS if v["id"] == vid), "samples": {}}
        hit = False
        for sid, fw in frameworks:
            present = any(v["id"] == vid for v in fw["vector"]["vectors"])
            row["samples"][sid] = present
            hit = hit or present
        if hit:
            matrix.append(row)

    summary = [{"id": sid, "name": fw["identity"]["name"], "family": fw["identity"]["family"],
                "arch": fw["identity"]["arch"], "platform": fw["identity"]["platform"],
                "gpon": fw["vector"]["gpon_relevance"], "risk": fw["risk"]["level"],
                "score": fw["risk"]["score"], "roles": fw["identity"]["roles"]} for sid, fw in frameworks]
    return {"samples": summary, "links": links,
            "clusters": [c for c in clusters.values()], "vector_matrix": matrix}

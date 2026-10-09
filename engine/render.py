"""Markdown export of a generated framework."""


def _table(headers, rows):
    esc = lambda s: str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def to_markdown(fw):
    i, v, d, r = fw["identity"], fw["vector"], fw["dynamic"], fw["risk"]
    md = [f"# GPON Malware Framework - {i['name']}", "",
          f"_Generated {fw['meta']['generated_at']} by {fw['meta']['generator']} v{fw['meta']['version']}_", "",
          f"**Risk:** {r['level']} ({r['score']}/100) · **Priority:** {fw['operator']['priority']} · "
          f"**GPON relevance:** {v['gpon_relevance']}", ""]

    md += ["## 1. Sample identity", "", _table(["Field", "Value"], [
        ["SHA256", i["sha256"]], ["Platform", i["platform"]], ["Architecture", f"{i['arch']} {i['bits'] or ''}-bit {i['endian'] or ''}-endian"],
        ["Linking / symbols", f"{i['linking']} / {'stripped' if i['stripped'] else 'not stripped' if i['stripped'] is False else '?'}"],
        ["File size", f"{i['file_size']:,} bytes" if i["file_size"] else "-"],
        ["Family (engine)", f"{i['family']} - {i['family_confidence']} confidence"],
        ["Family (analyst)", i["family_analyst"] or "-"], ["Role", ", ".join(i["roles"])]]), "",
        f"_{i['family_note']}_", ""]

    md += ["## 2. Infection vector", "", v["gpon_summary"], ""]
    if v["vectors"]:
        md.append(_table(["Vector", "Target", "CVE", "Source"],
                         [[x["name"], x["target"], ", ".join(x["cves"]) or "-", x["source"]] for x in v["vectors"]]))
    else:
        md.append("No infection vector recovered from the analysis.")
    md.append("")

    md += ["## 3. Static findings", "", _table(["Finding", "Value"], [[f["label"], f["value"]] for f in fw["static"]["findings"]]), ""]

    md += ["## 4. Dynamic findings", "", f"**Assessment:** {d['verdict']}", ""]
    md += [f"- **{e['environment']}**: {e['note']}" for e in d["environments"]]
    md += [f"- {s['label']}" for s in d["signals"]] + [""]

    md += ["## 5. IOC pack", "", _table(["Type", "Indicator", "Context", "Confidence"],
                                        [[x["type"], x["value"], x["context"], x["confidence"]] for x in fw["iocs"]]), ""]
    if fw["excluded"]:
        md += ["Excluded as sandbox/lab noise: " + ", ".join(f"`{e['value']}`" for e in fw["excluded"]), ""]

    md += ["## 6. ATT&CK mapping", "", _table(["Tactic", "Technique", "ID", "Evidence"],
                                              [[a["tactic"], a["technique"], a["tid"], a["source"]] for a in fw["attack"]]), ""]

    md += ["## 7. Detection package", "", "### YARA", "```yara", fw["detections"]["yara"], "```", "",
           "### Suricata", "```", *fw["detections"]["suricata"], "```", "",
           "### Host hunting", "```sh", *fw["detections"]["hunt"], "```", ""]

    md += ["## 8. Operator framework (FTTH / ISP)", "", f"**Priority:** {fw['operator']['priority']}", ""]
    for p in fw["operator"]["phases"]:
        md += [f"### {p['phase']}", *[f"- {a}" for a in p["actions"]], ""]

    md += ["## Risk score breakdown", "", _table(["Factor", "Points"], [[f["factor"], f["points"]] for f in r["factors"]]),
           "", f"_{r['note']}_", ""]
    return "\n".join(md)

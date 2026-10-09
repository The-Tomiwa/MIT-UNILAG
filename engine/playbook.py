"""Operator framework: what an FTTH/ISP should do about this sample.

Actions are selected by the sample's vectors and behaviours, so a Telnet
Mirai loader, a GPON-exploiting worm and an Android TV backdoor each get a
different response plan.
"""


def build_playbook(fw):
    vectors = fw["vector"]["vectors"]
    beh = {b["id"] for b in fw["attack"]}
    rel = fw["vector"]["gpon_relevance"]
    android = fw["identity"]["platform"].startswith("Android")
    gpon = any(v["gpon"] for v in vectors)
    telnet = any(v["telnet"] for v in vectors)
    other = [v for v in vectors if not v["gpon"] and not v["telnet"]]
    ips = [i["value"] for i in fw["iocs"] if i["type"] == "IP"]
    urls = [i["value"] for i in fw["iocs"] if i["type"] == "URL"]
    persist_paths = [i["value"] for i in fw["iocs"] if i["type"] in ("File path", "Cron entry")]

    prevent, detect, contain, eradicate, recover = [], [], [], [], []

    # ---- Prevent / harden -------------------------------------------------
    if gpon:
        prevent += [
            "Push patched ONT firmware fixing CVE-2018-10561/10562 (auth bypass + diag_Form injection) via OMCI or the TR-069 ACS.",
            "Disable WAN-side web management on all ONTs (TCP 80/8080/443/8443); allow it only from the ISP management VLAN.",
            "Add an edge/BNG ACL dropping Internet-sourced HTTP to subscriber ONT management addresses.",
            "Add an IPS/WAF rule at the edge rejecting any request whose URI contains /GponForm/ or 'images/' after a form path.",
        ]
    if telnet:
        prevent += [
            "Disable Telnet (TCP 23/2323) on all CPE/ONTs through TR-069 and block inbound 23/2323 at the edge.",
            "Provision unique per-device admin passwords; the sample's wordlist targets factory defaults.",
        ]
    if other:
        targets = sorted({v["target"] for v in other})
        prevent.append("Audit the CPE/managed-device inventory for these targeted platforms and patch or replace: "
                       + "; ".join(targets) + ".")
        prevent.append("Close TR-064/UPnP (TCP 7547, 37215, 52869) on the WAN side of ISP-supplied CPE.")
    if android:
        prevent += [
            "This is not ISP CPE: publish subscriber guidance to avoid uncertified Android TV boxes and update firmware.",
            "Offer DNS-based protection (RPZ) for residential subscribers once Vo1d C2 domains are obtained from decrypted config/threat intel.",
        ]
    if not vectors and not android:
        prevent.append("Loader only: harden against the likely delivery paths (Telnet, GPON diag_Form, router web RCE) as a precaution.")

    # ---- Detect -------------------------------------------------------------
    detect.append("Deploy the generated Suricata rules on the BNG/aggregation mirror port and the YARA rules on firmware/binary collection points.")
    if telnet or gpon or other:
        detect.append("NetFlow/IPFIX: alert on subscriber IPs with high fan-out to TCP 23/2323/80/8080/7547 (worm scanning).")
    if gpon:
        detect.append("Monitor OLT/ONT alarms for unexpected reboots, CPU spikes or config changes on ONT models known to be vulnerable.")
    if ips or urls:
        detect.append("Alert on any subscriber traffic to: " + ", ".join(ips + urls) + ".")
    if "ddos" in beh:
        detect.append("Watch for outbound UDP/HTTP flood patterns from single subscribers (sudden upstream saturation).")
    if "anti_emu" in beh or fw["dynamic"]["level"] != "observed":
        detect.append("Network IOCs were not confirmed dynamically - prioritise behaviour-based rules (scanning, ELF downloads) over IP blocklists alone.")

    # ---- Contain ------------------------------------------------------------
    if not android:
        contain.append("Move affected subscriber ONTs/CPE to a walled-garden/quarantine VLAN; keep management access for remediation.")
    else:
        contain.append("Notify the affected subscriber; rate-limit or walled-garden the subscriber line if the device is attacking others.")
    if ips:
        contain.append("Null-route / firewall the C2 and payload hosts at the edge: " + ", ".join(i.split(":")[0] for i in ips) + ".")
    if urls:
        contain.append("Block the payload URL(s) at the transparent proxy / DNS layer so re-infection fetches fail.")
    if telnet or gpon or other:
        contain.append("Rate-limit or block outbound scanning (23/2323/80/8080) from the quarantined lines to stop worm propagation.")

    # ---- Eradicate ----------------------------------------------------------
    persist = {"cron", "initd", "systemd", "shell_profile", "openwrt_cfg", "boot_android"} & beh
    if persist:
        eradicate.append("A reboot alone is NOT sufficient - the sample installs persistence (" +
                         ", ".join(sorted(persist)) + "). Factory-reset and reflash firmware.")
        if persist_paths:
            eradicate.append("Verify removal of: " + "; ".join(persist_paths[:8]) + ".")
    else:
        eradicate.append("Reboot clears memory-resident IoT bots, but reflash firmware anyway and patch before reconnecting, "
                         "otherwise re-infection occurs within minutes.")
    eradicate.append("Rotate all device credentials (admin, Telnet/SSH, Wi-Fi) after reflash.")
    if android:
        eradicate.append("Android TV box: full firmware reflash from the vendor, or replace the device if unsupported.")

    # ---- Recover / lessons --------------------------------------------------
    recover += [
        "Restore service only after the device reports patched firmware and passes a WAN-side port check.",
        "Keep the line under enhanced monitoring for 14 days (re-infection indicators above).",
        "Share IOCs with the national CERT / MISP community and record the incident against the CPE model.",
    ]

    if rel == "direct":
        priority = "P1 - active GPON ONT exploitation capability"
    elif fw["risk"]["level"] in ("Critical", "High"):
        priority = "P2 - high-capability IoT threat to subscriber equipment"
    elif android:
        priority = "P3 - subscriber-side device threat (not ISP CPE)"
    else:
        priority = "P3 - monitor and harden"

    return {
        "priority": priority,
        "phases": [
            {"phase": "Prevent / harden", "actions": prevent},
            {"phase": "Detect", "actions": detect},
            {"phase": "Contain", "actions": contain},
            {"phase": "Eradicate", "actions": eradicate},
            {"phase": "Recover & report", "actions": recover},
        ],
    }

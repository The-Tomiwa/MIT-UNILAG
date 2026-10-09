"""Regression tests: the five analysed samples must keep producing the
classifications documented in the analysis reports."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import correlate, generate  # noqa: E402
from engine.extract import classify_ip, extract, parse_elf  # noqa: E402


def load(n):
    d = ROOT / "samples" / f"sample{n}"
    return generate((d / "static.txt").read_text(encoding="utf-8"),
                    (d / "dynamic.txt").read_text(encoding="utf-8"),
                    json.loads((d / "meta.json").read_text()))


@pytest.fixture(scope="module")
def fws():
    if not (ROOT / "samples" / "sample1").is_dir():
        pytest.skip("bundled samples not present")
    return {n: load(n) for n in range(1, 6)}


def test_families(fws):
    assert fws[1]["identity"]["family"] == "Mirai"
    assert fws[1]["identity"]["family_confidence"] == "high"
    assert fws[2]["identity"]["family_confidence"] == "low"          # reputation tag only
    assert fws[3]["identity"]["family"] == "Mozi"
    assert fws[4]["identity"]["family"] == "Vo1d"
    assert fws[5]["identity"]["family"] == "Mozi"


def test_architectures(fws):
    assert fws[3]["identity"]["arch"] == "PowerPC" and fws[3]["identity"]["endian"] == "big"
    assert fws[4]["identity"]["platform"].startswith("Android")
    assert fws[1]["identity"]["stripped"] is False and fws[2]["identity"]["stripped"] is True


def test_gpon_relevance(fws):
    assert fws[3]["vector"]["gpon_relevance"] == "direct"
    assert fws[5]["vector"]["gpon_relevance"] == "direct"
    assert fws[1]["vector"]["gpon_relevance"] == "indirect"
    assert fws[4]["vector"]["gpon_relevance"] == "none"
    assert fws[3]["operator"]["priority"].startswith("P1")


def test_sample5_extra_vectors(fws):
    ids = {v["id"] for v in fws[5]["vector"]["vectors"]}
    assert {"shellshock", "cisco_logon", "gpon"} <= ids
    assert "shellshock" not in {v["id"] for v in fws[3]["vector"]["vectors"]}


def test_c2_iocs(fws):
    vals = {i["value"] for i in fws[1]["iocs"]}
    assert "64.89.160.222:55487" in vals and "http://213.232.114.14/handshakebins.sh" in vals
    assert any(i["value"] == "178.132.198.200" for i in fws[3]["iocs"])


def test_noise_is_excluded(fws):
    for fw in fws.values():
        ioc_vals = " ".join(i["value"] for i in fw["iocs"])
        for noise in ("185.125.190", "91.189.91", "10.0.0.4", "8.8.8.8", "microsoft.com"):
            assert noise not in ioc_vals


def test_android_uses_mobile_attack_ids(fws):
    tids = {a["tid"] for a in fws[4]["attack"]}
    assert {"T1633", "T1406", "T1575"} <= tids


def test_loader_gets_hypothesised_techniques(fws):
    a = {x["tid"]: x["source"] for x in fws[2]["attack"]}
    assert a.get("T1105") == "inferred" and a.get("T1071") == "inferred"


def test_campaign_links_3_and_5_only(fws):
    c = correlate([(f"s{n}", fw) for n, fw in fws.items()])
    strong = [(l["a"], l["b"]) for l in c["links"] if l["strength"] == "strong"]
    assert strong == [("s3", "s5")]
    assert ["s3", "s5"] in [sorted(x) for x in c["clusters"]]


def test_yara_compiles(fws):
    yara = pytest.importorskip("yara")
    for fw in fws.values():
        yara.compile(source=fw["detections"]["yara"])


def test_extract_helpers():
    assert classify_ip("10.0.0.4")[0] == "private"
    assert classify_ip("185.125.190.56")[0] == "noise"
    assert classify_ip("178.132.198.200")[0] == "public"
    e = extract("wget http://1.2.3.4/x.sh ; POST /GponForm/diag_Form?images/ HTTP/1.1 CVE-2018-10561")
    assert e["urls"] == ["http://1.2.3.4/x.sh"] and e["cves"] == ["CVE-2018-10561"]
    assert parse_elf("ELF 32-bit MSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped")["arch"] == "MIPS"


def test_empty_input_is_safe():
    fw = generate("", "", {})
    assert fw["identity"]["family"] == "Unknown"
    assert fw["dynamic"]["level"] == "none"

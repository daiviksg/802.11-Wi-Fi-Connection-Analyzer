"""The `compare` command and the Python / C / tshark agreement report (SPEC.md 8)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from conftest import PUBLIC_DIR, SYNTHETIC_DIR

from wifi_analyzer import compare as cmp
from wifi_analyzer.cli import main

CAPTURES = [p for p in sorted(SYNTHETIC_DIR.glob("*.pcap")) if p.stem != "ethernet_dhcp"]
if (PUBLIC_DIR / "wpa-Induction.pcap").exists():
    CAPTURES.append(PUBLIC_DIR / "wpa-Induction.pcap")


# --- agreement arithmetic -----------------------------------------------------

def test_agreement_percentages():
    a = {1: {"type": 0, "seq": 5}, 2: {"type": 2, "seq": 6}}
    b = {1: {"type": 0, "seq": 5}, 2: {"type": 2, "seq": 7}}
    ag = cmp.agreement(a, b, fields=("type", "seq"))
    assert (ag.agree, ag.total, ag.percent) == (3, 4, 75.0)
    assert ag.per_field == {"type": [2, 2], "seq": [1, 2]}
    assert ag.disagreements == [(2, "seq", 6, 7)]


def test_missing_frame_counts_against_every_field():
    a = {1: {"type": 0, "seq": 1}, 2: {"type": 0, "seq": 2}}
    b = {1: {"type": 0, "seq": 1}}
    ag = cmp.agreement(a, b, fields=("type", "seq"))
    assert (ag.agree, ag.total, ag.percent) == (2, 4, 50.0)
    assert ag.only_in_a == [2] and ag.only_in_b == []


def test_none_equals_none_and_frame_filter():
    a = {1: {"sa": None}, 2: {"sa": "x"}}
    b = {1: {"sa": None}, 2: {"sa": "y"}}
    assert cmp.agreement(a, b, fields=("sa",)).percent == 50.0
    assert cmp.agreement(a, b, fields=("sa",), only={1}).percent == 100.0


def test_report_text_shows_percentages(monkeypatch):
    monkeypatch.setattr(cmp, "find_wifiparse", lambda explicit=None: None)
    monkeypatch.setattr(cmp, "find_tshark", lambda explicit=None: None)
    result = cmp.compare_capture(SYNTHETIC_DIR / "wpa2_connected.pcap")
    assert result["sources"] == ["python"]
    text = cmp.report_text(result)
    assert "Nothing to compare" in text and "skipped c" in text and "skipped tshark" in text

    # Python against itself: 100%, and the arithmetic shows up in the report.
    py = cmp.python_rows(SYNTHETIC_DIR / "wpa2_connected.pcap")
    ag = cmp.agreement(py, py)
    result["pairs"] = [{"a": "python", "b": "python", "all": ag, "clean": ag}]
    text = cmp.report_text(result)
    assert f"100.00% of fields agree on clean frames ({ag.total}/{ag.total})" in text
    data = cmp.report_json(result)
    assert data["pairs"][0]["all"]["percent"] == 100.0 and "clean_set" not in data


# --- tshark output parsing ------------------------------------------------------

def test_parse_tshark_fields_both_boolean_styles():
    text = (
        "1\t0\t8\t02:00:00:00:00:aa\tff:ff:ff:ff:ff:ff\t02:00:00:00:00:aa\t100\tFalse\tFalse\t\n"
        "2\t1\t13\t\t\t\t\t0\t0\t1\n"
        "3\t2\t8\t02:00:00:00:00:01\t02:00:00:00:00:aa\t02:00:00:00:00:aa\t7\t1\tTrue\t0\n"
        "4\t\t\t\t\t\t\t\t\t\n"  # not an 802.11 frame
    )
    rows = cmp.parse_tshark_fields(text)
    assert sorted(rows) == [1, 2, 3]
    assert rows[1] == {"type": 0, "subtype": 8, "sa": "02:00:00:00:00:aa", "da": "ff:ff:ff:ff:ff:ff",
                       "bssid": "02:00:00:00:00:aa", "seq": 100, "retry": False, "protected": False,
                       "fcs_ok": None, "error": None}
    assert (rows[2]["sa"], rows[2]["seq"], rows[2]["retry"], rows[2]["fcs_ok"]) == (None, None, False, True)
    assert (rows[3]["retry"], rows[3]["protected"], rows[3]["fcs_ok"]) == (True, True, False)


# --- end to end ---------------------------------------------------------------

C_BIN = cmp.find_wifiparse()
TSHARK = cmp.find_tshark()


@pytest.mark.skipif(C_BIN is None, reason="C parser not built")
def test_compare_command_python_vs_c():
    result = CliRunner().invoke(main, ["compare", "--format", "json", str(SYNTHETIC_DIR / "roaming.pcap")])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    (pair,) = [p for p in data["pairs"] if (p["a"], p["b"]) == ("python", "c")]
    assert pair["all"]["percent"] == 100.0
    assert pair["all"]["total"] == data["frames"] * len(cmp.PY_C_FIELDS)


@pytest.mark.skipif(TSHARK is None, reason="tshark not installed")
@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: p.stem)
def test_python_and_c_match_tshark(path):
    """Every clean frame (valid FCS, fully parsed) must match Wireshark's
    dissection on type, subtype, SA, DA, BSSID, sequence number, Retry,
    Protected, and the FCS verdict."""
    result = cmp.compare_capture(path)
    pairs = {(p["a"], p["b"]): p for p in result["pairs"]}
    checked = [("python", "tshark")] + ([("c", "tshark")] if C_BIN else [])
    for key in checked:
        clean = pairs[key]["clean"]
        assert clean.disagreements == [], (key, clean.disagreements[:10])
        assert clean.frames == result["clean_frames"]

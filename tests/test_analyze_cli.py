"""`wifi-analyzer analyze`: text and JSON output, filters, schema."""

from __future__ import annotations

import json

import pytest
from builders import AP2, STA
from click.testing import CliRunner
from conftest import PUBLIC_DIR, SYNTHETIC_DIR

from wifi_analyzer.cli import main

EVENT_KEYS = {
    "idx", "ts", "t", "kind", "from", "label", "detail", "status", "reason", "auth_algo", "auth_seq", "aid",
    "eapol_message", "replay_counter", "dhcp_message", "xid", "ip", "broadcast",
}


def run(*args) -> str:
    result = CliRunner().invoke(main, [str(a) for a in args])
    assert result.exit_code == 0, result.output
    return result.output


def test_json_schema_is_stable():
    report = json.loads(run("analyze", "--format", "json", SYNTHETIC_DIR / "wpa3_sae_connected.pcap"))
    assert report["schema_version"] == 1
    assert set(report) == {"schema_version", "capture", "networks", "clients"}
    assert set(report["capture"]) == {"file", "packets", "frames_80211", "bad_fcs", "malformed", "retransmissions_skipped"}
    (net,) = report["networks"]
    assert set(net) == {"bssid", "ssid", "channel", "security"}
    assert set(net["security"]) == {"name", "akms", "pmf", "notes", "description"}
    (client,) = report["clients"]
    assert set(client) == {"client", "bssid", "ssid", "result", "dhcp", "attempts", "events"}
    assert set(client["result"]) == {"code", "summary", "likely_cause", "status_code", "reason_code", "code_meaning", "notes"}
    for ev in client["events"]:
        assert set(ev) == EVENT_KEYS


def test_text_and_json_carry_the_same_events():
    path = SYNTHETIC_DIR / "handshake_no_m4.pcap"
    text = run("analyze", path)
    report = json.loads(run("analyze", "--format", "json", path))
    for ev in report["clients"][0]["events"]:
        assert ev["label"] in text
    assert f"RESULT: {report['clients'][0]['result']['code']}" in text


def test_bssid_and_client_filters():
    path = SYNTHETIC_DIR / "roaming.pcap"
    both = json.loads(run("analyze", "--format", "json", path))
    assert len(both["clients"]) == 2
    one = json.loads(run("analyze", "--format", "json", "--bssid", AP2.upper(), path))
    assert [c["bssid"] for c in one["clients"]] == [AP2]
    assert [n["bssid"] for n in one["networks"]] == [AP2]
    none = json.loads(run("analyze", "--format", "json", "--client", "02:00:00:00:00:99", path))
    assert none["clients"] == []
    assert "No connection attempts found." in run("analyze", "--client", "02:00:00:00:00:99", path)
    assert len(json.loads(run("analyze", "--format", "json", "--client", STA, path))["clients"]) == 2


def test_wired_dhcp_text():
    text = run("analyze", SYNTHETIC_DIR / "ethernet_dhcp.pcap")
    assert "Wired (Ethernet) DHCP" in text
    assert "RESULT: CONNECTED" in text and "DHCP: ACK (10.0.0.20)" in text


@pytest.mark.skipif(not (PUBLIC_DIR / "wpa-Induction.pcap").exists(), reason="run tests/data/public/fetch.py")
def test_public_capture_analysis():
    report = json.loads(run("analyze", "--format", "json", PUBLIC_DIR / "wpa-Induction.pcap"))
    assert report["capture"]["bad_fcs"] == 13
    (c,) = report["clients"]
    assert (c["client"], c["bssid"], c["ssid"]) == ("00:0d:93:82:36:3a", "00:0c:41:82:b2:55", "Coherer")
    assert c["result"]["code"] == "CONNECTED"
    assert c["dhcp"] == "not observable: encrypted"
    assert [e["eapol_message"] for e in c["events"] if e["eapol_message"]] == ["M1", "M2", "M3", "M4"]
    assert any("left on purpose" in n for n in c["result"]["notes"])

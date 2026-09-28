"""Failure classification (SPEC.md 4.5): one test per synthetic scenario,
covering every result code, plus targeted rule tests."""

from __future__ import annotations

import json

import pytest
from builders import (
    AP,
    STA,
    STA2,
    assoc_req,
    assoc_resp,
    auth,
    beacon,
    deauth,
    dhcp_over_air,
    eapol_msg,
    handshake,
)
from conftest import SYNTHETIC_DIR
from scapy.layers.dot11 import RadioTap

from wifi_analyzer.classify import RESULT_CODES
from wifi_analyzer.report import build_report

SCENARIOS = sorted(p.name.removesuffix(".expected.json") for p in SYNTHETIC_DIR.glob("*.expected.json"))


def expected(name: str) -> dict:
    return json.loads((SYNTHETIC_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario(name):
    exp = expected(name)
    report = build_report(SYNTHETIC_DIR / f"{name}.pcap")
    got = {(c["client"], c["bssid"]): c for c in report["clients"]}
    assert len(got) == len(exp["results"]), f"{name}: {list(got)}"
    for want in exp["results"]:
        c = got[(want["client"], want["bssid"])]
        assert c["result"]["code"] == want["code"], f"{name}: {c['result']}"
        for key in ("status_code", "reason_code"):
            if key in want:
                assert c["result"][key] == want[key]
        if "dhcp" in want:
            assert c["dhcp"] == want["dhcp"]


def test_every_result_code_has_a_scenario():
    covered = {r["code"] for name in SCENARIOS for r in expected(name)["results"]}
    assert covered == set(RESULT_CODES)


def test_committed_captures_are_up_to_date(tmp_path):
    from gen_captures import generate

    names = generate(tmp_path)
    assert names == SCENARIOS
    for name in names:
        for suffix in (".pcap", ".expected.json"):
            fresh = (tmp_path / f"{name}{suffix}").read_bytes()
            committed = (SYNTHETIC_DIR / f"{name}{suffix}").read_bytes().replace(b"\r\n", b"\n")
            assert fresh.replace(b"\r\n", b"\n") == committed, f"{name}{suffix} is stale: run tests/gen_captures.py"


def test_spec_example_report_text():
    from wifi_analyzer.report import render_text

    text = render_text(build_report(SYNTHETIC_DIR / "handshake_no_m3.pcap"))
    assert 'Network: "LabNet"  BSSID 02:00:00:00:00:aa  Security: WPA3-Personal (SAE, PMF required)' in text
    assert "  0.012s  Assoc Response            status 0 (Successful)  AID 3" in text
    assert "  1.020s  EAPOL M1 (retry, replay counter 2)" in text
    assert "RESULT: HANDSHAKE_NO_M3 -> AP never sent M3 after M2." in text
    assert "Most likely cause: wrong passphrase." in text


def test_truncated_frame_counted_as_malformed():
    report = build_report(SYNTHETIC_DIR / "truncated_frame.pcap")
    assert report["capture"]["malformed"] == 1


# --- targeted rule tests (small captures built inline) ----------------------

def analyze(write_pcap, frames, name="x.pcap"):
    path = write_pcap(name, [RadioTap() / f if not isinstance(f, bytes) else f for f in frames], 127)
    return {(c["client"], c["bssid"]): c for c in build_report(path)["clients"]}


def join(**kw):
    return [beacon(), auth(True), auth(False, auth_seq=2), assoc_req(), assoc_resp()]


def test_single_m1_at_capture_end_is_incomplete(write_pcap):
    # No evidence the client failed: the capture may just have stopped.
    got = analyze(write_pcap, join() + [eapol_msg(1, 1)])
    c = got[(STA, AP)]
    assert c["result"]["code"] == "INCOMPLETE"
    assert "last message: M1" in c["result"]["summary"]


def test_repeated_m1_without_deauth_is_no_m2(write_pcap):
    got = analyze(write_pcap, join() + [eapol_msg(1, 1, seq=21), eapol_msg(1, 2, seq=22)])
    assert got[(STA, AP)]["result"]["code"] == "HANDSHAKE_NO_M2"


def test_mac_retransmission_is_not_an_eapol_retry(write_pcap):
    # Same M1 frame re-sent with the Retry bit and the same sequence number:
    # a lost ACK, not the AP restarting the handshake.
    m1 = eapol_msg(1, 1, seq=21)
    dup = eapol_msg(1, 1, seq=21)
    dup.FCfield |= 0x08
    got = analyze(write_pcap, join() + [m1, dup])
    c = got[(STA, AP)]
    assert c["result"]["code"] == "INCOMPLETE"
    assert sum(e["eapol_message"] == "M1" for e in c["events"]) == 1


def test_bad_fcs_frames_are_ignored(write_pcap):
    import zlib

    good = [bytes(RadioTap(present="Flags", Flags="FCS")) + bytes(f) + zlib.crc32(bytes(f)).to_bytes(4, "little")
            for f in join() + handshake()]
    # A corrupted deauth (wrong FCS) must not end the connection.
    fake = bytes(deauth(False, reason=15))
    corrupted = bytes(RadioTap(present="Flags", Flags="FCS")) + fake + b"\x00\x00\x00\x00"
    got = analyze(write_pcap, good + [corrupted])
    assert got[(STA, AP)]["result"]["code"] == "CONNECTED"


def test_last_attempt_decides(write_pcap):
    # First attempt rejected (AP full), second attempt succeeds.
    frames = [beacon(), auth(True, seq=2), auth(False, auth_seq=2), assoc_req(seq=3), assoc_resp(status=17, seq=103),
              auth(True, seq=4), auth(False, auth_seq=2, seq=104), assoc_req(seq=5), assoc_resp(seq=105)] + handshake(seq=30)
    c = analyze(write_pcap, frames)[(STA, AP)]
    assert c["result"]["code"] == "CONNECTED"
    assert c["attempts"] == 2
    assert any("2 connection attempts" in n for n in c["result"]["notes"])


def test_broadcast_deauth_applies_to_all_clients(write_pcap):
    from builders import BCAST

    frames = join() + handshake()
    frames += [auth(True, sta=STA2, seq=40), auth(False, auth_seq=2, sta=STA2, seq=140),
               assoc_req(sta=STA2, seq=41), assoc_resp(sta=STA2, aid=2, seq=141)]
    frames += handshake(sta=STA2, seq=50)
    bcast = deauth(False, reason=3, seq=300)
    bcast.addr1 = BCAST
    got = analyze(write_pcap, frames + [bcast])
    for sta in (STA, STA2):
        c = got[(sta, AP)]
        assert c["result"]["code"] == "DEAUTHENTICATED" and c["result"]["reason_code"] == 3
        assert c["events"][-1]["broadcast"] is True


def test_single_dhcp_discover_is_incomplete(write_pcap):
    frames = [beacon(rsn=None), auth(True), auth(False, auth_seq=2), assoc_req(rsn=None), assoc_resp(), dhcp_over_air("discover")]
    c = analyze(write_pcap, frames)[(STA, AP)]
    assert c["result"]["code"] == "INCOMPLETE" and c["dhcp"] == "in progress"


def test_dhcp_nak_then_success_is_connected(write_pcap):
    frames = [beacon(rsn=None), auth(True), auth(False, auth_seq=2), assoc_req(rsn=None), assoc_resp()]
    frames += [dhcp_over_air("request", seq=5), dhcp_over_air("nak", seq=104), dhcp_over_air("discover", seq=6),
               dhcp_over_air("offer", seq=105), dhcp_over_air("request", seq=7), dhcp_over_air("ack", seq=106)]
    c = analyze(write_pcap, frames)[(STA, AP)]
    assert c["result"]["code"] == "CONNECTED" and c["dhcp"] == "ACK (192.168.1.50)"


def test_no_beacon_still_detects_handshake_need(write_pcap):
    # No beacon captured: the RSN element in the client's Assoc Request tells us.
    frames = [auth(True), auth(False, auth_seq=2), assoc_req(), assoc_resp()]
    c = analyze(write_pcap, frames)[(STA, AP)]
    assert c["result"]["code"] == "INCOMPLETE"
    assert "before the 4-way handshake started" in c["result"]["summary"]

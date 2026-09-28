"""Generate the synthetic test captures in tests/data/synthetic/.

Each scenario writes <name>.pcap plus <name>.expected.json with the result
the analyzer should report for each client. Timestamps and contents are
fixed, so re-running this script produces byte-identical files; a test
checks that the committed files match.

Usage: python tests/gen_captures.py [output_dir]
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

from scapy.layers.dot11 import RadioTap



sys.path.insert(0, str(Path(__file__).parent))

from builders import (  # noqa: E402
    AP,
    AP2,
    STA,
    WPA2_RSN,
    WPA3_RSN,
    assoc_req,
    assoc_resp,
    auth,
    beacon,
    deauth,
    dhcp_ethernet,
    dhcp_over_air,
    disassoc,
    eapol_msg,
    handshake,
    probe_req,
    probe_resp,
    protected_data,
    reassoc_req,
    sae_commit,
    sae_confirm,
)

T0 = 1_700_000_000.0
OUT = Path(__file__).parent / "data" / "synthetic"


def at(t: float, pkt):
    """Radiotap-wrap a frame and stamp it t seconds after T0."""
    if not isinstance(pkt, RadioTap):
        pkt = RadioTap() / pkt
    pkt.time = T0 + t
    return pkt


def spaced(t0: float, frames, step=0.003):
    return [at(t0 + i * step, f) for i, f in enumerate(frames)]


# --- building blocks ------------------------------------------------------

def discover(rsn=WPA2_RSN, ssid="LabNet", bssid=AP):
    return [at(0.000, beacon(ssid, rsn, bssid=bssid)), at(0.050, probe_req(ssid)), at(0.052, probe_resp(ssid, rsn, bssid=bssid))]


def open_auth(t, bssid=AP):
    return spaced(t, [auth(True, bssid=bssid, seq=2), auth(False, auth_seq=2, bssid=bssid, seq=103)])


def sae_auth(t):
    return spaced(t, [sae_commit(True, seq=2), sae_commit(False, seq=103), sae_confirm(True, seq=3), sae_confirm(False, seq=104)])


def associate(t, rsn=WPA2_RSN, status=0, aid=1):
    return spaced(t, [assoc_req(rsn=rsn, seq=4), assoc_resp(status=status, aid=aid)])


def wpa2_join(t=0.1):
    return open_auth(t) + associate(t + 0.01) + spaced(t + 0.02, handshake())


def result(code, client=STA, bssid=AP, **extra):
    return {"client": client, "bssid": bssid, "code": code, **extra}


# --- scenarios: name -> (frames, expected, description) --------------------

def scenarios():
    s = {}

    frames = discover() + wpa2_join() + [at(0.5, protected_data(seq=60)), at(0.6, protected_data(False, seq=61))]
    s["wpa2_connected"] = (frames, [result("CONNECTED", dhcp="not observable: encrypted")],
                           "WPA2-PSK join: open auth, association, 4-way handshake, then encrypted data")

    frames = discover(WPA3_RSN) + sae_auth(0.1) + associate(0.12, WPA3_RSN, aid=3) + spaced(0.13, handshake(sae=True))
    s["wpa3_sae_connected"] = (frames, [result("CONNECTED")], "WPA3-SAE join: SAE commit/confirm, association, handshake")

    frames = discover(WPA3_RSN) + spaced(0.1, [
        sae_commit(True, seq=2), sae_commit(False, status=76, seq=103),  # anti-clogging token requested
        sae_commit(True, seq=3), sae_commit(False, seq=104), sae_confirm(True, seq=4), sae_confirm(False, seq=105),
    ]) + associate(0.13, WPA3_RSN) + spaced(0.14, handshake(sae=True))
    s["wpa3_anti_clogging"] = (frames, [result("CONNECTED")], "SAE with an anti-clogging token request (status 76) is not a failure")

    frames = discover(WPA3_RSN) + spaced(0.1, [auth(True, seq=2), auth(False, auth_seq=2, status=13, seq=103)])
    s["auth_failed"] = (frames, [result("AUTH_FAILED", status_code=13)], "Open System auth to a WPA3-only AP: status 13")

    frames = discover(WPA3_RSN) + spaced(0.1, [sae_commit(True, seq=2), sae_commit(False, status=77, seq=103)])
    s["sae_rejected"] = (frames, [result("SAE_FAILED", status_code=77)], "AP rejects the SAE group: status 77")

    frames = discover(WPA3_RSN) + spaced(0.1, [sae_commit(True, seq=2), sae_commit(False, seq=103), sae_confirm(True, seq=3)]) + [
        at(1.1, sae_confirm(True, seq=4)), at(2.1, sae_confirm(True, seq=5)), at(3.1, deauth(True, reason=1, seq=6)),
    ]
    s["sae_wrong_password"] = (frames, [result("SAE_FAILED", reason_code=1)], "AP never sends its SAE Confirm (wrong password); client gives up")

    frames = discover() + open_auth(0.1) + associate(0.11, status=17)
    s["assoc_rejected"] = (frames, [result("ASSOC_REJECTED", status_code=17)], "AP is full: association status 17")

    frames = discover() + open_auth(0.1) + associate(0.11) + [
        at(0.12, eapol_msg(1, 1, seq=21)), at(1.12, eapol_msg(1, 2, seq=22)), at(2.12, deauth(False, reason=15, seq=23)),
    ]
    s["handshake_no_m2"] = (frames, [result("HANDSHAKE_NO_M2", reason_code=15)], "Client never answers M1")

    # The example from SPEC.md section 5: WPA3, M2 sent, AP never sends M3.
    # Times are chosen so the report matches the spec's example, measured from the probe request.
    frames = [at(0.0, beacon(rsn=WPA3_RSN))] + [at(0.001 + t, f) for t, f in [
        (0.000, probe_req()),
        (0.004, sae_commit(True, seq=2)), (0.005, sae_commit(False, seq=103)),
        (0.008, sae_confirm(True, seq=3)), (0.009, sae_confirm(False, seq=104)),
        (0.010, assoc_req(rsn=WPA3_RSN, seq=4)), (0.012, assoc_resp(aid=3)),
        (0.015, eapol_msg(1, 1, sae=True, seq=21)), (0.018, eapol_msg(2, 1, sae=True, seq=5)),
        (1.020, eapol_msg(1, 2, sae=True, seq=22)), (2.021, deauth(False, reason=15, seq=23)),
    ]]
    s["handshake_no_m3"] = (frames, [result("HANDSHAKE_NO_M3", reason_code=15)], "AP never sends M3 after M2 (wrong passphrase)")

    frames = discover() + open_auth(0.1) + associate(0.11) + spaced(0.12, handshake(upto=3)) + [
        at(1.2, eapol_msg(3, 3, seq=24)), at(2.2, deauth(False, reason=15, seq=25)),
    ]
    s["handshake_no_m4"] = (frames, [result("HANDSHAKE_NO_M4", reason_code=15)], "Client never sends M4")

    frames = discover() + open_auth(0.1) + associate(0.11) + [at(3.2, deauth(False, reason=15, seq=30))]
    s["handshake_timeout"] = (frames, [result("HANDSHAKE_TIMEOUT", reason_code=15)], "Deauth reason 15 with no EAPOL frames captured")

    frames = discover() + open_auth(0.1) + associate(0.11) + spaced(0.12, handshake(upto=2)) + [at(0.2, deauth(False, reason=14, seq=30))]
    s["mic_failure"] = (frames, [result("MIC_FAILURE", reason_code=14)], "Deauth reason 14 during the handshake")

    frames = discover() + wpa2_join() + [at(5.0, protected_data(seq=60)), at(65.0, deauth(False, reason=4, seq=90))]
    s["deauthenticated"] = (frames, [result("DEAUTHENTICATED", reason_code=4)], "Connected, then the AP deauthenticates (inactivity)")

    frames = discover() + wpa2_join() + [at(5.0, protected_data(seq=60)), at(9.0, disassoc(True, reason=8, seq=90))]
    s["client_left"] = (frames, [result("CONNECTED")], "Connected, then the client leaves on purpose (reason 8)")

    frames = discover() + open_auth(0.1) + [at(0.11, assoc_req(seq=4))]
    s["incomplete"] = (frames, [result("INCOMPLETE")], "Capture ends after the association request")

    frames = discover(None) + open_auth(0.1) + associate(0.11, rsn=None) + [
        at(0.2, dhcp_over_air("discover", seq=5)), at(0.21, dhcp_over_air("offer", seq=104)),
        at(0.22, dhcp_over_air("request", seq=6)), at(0.23, dhcp_over_air("ack", seq=105)),
    ]
    s["open_dhcp_connected"] = (frames, [result("CONNECTED", dhcp="ACK (192.168.1.50)")], "Open network, full DHCP exchange")

    frames = discover(None) + open_auth(0.1) + associate(0.11, rsn=None) + [
        at(0.2, dhcp_over_air("discover", seq=5)), at(2.2, dhcp_over_air("discover", seq=6)), at(6.2, dhcp_over_air("discover", seq=7)),
    ]
    s["dhcp_no_offer"] = (frames, [result("DHCP_NO_OFFER", dhcp="no offer")], "Open network, three unanswered Discovers")

    frames = discover(None) + open_auth(0.1) + associate(0.11, rsn=None) + [
        at(0.2, dhcp_over_air("request", seq=5)), at(0.21, dhcp_over_air("nak", seq=104)),
    ]
    s["dhcp_nak"] = (frames, [result("DHCP_NAK", dhcp="NAK")], "Open network, the server NAKs the requested address")

    # Roaming: connected to AP, then reassociates to AP2 (same SSID).
    frames = discover() + wpa2_join() + [at(0.4, beacon("LabNet", WPA2_RSN, bssid=AP2, seq=300))] + spaced(1.0, [
        auth(True, bssid=AP2, seq=10), auth(False, auth_seq=2, bssid=AP2, seq=301),
        reassoc_req(current_ap=AP, seq=11), assoc_resp(bssid=AP2, reassoc=True, aid=7, seq=302),
    ]) + spaced(1.02, handshake(bssid=AP2, seq=40))
    s["roaming"] = (frames, [result("CONNECTED"), result("CONNECTED", bssid=AP2)], "Client roams from AP to AP2 by reassociation")

    # One truncated frame in the middle of a successful join.
    frames = discover() + wpa2_join()
    truncated = RadioTap() / auth(True, seq=9)
    cut = bytes(truncated)[:8 + 20]  # radiotap + 20 of the 24 header bytes
    frames.insert(3, (0.09, cut))
    s["truncated_frame"] = (frames, [result("CONNECTED")], "A truncated frame is reported as malformed and doesn't break the analysis")

    return s


def ethernet_scenario():
    frames = [
        (0.0, dhcp_ethernet("discover")), (0.01, dhcp_ethernet("offer")),
        (0.02, dhcp_ethernet("request")), (0.03, dhcp_ethernet("ack")),
    ]
    return frames, [result("CONNECTED", bssid=None, dhcp="ACK (10.0.0.20)")], "Wired-side capture: DHCP only"


def _write(path: Path, frames, linktype: int) -> None:
    packets = []
    for f in frames:
        if isinstance(f, tuple):  # (t, raw bytes or packet)
            t, pkt = f
            if isinstance(pkt, bytes):
                packets.append((t, pkt))
                continue
            pkt.time = T0 + t
            packets.append((t, pkt))
        else:
            packets.append((float(f.time) - T0, f))
    packets.sort(key=lambda p: p[0])  # file order = time order (stable for equal times)
    # Classic pcap, written directly so truncated byte strings can sit next to
    # normal frames: a 24-byte global header (magic, version 2.4, timezone,
    # sigfigs, snaplen, link type), then per packet ts_sec, ts_usec,
    # captured length, original length, and the bytes. All little-endian.
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for t, pkt in packets:
            data = pkt if isinstance(pkt, bytes) else bytes(pkt)
            usec_total = round(t * 1_000_000)  # integer microseconds: no float drift
            sec, usec = int(T0) + usec_total // 1_000_000, usec_total % 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


def generate(out: Path = OUT) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    all_scenarios = {name: (frames, exp, desc, 127) for name, (frames, exp, desc) in scenarios().items()}
    f, e, d = ethernet_scenario()
    all_scenarios["ethernet_dhcp"] = (f, e, d, 1)
    for name, (frames, expected, desc, linktype) in all_scenarios.items():
        _write(out / f"{name}.pcap", frames, linktype)
        (out / f"{name}.expected.json").write_text(
            json.dumps({"description": desc, "results": expected}, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    return sorted(all_scenarios)


if __name__ == "__main__":
    names = generate(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT)
    print(f"wrote {len(names)} captures: {', '.join(names)}")

"""The C parser (c/wifiparse) against the Python parser, frame by frame.

Skipped unless the binary is built (`make -C c`) or $WIFIPARSE points to it.
CI runs this file twice: with the optimized build, and with the
AddressSanitizer + UndefinedBehaviorSanitizer build, where any out-of-bounds
read, leak or undefined behaviour aborts the program and fails the test.
"""

from __future__ import annotations

import json
import random
import struct
import subprocess
import zlib

import pytest
from builders import auth, beacon, eapol_msg, write_raw_pcap
from conftest import PUBLIC_DIR, SYNTHETIC_DIR
from scapy.layers.dot11 import RadioTap

from wifi_analyzer.capture import read_packets
from wifi_analyzer.compare import PY_C_FIELDS, agreement, c_rows, find_wifiparse, python_rows

BIN = find_wifiparse()
pytestmark = pytest.mark.skipif(BIN is None, reason="C parser not built: run `make -C c` or set WIFIPARSE")

CAPTURES = [p for p in sorted(SYNTHETIC_DIR.glob("*.pcap")) if p.stem != "ethernet_dhcp"]
if (PUBLIC_DIR / "wpa-Induction.pcap").exists():
    CAPTURES.append(PUBLIC_DIR / "wpa-Induction.pcap")


def run_c(*args) -> subprocess.CompletedProcess:
    return subprocess.run([BIN, *map(str, args)], capture_output=True, text=True)


def assert_same(path):
    """C and Python agree on every header field of every frame, and C reports
    an error exactly when Python couldn't read the header."""
    py, c = python_rows(path), c_rows(path, BIN)
    assert sorted(c) == sorted(py), "C must print exactly one record per packet"
    ag = agreement(py, c, PY_C_FIELDS)
    assert ag.disagreements == [], ag.disagreements[:10]
    for idx, row in py.items():
        assert (c[idx]["error"] is not None) == (row["addr1"] is None), (idx, row, c[idx])
    return len(py)


@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: p.stem)
def test_matches_python(path):
    assert assert_same(path) > 0


def _synthetic_frames() -> list[bytes]:
    frames = []
    for p in SYNTHETIC_DIR.glob("*.pcap"):
        frames += [pkt.data for pkt in read_packets(p) if pkt.linktype == 127]
    return list(dict.fromkeys(frames))  # unique, stable order


def test_every_truncation_point(tmp_path):
    """Cut every synthetic frame at every possible length: radiotap and raw 802.11."""
    frames = _synthetic_frames()
    rt = tmp_path / "prefixes_radiotap.pcap"
    write_raw_pcap(rt, [f[:n] for f in frames for n in range(len(f) + 1)], 127)
    raw = tmp_path / "prefixes_raw.pcap"
    write_raw_pcap(raw, [f[8:][:n] for f in frames for n in range(len(f) - 8 + 1)], 105)
    assert assert_same(rt) > 1000
    assert assert_same(raw) > 1000


def test_random_bytes(tmp_path):
    """Deterministic fuzzing: random frames, most behind a random radiotap header."""
    rng = random.Random(1234)
    packets = []
    for _ in range(5000):
        body = rng.randbytes(rng.randint(0, 64))
        if rng.random() < 0.7:
            body = struct.pack("<BBHI", 0, 0, rng.randint(0, 40), rng.getrandbits(32)) + body
        packets.append(body)
    path = tmp_path / "random.pcap"
    write_raw_pcap(path, packets, 127)
    assert assert_same(path) == 5000


def _with_fcs(frame: bytes) -> bytes:
    return frame + zlib.crc32(frame).to_bytes(4, "little")


def test_radiotap_tsft_alignment_and_extended_bitmap(tmp_path):
    frame = _with_fcs(bytes(beacon()))
    # present = TSFT | Flags: TSFT at offset 8 (already 8-aligned), Flags at 16.
    rt1 = struct.pack("<BBHI", 0, 0, 17, 0x3) + bytes(8) + bytes([0x10])
    # Two present words (EXT bit set): fields start at 12, TSFT aligns up to 16, Flags at 24.
    rt2 = struct.pack("<BBHII", 0, 0, 25, 0x80000003, 0) + bytes(4) + bytes(8) + bytes([0x10])
    bad = bytearray(frame)
    bad[30] ^= 0xFF
    path = tmp_path / "rt.pcap"
    write_raw_pcap(path, [rt1 + frame, rt2 + frame, rt1 + bytes(bad)], 127)
    c = c_rows(path, BIN)
    assert [c[i]["fcs_ok"] for i in (1, 2, 3)] == [True, True, False]
    assert c[1]["bssid"] == c[2]["bssid"] == "02:00:00:00:00:aa"
    assert_same(path)


def test_radiotap_errors(tmp_path):
    good = bytes(RadioTap() / auth(True))
    cases = [
        b"",  # empty packet
        b"\x00\x00\x08",  # shorter than the fixed radiotap header
        b"\x01" + good[1:],  # radiotap version 1 doesn't exist
        b"\x00\x00\x04\x00" + good[4:],  # it_len smaller than 8
        b"\x00\x00\xff\x00" + good[4:],  # it_len beyond the captured bytes
        struct.pack("<BBHI", 0, 0, 8, 0x80000000),  # EXT bit, but no second word
    ]
    path = tmp_path / "rterr.pcap"
    write_raw_pcap(path, cases, 127)
    c = c_rows(path, BIN)
    assert all(c[i]["error"] for i in range(1, 6))
    assert c[6]["error"] and "Frame Control" in c[6]["error"]  # header fine, no 802.11 bytes
    assert_same(path)


def test_four_address_and_amsdu(tmp_path):
    base = bytes(eapol_msg(1, 1))  # QoS data, FromDS
    # 4-address frame: set ToDS too and insert Addr4 after Sequence Control.
    wds = bytes([base[0], base[1] | 0x01]) + base[2:24] + bytes.fromhex("020000000077") + base[24:]
    # A-MSDU: set bit 7 of the first QoS Control byte (offset 24 in a 3-address frame).
    amsdu = base[:24] + bytes([base[24] | 0x80]) + base[25:]
    path = tmp_path / "wds.pcap"
    write_raw_pcap(path, [wds, amsdu], 105)
    c = c_rows(path, BIN)
    assert (c[1]["addr4"], c[1]["sa"], c[1]["bssid"]) == ("02:00:00:00:00:77", "02:00:00:00:00:77", None)
    assert (c[2]["sa"], c[2]["bssid"]) == (None, "02:00:00:00:00:aa")
    assert_same(path)


def test_ethernet_capture_has_nothing_to_parse():
    proc = run_c(SYNTHETIC_DIR / "ethernet_dhcp.pcap")
    assert proc.returncode == 0 and proc.stdout == ""
    assert "no 802.11 frames" in proc.stderr


def test_usage_and_file_errors(tmp_path):
    assert run_c().returncode == 2
    assert run_c("--limit", "x", SYNTHETIC_DIR / "incomplete.pcap").returncode == 2
    assert run_c("--bogus", SYNTHETIC_DIR / "incomplete.pcap").returncode == 2
    assert run_c(tmp_path / "missing.pcap").returncode == 1
    not_pcap = tmp_path / "not.pcap"
    not_pcap.write_bytes(b"hello world, not a capture")
    assert run_c(not_pcap).returncode == 1


def test_limit_and_quiet():
    path = SYNTHETIC_DIR / "wpa2_connected.pcap"
    lines = run_c("--limit", 3, path).stdout.splitlines()
    assert [json.loads(line)["idx"] for line in lines] == [1, 2, 3]
    summary = json.loads(run_c("--quiet", path).stdout)
    assert summary["frames"] == len(list(read_packets(path))) and summary["errors"] == 0
    assert summary["seconds"] >= 0


def test_pcapng(tmp_path):
    """libpcap reads pcapng too; the output must be the same as for pcap."""
    from scapy.utils import wrpcapng

    pkts = [RadioTap() / beacon(), RadioTap() / auth(True)]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i
    path = tmp_path / "x.pcapng"
    wrpcapng(str(path), pkts)
    assert assert_same(path) == 2

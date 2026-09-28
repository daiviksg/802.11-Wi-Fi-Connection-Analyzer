"""Tests for capture reading and 802.11 header parsing (Milestone 0)."""

from __future__ import annotations

import struct
import zlib

from builders import AP, BCAST, STA, auth, beacon, probe_req
from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcapng

from wifi_analyzer.capture import radiotap_length, read_packets
from wifi_analyzer.frames import parse_frame


def parse_all(path):
    return [parse_frame(p) for p in read_packets(path)]


def test_radiotap_management_frames(radiotap_capture):
    frames = parse_all(radiotap_capture)
    assert [f.idx for f in frames] == [1, 2, 3]  # 1-based, like Wireshark
    b, p, a = frames
    assert (b.type, b.subtype, b.name) == (0, 8, "Beacon")
    assert (b.addr1, b.addr2, b.addr3) == (BCAST, AP, AP)
    assert (b.da, b.sa, b.bssid) == (BCAST, AP, AP)
    assert b.seq == 100
    assert b.mgmt.ssid == "LabNet"
    assert (p.subtype, p.addr2, p.mgmt.ssid, p.seq) == (4, STA, "LabNet", 1)
    assert (a.name, a.addr1, a.addr2, a.mgmt.ssid) == ("Authentication", AP, STA, None)
    assert all(f.error is None and f.fcs_ok is None for f in frames)
    assert abs(p.ts - b.ts - 0.001) < 1e-6


def test_raw_80211_linktype(write_pcap):
    path = write_pcap("raw.pcap", [beacon("Raw"), probe_req()], linktype=105)
    b, p = parse_all(path)
    assert (b.subtype, b.mgmt.ssid, b.addr2) == (8, "Raw", AP)
    assert p.subtype == 4


def test_ethernet_has_no_80211_fields(write_pcap):
    pkt = Ether(src=STA, dst=BCAST) / IP() / UDP(sport=1234, dport=80)
    path = write_pcap("eth.pcap", [pkt], linktype=1)
    (f,) = parse_all(path)
    assert (f.linktype, f.type, f.sa, f.da, f.dhcp, f.error) == (1, None, STA, BCAST, None, None)


def test_pcapng(tmp_path):
    path = tmp_path / "x.pcapng"
    pkt = RadioTap() / beacon("NG")
    pkt.time = 1_700_000_000.5
    wrpcapng(str(path), [pkt])
    (f,) = parse_all(path)
    assert f.mgmt.ssid == "NG"
    assert abs(f.ts - 1_700_000_000.5) < 1e-6


def test_radiotap_length_is_read_not_assumed(write_pcap):
    # Adding radiotap fields makes the header longer than the minimal 8 bytes.
    short = RadioTap() / beacon()
    long = RadioTap(present="Flags+Rate+Channel+dBm_AntSignal", Rate=2, ChannelFrequency=2437) / beacon()
    path = write_pcap("rt.pcap", [short, long], linktype=127)
    pkts = list(read_packets(path))
    assert radiotap_length(pkts[0].data) == 8
    assert radiotap_length(pkts[1].data) > 8
    assert [f.mgmt.ssid for f in parse_all(path)] == ["LabNet", "LabNet"]


def test_fcs_checked(write_pcap):
    # Radiotap with the "FCS at end" flag, then the frame, then its CRC-32
    # (sent least-significant byte first).
    body = bytes(beacon())
    good = bytes(RadioTap(present="Flags", Flags="FCS")) + body + zlib.crc32(body).to_bytes(4, "little")
    raw = bytearray(good)
    raw[-10] ^= 0xFF  # corrupt one body byte; the FCS no longer matches
    path = write_pcap("fcs.pcap", [good, bytes(raw)], linktype=127)
    ok, bad = parse_all(path)
    assert ok.fcs_ok is True and ok.mgmt.ssid == "LabNet"
    assert bad.fcs_ok is False


def test_control_frame_has_only_addr1(write_pcap):
    ack = Dot11(type=1, subtype=13, addr1=STA)  # ACK: FC, Duration, RA = 10 bytes
    path = write_pcap("ack.pcap", [RadioTap() / ack], linktype=127)
    (f,) = parse_all(path)
    assert (f.type, f.subtype, f.addr1, f.addr2, f.addr3, f.seq) == (1, 13, STA, None, None, None)
    assert f.error is None


def test_truncated_management_frame(write_pcap):
    full = bytes(RadioTap() / auth(True))
    cut = full[: 8 + 20]  # radiotap (8) + only 20 of the 24 header bytes
    path = write_pcap("trunc.pcap", [cut], linktype=127)
    (f,) = parse_all(path)
    assert (f.type, f.subtype) == (0, 11)
    assert f.addr1 is None
    assert "truncated" in f.error and "needs 24" in f.error


def test_radiotap_len_beyond_caplen(write_pcap):
    bogus = b"\x00\x00" + struct.pack("<H", 200) + b"\x00" * 20
    path = write_pcap("rtbad.pcap", [bogus], linktype=127)
    (f,) = parse_all(path)
    assert f.type is None
    assert "exceeds captured length" in f.error


def test_unsupported_protocol_version(write_pcap):
    raw = bytearray(bytes(beacon()))
    raw[0] |= 0x02  # protocol version 2 doesn't exist
    path = write_pcap("pv.pcap", [bytes(raw)], linktype=105)
    (f,) = parse_all(path)
    assert "protocol version" in f.error

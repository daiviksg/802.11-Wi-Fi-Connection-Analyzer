"""EAPOL-Key 4-way handshake message identification (SPEC.md 4.4)."""

from __future__ import annotations

import struct

import pytest
from builders import ANONCE, SNONCE, eapol_key_body, eapol_msg, handshake
from scapy.layers.dot11 import RadioTap

from wifi_analyzer.capture import read_packets
from wifi_analyzer.frames import identify_key_message, parse_eapol, parse_frame


def eapol_packet(key_body: bytes) -> bytes:
    # EAPOL header: version 2, type 3 (Key), body length (big-endian)
    return bytes([2, 3]) + struct.pack(">H", len(key_body)) + key_body


@pytest.mark.parametrize("n, key_info", [(1, 0x008A), (2, 0x010A), (3, 0x13CA), (4, 0x030A)])
def test_wpa2_messages_through_full_parser(write_pcap, n, key_info):
    path = write_pcap("hs.pcap", [RadioTap() / eapol_msg(n, replay=1)], 127)
    (f,) = [parse_frame(p) for p in read_packets(path)]
    assert f.error is None
    assert f.eapol.message == f"M{n}"
    assert f.eapol.key_info == key_info
    assert f.eapol.replay_counter == 1
    assert f.name == f"EAPOL M{n}"


def test_sae_handshake_descriptor_version_0(write_pcap):
    # WPA3-SAE uses descriptor version 0; the message logic is the same.
    path = write_pcap("sae.pcap", [RadioTap() / m for m in handshake(sae=True)], 127)
    msgs = [parse_frame(p).eapol for p in read_packets(path)]
    assert [m.message for m in msgs] == ["M1", "M2", "M3", "M4"]
    assert [m.key_info & 0x7 for m in msgs] == [0, 0, 0, 0]
    assert [m.replay_counter for m in msgs] == [1, 1, 2, 2]


def test_direction_and_addresses(write_pcap):
    from builders import AP, STA
    path = write_pcap("dir.pcap", [RadioTap() / m for m in handshake()], 127)
    frames = [parse_frame(p) for p in read_packets(path)]
    for f in frames:
        assert f.bssid == AP
    assert [(f.sa, f.da) for f in frames] == [(AP, STA), (STA, AP), (AP, STA), (STA, AP)]


def test_m2_with_secure_bit_set_is_still_m2():
    # Windows sets Secure on M2 during a rekey. Key Data (the client's RSN
    # element) is what identifies M2.
    body = eapol_key_body(0x010A | 0x0200, 2, SNONCE, key_data=b"\x30\x14" + bytes(20))
    assert parse_eapol(eapol_packet(body)).message == "M2"


def test_m4_with_nonzero_nonce_is_still_m4():
    # Some clients (Wireshark bug 11994) put a nonce in M4. With Secure set
    # and no Key Data it's still M4.
    body = eapol_key_body(0x030A, 2, SNONCE)
    info = parse_eapol(eapol_packet(body))
    assert info.message == "M4" and not info.nonce_zero


def test_m2_with_empty_key_data_uses_secure_and_nonce():
    # Empty Key Data, Secure clear, nonce present: M2 (as in Wi-SUN).
    assert identify_key_message(0x010A, key_data_len=0, mic_len=16, nonce_zero=False) == "M2"
    # Same but zero nonce: M4.
    assert identify_key_message(0x010A, key_data_len=0, mic_len=16, nonce_zero=True) == "M4"


def test_mlo_m4_with_12_bytes_key_data():
    assert identify_key_message(0x030A, key_data_len=12, mic_len=16, nonce_zero=True) == "M4"


def test_group_key_and_request():
    assert identify_key_message(0x1382, 22, 16, True) == "G1"  # ack, no pairwise bit
    assert identify_key_message(0x0302, 0, 16, True) == "G2"
    assert identify_key_message(0x0B0A, 0, 16, True) == "REQUEST"


@pytest.mark.parametrize("mic_len", [24, 32])
def test_longer_mic_lengths(mic_len):
    # SAE-EXT-KEY and Suite B 192-bit use longer MICs. Key Data Length must line up.
    body = eapol_key_body(0x0108, 1, SNONCE, key_data=bytes(22), mic_len=mic_len)
    info = parse_eapol(eapol_packet(body))
    assert (info.mic_len, info.key_data_len, info.message) == (mic_len, 22, "M2")


def test_padding_after_body_is_ignored():
    body = eapol_key_body(0x008A, 1, ANONCE)
    info = parse_eapol(eapol_packet(body) + bytes(10))
    assert info.message == "M1" and info.error is None


def test_truncated_key_frame():
    body = eapol_key_body(0x008A, 1, ANONCE)
    info = parse_eapol(eapol_packet(body)[:60])
    assert info.message is None and "truncated" in info.error
    assert "truncated" in parse_eapol(b"\x02\x03").error


def test_non_key_eapol_packet():
    info = parse_eapol(bytes([2, 0, 0, 4]) + b"\x01\x01\x00\x04")  # EAP-Request
    assert info.packet_type == 0 and info.message is None and info.error is None

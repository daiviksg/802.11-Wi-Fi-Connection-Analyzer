"""Management frame bodies and DHCP parsing (SPEC.md 4.2)."""

from __future__ import annotations

from builders import (
    AP,
    STA,
    WPA3_RSN,
    assoc_req,
    assoc_resp,
    auth,
    beacon,
    deauth,
    dhcp_ethernet,
    dhcp_over_air,
    disassoc,
    protected_data,
    reassoc_req,
    sae_commit,
)
from scapy.layers.dot11 import RadioTap

from wifi_analyzer.capture import read_packets
from wifi_analyzer.frames import parse_frame
from wifi_analyzer.report import describe_frame


def parse_one(write_pcap, pkt, linktype=127):
    path = write_pcap("one.pcap", [RadioTap() / pkt if linktype == 127 else pkt], linktype)
    (f,) = [parse_frame(p) for p in read_packets(path)]
    return f


def test_beacon_security_and_channel(write_pcap):
    f = parse_one(write_pcap, beacon("Lab3", rsn=WPA3_RSN, channel=11))
    m = f.mgmt
    assert (m.ssid, m.channel, m.privacy) == ("Lab3", 11, True)
    assert m.rsn.akms == [8] and m.rsn.mfpr
    assert "WPA3-Personal (SAE, PMF required)" in describe_frame(f)


def test_open_beacon(write_pcap):
    f = parse_one(write_pcap, beacon(rsn=None))
    assert f.mgmt.privacy is False and f.mgmt.rsn is None
    assert describe_frame(f).endswith("Open")


def test_auth_fields(write_pcap):
    f = parse_one(write_pcap, auth(False, algo=0, auth_seq=2, status=13))
    assert (f.mgmt.auth_algo, f.mgmt.auth_seq, f.mgmt.status) == (0, 2, 13)
    assert (f.sa, f.da, f.bssid) == (AP, STA, AP)
    assert "does not support the specified authentication algorithm" in describe_frame(f)


def test_sae_commit(write_pcap):
    f = parse_one(write_pcap, sae_commit(True))
    assert (f.mgmt.auth_algo, f.mgmt.auth_seq) == (3, 1)
    assert "SAE commit" in describe_frame(f)


def test_assoc_request_and_response(write_pcap):
    req = parse_one(write_pcap, assoc_req())
    assert req.mgmt.ssid == "LabNet" and req.mgmt.rsn.akms == [2]
    resp = parse_one(write_pcap, assoc_resp(status=0, aid=3))
    assert (resp.mgmt.status, resp.mgmt.aid) == (0, 3)  # top two AID bits masked off
    rej = parse_one(write_pcap, assoc_resp(status=17))
    assert rej.mgmt.status == 17


def test_reassociation(write_pcap):
    req = parse_one(write_pcap, reassoc_req(current_ap=AP))
    assert req.name == "Reassoc Request" and req.mgmt.ssid == "LabNet"
    resp = parse_one(write_pcap, assoc_resp(reassoc=True, aid=5))
    assert (resp.name, resp.mgmt.status, resp.mgmt.aid) == ("Reassoc Response", 0, 5)


def test_deauth_and_disassoc_reason(write_pcap):
    f = parse_one(write_pcap, deauth(False, reason=15))
    assert f.mgmt.reason == 15 and (f.sa, f.da) == (AP, STA)
    assert "4-way handshake timeout" in describe_frame(f)
    g = parse_one(write_pcap, disassoc(True, reason=8))
    assert g.mgmt.reason == 8 and (g.sa, g.da) == (STA, AP)


def test_protected_deauth_hides_reason(write_pcap):
    pkt = deauth(False, reason=7)
    pkt.FCfield |= 0x40
    f = parse_one(write_pcap, pkt)
    assert f.protected and f.mgmt.reason is None
    assert "encrypted" in describe_frame(f)


def test_truncated_mgmt_body(write_pcap):
    raw = bytes(RadioTap() / auth(True))[:-3]  # header intact, body cut to 3 of 6 bytes
    path = write_pcap("t.pcap", [raw], 127)
    (f,) = [parse_frame(p) for p in read_packets(path)]
    assert "fixed fields need 6" in f.error


def test_ht_control_field_is_skipped(write_pcap):
    # Order bit set on a management frame: a 4-byte HT Control field sits
    # between the header and the body. Build it by hand.
    base = bytes(auth(False, status=0))
    raw = bytes([base[0], base[1] | 0x80]) + base[2:24] + b"\xaa\xbb\xcc\xdd" + base[24:]
    path = write_pcap("htc.pcap", [raw], 105)
    (f,) = [parse_frame(p) for p in read_packets(path)]
    assert f.error is None
    assert (f.mgmt.auth_algo, f.mgmt.auth_seq, f.mgmt.status) == (0, 1, 0)


def test_dhcp_over_the_air(write_pcap):
    f = parse_one(write_pcap, dhcp_over_air("discover"))
    assert f.dhcp.message == "DISCOVER" and f.dhcp.client_mac == STA and f.dhcp.xid == 0x1234ABCD
    assert (f.sa, f.bssid) == (STA, AP)
    g = parse_one(write_pcap, dhcp_over_air("ack"))
    assert g.dhcp.message == "ACK" and g.dhcp.your_ip == "192.168.1.50"
    assert g.dhcp.client_mac == STA  # from chaddr: the 802.11 destination is broadcast
    assert g.name == "DHCP ACK"


def test_dhcp_on_ethernet(write_pcap):
    f = parse_one(write_pcap, dhcp_ethernet("nak"), linktype=1)
    assert f.linktype == 1 and f.dhcp.message == "NAK" and f.dhcp.client_mac == STA


def test_protected_data_is_not_decoded(write_pcap):
    f = parse_one(write_pcap, protected_data())
    assert f.protected and f.eapol is None and f.dhcp is None and f.error is None

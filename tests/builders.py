"""Builders for synthetic 802.11 / EAPOL / DHCP frames.

Frame layouts come from Scapy. The EAPOL-Key descriptor and RSN element
bytes are packed by hand with struct, so the tests don't just check Scapy
against itself.

All MAC addresses are locally administered (first octet 02), so no real
device's address appears in test data.
"""

from __future__ import annotations

import struct

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11QoS,
    Dot11ReassoReq,
    Dot11ReassoResp,
)
from scapy.layers.eap import EAPOL
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import LLC, SNAP, Ether
from scapy.packet import Raw
from scapy.utils import mac2str

AP = "02:00:00:00:00:aa"
AP2 = "02:00:00:00:00:bb"
STA = "02:00:00:00:00:01"
STA2 = "02:00:00:00:00:02"
ROUTER = "02:00:00:00:00:fe"
BCAST = "ff:ff:ff:ff:ff:ff"

OUI = b"\x00\x0f\xac"
# Capability Information flags, given by name: Scapy's "cap" field maps names
# to the right bits of the little-endian field, but a plain int ends up
# byte-swapped.
CAP_OPEN = "ESS"
CAP_SECURE = "ESS+privacy"

# Key Information values for the 4-way handshake. Low 3 bits = descriptor
# version: 2 (HMAC-SHA1-128 / AES key wrap) for WPA2-PSK with CCMP; 0 ("AKM
# defined") for SAE. Then pairwise 0x0008, install 0x0040, ack 0x0080, mic 0x0100,
# secure 0x0200, encrypted key data 0x1000.
KI_M1, KI_M2, KI_M3, KI_M4 = 0x0088, 0x0108, 0x13C8, 0x0308


# --- elements ---------------------------------------------------------------

def rsn_body(akms=(2,), pairwise=(4,), group=4, caps=0x000C) -> bytes:
    """RSN element body. Default: WPA2-PSK, CCMP-128, capabilities 0x000C
    (PTKSA replay counter 16), no PMF."""
    b = struct.pack("<H", 1) + OUI + bytes([group])
    b += struct.pack("<H", len(pairwise)) + b"".join(OUI + bytes([p]) for p in pairwise)
    b += struct.pack("<H", len(akms)) + b"".join(OUI + bytes([a]) for a in akms)
    b += struct.pack("<H", caps)
    return b


WPA2_RSN = rsn_body()
WPA3_RSN = rsn_body(akms=(8,), caps=0x00CC)  # MFPC 0x80 + MFPR 0x40 set
TRANSITION_RSN = rsn_body(akms=(2, 8), caps=0x008C)  # MFPC only


def elements(ssid: str, channel: int | None = 6, rsn: bytes | None = None):
    e = Dot11Elt(ID=0, info=ssid.encode()) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    if channel is not None:
        e = e / Dot11Elt(ID=3, info=bytes([channel]))
    if rsn is not None:
        e = e / Dot11Elt(ID=48, info=rsn)
    return e


# --- management frames ------------------------------------------------------

def hdr(subtype: int, da: str, sa: str, bssid: str, seq: int, **kw) -> Dot11:
    return Dot11(type=0, subtype=subtype, addr1=da, addr2=sa, addr3=bssid, SC=seq << 4, **kw)


def beacon(ssid="LabNet", rsn: bytes | None = WPA2_RSN, bssid=AP, seq=100, channel=6):
    cap = CAP_SECURE if rsn else CAP_OPEN
    return hdr(8, BCAST, bssid, bssid, seq) / Dot11Beacon(cap=cap) / elements(ssid, channel, rsn)


def probe_req(ssid="LabNet", sta=STA, seq=1):
    return hdr(4, BCAST, sta, BCAST, seq) / Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid.encode())


def probe_resp(ssid="LabNet", rsn: bytes | None = WPA2_RSN, bssid=AP, sta=STA, seq=101):
    cap = CAP_SECURE if rsn else CAP_OPEN
    return hdr(5, sta, bssid, bssid, seq) / Dot11ProbeResp(cap=cap) / elements(ssid, 6, rsn)


def auth(from_client: bool, algo=0, auth_seq=1, status=0, bssid=AP, sta=STA, seq=2, body=b""):
    da, sa = (bssid, sta) if from_client else (sta, bssid)
    pkt = hdr(11, da, sa, bssid, seq) / Dot11Auth(algo=algo, seqnum=auth_seq, status=status)
    return pkt / Raw(body) if body else pkt


def sae_commit(from_client: bool, status=0, **kw):
    # SAE Commit body: finite cyclic group (19 = NIST P-256), then the scalar
    # (32 bytes) and element (64 bytes). The values here are placeholders.
    body = struct.pack("<H", 19) + bytes(range(32)) + bytes(range(64))
    return auth(from_client, algo=3, auth_seq=1, status=status, body=body, **kw)


def sae_confirm(from_client: bool, status=0, **kw):
    # SAE Confirm body: send-confirm counter (2) + confirm value (32).
    return auth(from_client, algo=3, auth_seq=2, status=status, body=struct.pack("<H", 1) + bytes(32), **kw)


def assoc_req(ssid="LabNet", rsn: bytes | None = WPA2_RSN, bssid=AP, sta=STA, seq=3):
    return hdr(0, bssid, sta, bssid, seq) / Dot11AssoReq(cap=CAP_SECURE if rsn else CAP_OPEN, listen_interval=10) / elements(ssid, None, rsn)


def reassoc_req(current_ap: str, ssid="LabNet", rsn: bytes | None = WPA2_RSN, bssid=AP2, sta=STA, seq=3):
    return (
        hdr(2, bssid, sta, bssid, seq)
        / Dot11ReassoReq(cap=CAP_SECURE if rsn else CAP_OPEN, listen_interval=10, current_AP=current_ap)
        / elements(ssid, None, rsn)
    )


def assoc_resp(status=0, aid=1, bssid=AP, sta=STA, seq=102, reassoc=False):
    # Two top bits of the AID field are set (see frames.py).
    layer = Dot11ReassoResp if reassoc else Dot11AssoResp
    return hdr(3 if reassoc else 1, sta, bssid, bssid, seq) / layer(cap=CAP_OPEN, status=status, AID=0xC000 | aid)


def deauth(from_client: bool, reason: int, bssid=AP, sta=STA, seq=200):
    da, sa = (bssid, sta) if from_client else (sta, bssid)
    return hdr(12, da, sa, bssid, seq) / Dot11Deauth(reason=reason)


def disassoc(from_client: bool, reason: int, bssid=AP, sta=STA, seq=200):
    da, sa = (bssid, sta) if from_client else (sta, bssid)
    return hdr(10, da, sa, bssid, seq) / Dot11Disas(reason=reason)


# --- data frames ------------------------------------------------------------

def data_hdr(from_client: bool, bssid=AP, sta=STA, seq=10, dst: str | None = None, src: str | None = None, protected=False, qos=True):
    """A data frame between a client and its AP. ToDS/FromDS decide the address order."""
    # Frame Control flag bits: ToDS 0x01, FromDS 0x02, Protected 0x40.
    flags = 0x01 if from_client else 0x02
    if protected:
        flags |= 0x40
    if from_client:  # Addr1 = BSSID, Addr2 = SA, Addr3 = DA
        pkt = Dot11(type=2, subtype=8 if qos else 0, FCfield=flags, addr1=bssid, addr2=sta, addr3=dst or bssid, SC=seq << 4)
    else:  # Addr1 = DA, Addr2 = BSSID, Addr3 = SA
        pkt = Dot11(type=2, subtype=8 if qos else 0, FCfield=flags, addr1=dst or sta, addr2=bssid, addr3=src or bssid, SC=seq << 4)
    return pkt / Dot11QoS() if qos else pkt


def eapol_key_body(key_info: int, replay: int, nonce: bytes = bytes(32), key_data: bytes = b"", mic_len: int = 16, mic: bytes | None = None) -> bytes:
    """EAPOL-Key descriptor (big-endian fields; see frames.py for the layout)."""
    assert len(nonce) == 32
    mic = mic if mic is not None else (bytes(mic_len) if not key_info & 0x0100 else b"\x11" * mic_len)
    return (
        bytes([2])  # descriptor type 2: RSN (IEEE 802.11) key descriptor
        + struct.pack(">HHQ", key_info, 16, replay)  # key info, key length, replay counter
        + nonce
        + bytes(16) + bytes(8) + bytes(8)  # Key IV, Key RSC, reserved
        + mic
        + struct.pack(">H", len(key_data))
        + key_data
    )


ANONCE = bytes(range(1, 33))
SNONCE = bytes(range(101, 133))


def eapol_frame(from_client: bool, key_body: bytes, **kw):
    return data_hdr(from_client, **kw) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E) / EAPOL(version=2, type=3) / Raw(key_body)


def eapol_msg(n: int, replay: int, sae=False, **kw):
    """4-way handshake message n (1-4), with realistic key data sizes."""
    ver = 0 if sae else 2
    ki = {1: KI_M1, 2: KI_M2, 3: KI_M3, 4: KI_M4}[n] | ver
    body = {
        1: eapol_key_body(ki, replay, ANONCE),
        2: eapol_key_body(ki, replay, SNONCE, key_data=bytes([48, len(WPA2_RSN)]) + WPA2_RSN),
        3: eapol_key_body(ki, replay, ANONCE, key_data=bytes(56)),  # encrypted GTK KDE (wrapped)
        4: eapol_key_body(ki, replay),
    }[n]
    return eapol_frame(from_client=n in (2, 4), key_body=body, **kw)


def handshake(first_replay=1, sae=False, upto=4, seq=20, **kw):
    """M1..M{upto}. The AP increments the replay counter for each message it
    sends; the client echoes the counter of the message it answers."""
    msgs = []
    replay = {1: first_replay, 2: first_replay, 3: first_replay + 1, 4: first_replay + 1}
    for n in range(1, upto + 1):
        msgs.append(eapol_msg(n, replay[n], sae=sae, seq=seq + n, **kw))
    return msgs


def protected_data(from_client=True, seq=50, **kw):
    # CCMP header (8 bytes) + ciphertext + 8-byte MIC; the contents are placeholders.
    return data_hdr(from_client, seq=seq, protected=True, **kw) / Raw(b"\x01\x00\x00\x20\x00\x00\x00\x00" + bytes(48))


def dhcp_over_air(msg: str, xid=0x1234ABCD, bssid=AP, sta=STA, seq=60, your_ip="192.168.1.50"):
    """A DHCP message relayed through the AP. Client messages go to
    255.255.255.255 from 0.0.0.0; server replies are broadcast to the client."""
    from_client = msg in ("discover", "request", "decline", "release", "inform")
    options = [("message-type", msg)]
    if from_client:
        ip = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        bootp = BOOTP(op=1, xid=xid, chaddr=mac2str(sta))
        frame = data_hdr(True, bssid=bssid, sta=sta, seq=seq, dst=BCAST, qos=False)
    else:
        options.append(("server_id", "192.168.1.1"))
        ip = IP(src="192.168.1.1", dst="255.255.255.255") / UDP(sport=67, dport=68)
        yi = your_ip if msg in ("offer", "ack") else "0.0.0.0"
        bootp = BOOTP(op=2, xid=xid, yiaddr=yi, chaddr=mac2str(sta))
        frame = data_hdr(False, bssid=bssid, sta=sta, seq=seq, dst=BCAST, src=ROUTER, qos=False)
    return frame / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x0800) / ip / bootp / DHCP(options=options + ["end"])


def dhcp_ethernet(msg: str, xid=0x0BADCAFE, sta=STA, your_ip="10.0.0.20"):
    from_client = msg in ("discover", "request", "decline", "release", "inform")
    options = [("message-type", msg)]
    if from_client:
        return (
            Ether(src=sta, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, chaddr=mac2str(sta)) / DHCP(options=options + ["end"])
        )
    options.append(("server_id", "10.0.0.1"))
    yi = your_ip if msg in ("offer", "ack") else "0.0.0.0"
    return (
        Ether(src=ROUTER, dst=BCAST) / IP(src="10.0.0.1", dst="255.255.255.255") / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=xid, yiaddr=yi, chaddr=mac2str(sta)) / DHCP(options=options + ["end"])
    )

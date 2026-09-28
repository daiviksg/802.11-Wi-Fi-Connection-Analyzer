"""Parsing captured packets into plain dataclasses: 802.11 headers,
management frame bodies, EAPOL-Key frames, and DHCP.

802.11 MAC header (IEEE 802.11-2020, clause 9.2.3):

  Frame Control (2) | Duration/ID (2) | Addr1 (6) | Addr2 (6) | Addr3 (6) |
  Sequence Control (2) | [Addr4 (6)] | [QoS Control (2)] | [HT Control (4)] | body | [FCS (4)]

Not every frame has every field, so the header length depends on the frame
type and flags; see `header_len`. 802.11 multi-byte fields are
little-endian. EAPOL fields (an IEEE 802.1X format) are big-endian.

Approach: we check every length ourselves, on the original bytes. Only
after that do we hand the frame to Scapy, which decodes the fixed fields
and walks the data-frame layers (LLC/SNAP -> EAPOL, or -> IP/UDP/BOOTP/DHCP).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import asdict, dataclass

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Deauth,
    Dot11Disas,
    Dot11ReassoResp,
)
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import Ether

from .capture import DLT_EN10MB, DLT_IEEE802_11_RADIO, RadiotapError, RawPacket, dot11_bytes, radiotap_has_fcs
from .codes import DHCP_MESSAGE_TYPES
from .rsn import ELEMENT_ID_RSN, RsnInfo, parse_rsn

TYPE_MGMT, TYPE_CTRL, TYPE_DATA, TYPE_EXT = 0, 1, 2, 3

# Subtype names, IEEE 802.11-2020 Table 9-1 (valid type and subtype combinations).
MGMT_ASSOC_REQ, MGMT_ASSOC_RESP, MGMT_REASSOC_REQ, MGMT_REASSOC_RESP = 0, 1, 2, 3
MGMT_PROBE_REQ, MGMT_PROBE_RESP, MGMT_BEACON = 4, 5, 8
MGMT_DISASSOC, MGMT_AUTH, MGMT_DEAUTH = 10, 11, 12

MGMT_SUBTYPE_NAMES = {
    0: "Assoc Request",
    1: "Assoc Response",
    2: "Reassoc Request",
    3: "Reassoc Response",
    4: "Probe Request",
    5: "Probe Response",
    6: "Timing Advertisement",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack",
}
CTRL_PS_POLL, CTRL_CF_END = 10, 14
# Control subtypes that carry a transmitter address (Addr2) after Addr1:
# Trigger (2, added by 802.11ax), Beamforming Report Poll (4), VHT/HE NDP
# Announcement (5), BlockAckReq (8), BlockAck (9), PS-Poll (10), RTS (11),
# CF-End (14), CF-End+CF-Ack (15). ACK (13) and CTS (12) carry only Addr1.
CTRL_WITH_ADDR2 = {2, 4, 5, 8, 9, 10, 11, 14, 15}
CTRL_SUBTYPE_NAMES = {8: "BlockAckReq", 9: "BlockAck", 10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End"}
DATA_SUBTYPE_NAMES = {0: "Data", 4: "Null", 8: "QoS Data", 12: "QoS Null"}

# Fixed-length fields at the start of each management body, before the
# elements (IEEE 802.11-2020 clause 9.3.3):
#   Beacon / Probe Response: Timestamp (8), Beacon Interval (2), Capability (2)
#   Assoc Request: Capability (2), Listen Interval (2)
#   Reassoc Request: the same plus Current AP Address (6)
#   (Re)Assoc Response: Capability (2), Status Code (2), AID (2)
#   Authentication: Algorithm (2), Transaction Sequence (2), Status Code (2)
#   Deauthentication / Disassociation: Reason Code (2)
MGMT_FIXED_LEN = {0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 8: 12, 10: 2, 11: 6, 12: 2}
# Subtypes whose body continues with elements after the fixed fields.
MGMT_HAS_ELEMENTS = {0, 2, 4, 5, 8}

# Frame Control flag bits (second FC byte), IEEE 802.11-2020 9.2.4.1.
FC_TO_DS = 0x01
FC_FROM_DS = 0x02
FC_RETRY = 0x08
FC_PROTECTED = 0x40
FC_ORDER = 0x80

CAP_PRIVACY = 0x0010  # Capability Information bit 4: the network uses encryption

ELEMENT_ID_SSID = 0
ELEMENT_ID_DS_PARAMS = 3  # current channel (2.4 GHz)
ELEMENT_ID_HT_OPERATION = 61  # first byte = primary channel
ELEMENT_ID_VENDOR = 221
WPA1_OUI_TYPE = b"\x00\x50\xf2\x01"  # Microsoft OUI, type 1: pre-RSN WPA element

# EAPOL (IEEE 802.1X-2010 clause 11.3) packet types.
EAPOL_TYPE_KEY = 3

# EAPOL-Key Key Information bits (IEEE 802.11-2020 12.7.2; the same masks as
# Wireshark's KEY_INFO_*_MASK constants).
KI_KEY_TYPE_PAIRWISE = 0x0008  # 1 = pairwise key (4-way handshake), 0 = group key
KI_INSTALL = 0x0040
KI_ACK = 0x0080  # set by the authenticator (AP) when it expects a reply
KI_MIC = 0x0100
KI_SECURE = 0x0200
KI_ERROR = 0x0400
KI_REQUEST = 0x0800
KI_ENCRYPTED_KEY_DATA = 0x1000

# EAPOL-Key descriptor layout, offsets into the body after the 4-byte EAPOL header:
#   0 Descriptor Type (1) | 1 Key Information (2) | 3 Key Length (2) |
#   5 Replay Counter (8) | 13 Key Nonce (32) | 45 Key IV (16) | 61 Key RSC (8) |
#   69 Reserved (8) | 77 Key MIC (n) | 77+n Key Data Length (2) | Key Data
# The MIC length n is 16 bytes for PSK and SAE with group 19. Some newer AKMs
# (e.g. SAE-EXT-KEY, Suite B 192-bit, OWE with larger groups) use 24 or 32,
# and FILS uses 0. The frame doesn't say which, so we try each length and keep
# the one where Key Data Length exactly accounts for the rest of the body.
EAPOL_KEY_MIC_OFFSET = 77
MIC_LENGTH_CANDIDATES = (16, 24, 32, 0)


@dataclass
class MgmtInfo:
    ssid: str | None = None
    channel: int | None = None
    privacy: bool | None = None  # Capability "Privacy" bit (Beacon / Probe Response)
    rsn: RsnInfo | None = None
    wpa1: bool = False  # legacy WPA vendor element present
    auth_algo: int | None = None
    auth_seq: int | None = None  # Authentication transaction sequence number
    status: int | None = None
    aid: int | None = None
    reason: int | None = None


@dataclass
class EapolInfo:
    packet_type: int  # 0 EAP-Packet, 1 Start, 2 Logoff, 3 Key
    message: str | None = None  # "M1".."M4", "G1"/"G2" (group key), "REQUEST"
    key_info: int | None = None
    replay_counter: int | None = None
    key_data_len: int | None = None
    mic_len: int | None = None
    nonce_zero: bool | None = None
    error: str | None = None


@dataclass
class DhcpInfo:
    message: str  # "DISCOVER", "OFFER", ...
    xid: int  # transaction ID: ties a Discover to its Offer, Request, ACK
    client_mac: str  # chaddr: the client's MAC, even when the frame is relayed or broadcast
    your_ip: str | None = None  # yiaddr: the address being offered or assigned


@dataclass
class Frame:
    idx: int
    ts: float
    linktype: int
    type: int | None = None
    subtype: int | None = None
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    addr4: str | None = None  # only in 4-address (ToDS and FromDS) data frames
    # Source, destination and BSSID worked out from the addresses and ToDS/FromDS.
    sa: str | None = None
    da: str | None = None
    bssid: str | None = None
    seq: int | None = None
    retry: bool | None = None
    protected: bool | None = None
    to_ds: bool | None = None
    from_ds: bool | None = None
    fcs_ok: bool | None = None  # None: the capture has no FCS to check
    mgmt: MgmtInfo | None = None
    eapol: EapolInfo | None = None
    dhcp: DhcpInfo | None = None
    error: str | None = None  # set when the frame couldn't be fully parsed

    @property
    def name(self) -> str:
        if self.linktype == DLT_EN10MB:
            return f"DHCP {self.dhcp.message}" if self.dhcp else "Ethernet"
        if self.type is None:
            return "Malformed"
        if self.eapol is not None:
            return f"EAPOL {self.eapol.message}" if self.eapol.message else "EAPOL"
        if self.dhcp is not None:
            return f"DHCP {self.dhcp.message}"
        table = {TYPE_MGMT: MGMT_SUBTYPE_NAMES, TYPE_CTRL: CTRL_SUBTYPE_NAMES, TYPE_DATA: DATA_SUBTYPE_NAMES}.get(self.type, {})
        kind = {TYPE_MGMT: "Mgmt", TYPE_CTRL: "Ctrl", TYPE_DATA: "Data", TYPE_EXT: "Ext"}[self.type]
        return table.get(self.subtype, f"{kind} subtype {self.subtype}")

    @property
    def usable(self) -> bool:
        """Safe to use as evidence: parsed cleanly and not corrupted in the air."""
        return self.error is None and self.fcs_ok is not False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = self.name
        return d


def header_len(ftype: int, subtype: int, flags: int) -> int:
    """Length of the MAC header, so we know where the body starts and can
    check the frame is long enough before reading any field.

    IEEE 802.11-2020 clause 9.3:
      * Management: FC, Duration, Addr1-3, Seq Ctrl = 24 bytes. If the Order
        bit is set, a 4-byte HT Control field follows (9.2.4.6).
      * Data: the same 24, plus Addr4 (6) when both ToDS and FromDS are set
        (wireless distribution system), plus QoS Control (2) for QoS subtypes
        (subtype bit 3), plus HT Control (4) if a QoS frame has Order set.
      * Control frames are short. ACK and CTS carry only Addr1 (10 bytes);
        the subtypes in CTRL_WITH_ADDR2 also carry Addr2 (16).
    """
    if ftype == TYPE_MGMT:
        return 24 + (4 if flags & FC_ORDER else 0)
    if ftype == TYPE_DATA:
        n = 24
        if flags & FC_TO_DS and flags & FC_FROM_DS:
            n += 6
        if subtype & 0x8:
            n += 2
            if flags & FC_ORDER:
                n += 4
        return n
    if ftype == TYPE_CTRL:
        return 16 if subtype in CTRL_WITH_ADDR2 else 10
    return 10  # extension frames: at least FC + Duration + Addr1


def parse_frame(pkt: RawPacket) -> Frame | None:
    """Parse one captured packet. Returns None for unsupported link types.
    Never raises on malformed input: it sets `error` instead."""
    frame = Frame(idx=pkt.idx, ts=pkt.ts, linktype=pkt.linktype)
    if pkt.linktype == DLT_EN10MB:
        return _parse_ethernet(pkt, frame)
    try:
        body = dot11_bytes(pkt)
    except RadiotapError as exc:
        frame.error = str(exc)
        return frame
    if body is None:
        return None

    # Many drivers capture the 4-byte Frame Check Sequence (a CRC-32 over the
    # whole MAC frame) and say so with the radiotap Flags "FCS at end" bit.
    # Monitor mode also hands up frames that failed the check, and drivers
    # don't reliably set the radiotap "bad FCS" bit, so we verify it ourselves.
    # A corrupted frame can look like anything (a deauth, a bogus address),
    # so later stages must ignore frames with fcs_ok == False.
    if pkt.linktype == DLT_IEEE802_11_RADIO and radiotap_has_fcs(pkt.data):
        if len(body) < 4:
            frame.error = f"truncated: {len(body)} bytes, FCS alone needs 4"
            return frame
        body, fcs = body[:-4], body[-4:]
        # The FCS is sent least-significant byte first (IEEE 802.11-2020 9.2.4.8),
        # which is how zlib.crc32 represents the same CRC.
        frame.fcs_ok = zlib.crc32(body) == int.from_bytes(fcs, "little")

    # Frame Control, byte 0: bits 0-1 protocol version, bits 2-3 type,
    # bits 4-7 subtype. Byte 1 holds the flag bits.
    if len(body) < 2:
        frame.error = f"truncated: {len(body)} bytes, Frame Control needs 2"
        return frame
    fc0, flags = body[0], body[1]
    frame.type = (fc0 >> 2) & 0x3
    frame.subtype = (fc0 >> 4) & 0xF
    frame.retry = bool(flags & FC_RETRY)
    frame.protected = bool(flags & FC_PROTECTED)
    frame.to_ds = bool(flags & FC_TO_DS)
    frame.from_ds = bool(flags & FC_FROM_DS)

    if fc0 & 0x3 != 0:
        # Protocol version 1 is 802.11ah's short "PV1" header, a different
        # layout entirely. Reading it as PV0 would produce garbage addresses.
        frame.error = f"unsupported protocol version {fc0 & 0x3}"
        return frame

    hlen = header_len(frame.type, frame.subtype, flags)
    if len(body) < hlen:
        frame.error = f"truncated: {len(body)} bytes, {frame.name} header needs {hlen}"
        return frame

    if frame.type in (TYPE_CTRL, TYPE_EXT):
        # Control and extension headers are short and fixed, and Scapy's idea
        # of some newer control subtypes differs from the standard layout, so
        # read the addresses directly. Extension frames (e.g. the 60 GHz DMG
        # Beacon) have their own layout; we report only Addr1.
        frame.addr1 = _mac(body, 4)
        if frame.type == TYPE_CTRL and frame.subtype in CTRL_WITH_ADDR2:
            frame.addr2 = _mac(body, 10)
        _resolve_addresses(frame)
        return frame

    # Scapy doesn't know about the HT Control field, so if it's present we
    # remove it (and clear the Order bit) before decoding. That gives Scapy a
    # frame with the same fields, laid out the way it expects.
    for_scapy = body
    has_htc = flags & FC_ORDER and (frame.type == TYPE_MGMT or (frame.type == TYPE_DATA and frame.subtype & 0x8))
    if has_htc:
        for_scapy = bytes([fc0, flags & ~FC_ORDER]) + body[2:hlen - 4] + body[hlen:]
    try:
        dot11 = Dot11(for_scapy)
    except Exception as exc:  # Scapy can raise many types on garbage input
        frame.error = f"scapy decode failed: {exc}"
        return frame

    frame.addr1, frame.addr2, frame.addr3 = dot11.addr1, dot11.addr2, dot11.addr3
    if frame.type == TYPE_DATA and frame.to_ds and frame.from_ds:
        frame.addr4 = dot11.addr4
    if dot11.SC is not None:
        # Sequence Control: low 4 bits fragment number, high 12 bits sequence number.
        frame.seq = dot11.SC >> 4
    _resolve_addresses(frame, _is_amsdu(frame, body))

    if frame.type == TYPE_MGMT:
        _parse_mgmt(frame, dot11, body[hlen:])
    elif frame.type == TYPE_DATA and not frame.protected:
        # A protected data frame's body is encrypted, so we can't see EAPOL or
        # DHCP inside. (The 4-way handshake itself is sent unencrypted,
        # because the keys don't exist yet.)
        _parse_data(frame, dot11)
    return frame


def _is_amsdu(frame: Frame, body: bytes) -> bool:
    """QoS data frames carry an "A-MSDU Present" bit (bit 7 of the first QoS
    Control byte). An A-MSDU packs several packets, each with its own
    source/destination, so the header's Addr3 no longer names one SA or DA."""
    if frame.type != TYPE_DATA or not frame.subtype & 0x8 or frame.subtype & 0x4:
        return False  # not QoS, or a "no data" subtype such as QoS Null
    qos_offset = 30 if frame.to_ds and frame.from_ds else 24
    return len(body) > qos_offset and bool(body[qos_offset] & 0x80)


def _resolve_addresses(frame: Frame, amsdu: bool = False) -> None:
    """Map Addr1-4 to source, destination and BSSID, the same way Wireshark
    fills wlan.sa / wlan.da / wlan.bssid.

    Management frames: Addr1 = DA, Addr2 = SA, Addr3 = BSSID.
    Data frames depend on ToDS/FromDS (IEEE 802.11-2020 9.3.2.1):
        ToDS FromDS   Addr1   Addr2   Addr3   Addr4
         0     0      DA      SA      BSSID   -       (no AP relay, e.g. IBSS)
         1     0      BSSID   SA      DA      -       (client -> AP)
         0     1      DA      BSSID   SA      -       (AP -> client)
         1     1      RA      TA      DA      SA      (mesh/WDS: no single BSSID)
    In an A-MSDU, Addr3 carries the BSSID instead of SA/DA (and in the
    4-address case Addr3/Addr4 aren't SA/DA either), so those stay None.
    Control frames carry receiver/transmitter addresses; only PS-Poll
    (Addr1 = BSSID) and CF-End (Addr2 = BSSID) name the BSS.
    """
    a1, a2, a3 = frame.addr1, frame.addr2, frame.addr3
    if frame.type == TYPE_MGMT:
        frame.da, frame.sa, frame.bssid = a1, a2, a3
    elif frame.type == TYPE_DATA:
        if not frame.to_ds and not frame.from_ds:
            frame.da, frame.sa, frame.bssid = a1, a2, a3
        elif frame.to_ds and not frame.from_ds:
            frame.bssid, frame.sa = a1, a2
            frame.da = None if amsdu else a3
        elif frame.from_ds and not frame.to_ds:
            frame.da, frame.bssid = a1, a2
            frame.sa = None if amsdu else a3
        elif not amsdu:
            frame.da, frame.sa = a3, frame.addr4
    elif frame.type == TYPE_CTRL:
        if frame.subtype == CTRL_PS_POLL:
            frame.bssid = a1
        elif frame.subtype == CTRL_CF_END:
            frame.bssid = a2


def _parse_mgmt(frame: Frame, dot11: Dot11, mgmt_body: bytes) -> None:
    info = MgmtInfo()
    frame.mgmt = info
    if frame.protected:
        # Protected Management Frames (802.11w): a unicast deauth/disassoc or
        # action frame is encrypted with CCMP, so its reason code is hidden.
        return
    need = MGMT_FIXED_LEN.get(frame.subtype, 0)
    if len(mgmt_body) < need:
        frame.error = f"truncated: {frame.name} body has {len(mgmt_body)} bytes, fixed fields need {need}"
        return

    st = frame.subtype
    layer_cls = {
        MGMT_AUTH: Dot11Auth,
        MGMT_ASSOC_RESP: Dot11AssoResp,
        MGMT_REASSOC_RESP: Dot11ReassoResp,
        MGMT_DEAUTH: Dot11Deauth,
        MGMT_DISASSOC: Dot11Disas,
    }.get(st)
    layer = dot11.getlayer(layer_cls) if layer_cls else None
    if layer_cls and layer is None:
        frame.error = f"scapy found no {layer_cls.__name__} layer"
        return

    if st in (MGMT_BEACON, MGMT_PROBE_RESP):
        (cap,) = struct.unpack_from("<H", mgmt_body, 10)  # after Timestamp (8) and Interval (2)
        info.privacy = bool(cap & CAP_PRIVACY)
    elif st == MGMT_AUTH:
        info.auth_algo, info.auth_seq, info.status = int(layer.algo), int(layer.seqnum), int(layer.status)
    elif st in (MGMT_ASSOC_RESP, MGMT_REASSOC_RESP):
        info.status = int(layer.status)
        # The AID field sets its two top bits to 1 for historical reasons;
        # the association ID is the low 14 bits (Wireshark wlan.fixed.aid mask 0x3FFF).
        info.aid = int(layer.AID) & 0x3FFF
    elif st in (MGMT_DEAUTH, MGMT_DISASSOC):
        info.reason = int(layer.reason)

    if st in MGMT_HAS_ELEMENTS:
        _parse_elements(info, mgmt_body[need:])


def _parse_elements(info: MgmtInfo, data: bytes) -> None:
    """Walk the element list: Element ID (1) | Length (1) | Information (Length).
    Stops quietly at a truncated element, as Wireshark does."""
    pos = 0
    while pos + 2 <= len(data):
        eid, length = data[pos], data[pos + 1]
        if pos + 2 + length > len(data):
            break
        value = data[pos + 2:pos + 2 + length]
        pos += 2 + length
        if eid == ELEMENT_ID_SSID and info.ssid is None:
            # 0-32 arbitrary bytes, usually UTF-8. Empty = wildcard probe or hidden SSID.
            info.ssid = value.decode("utf-8", errors="replace")
        elif eid == ELEMENT_ID_DS_PARAMS and length >= 1:
            info.channel = value[0]
        elif eid == ELEMENT_ID_HT_OPERATION and length >= 1 and info.channel is None:
            info.channel = value[0]
        elif eid == ELEMENT_ID_RSN and info.rsn is None:
            info.rsn = parse_rsn(value)
        elif eid == ELEMENT_ID_VENDOR and value[:4] == WPA1_OUI_TYPE:
            info.wpa1 = True


def _parse_data(frame: Frame, dot11: Dot11) -> None:
    # Scapy follows the LLC/SNAP header's EtherType: 0x888E -> EAPOL, 0x0800 -> IP.
    eapol = dot11.getlayer(EAPOL)
    if eapol is not None:
        frame.eapol = parse_eapol(bytes(eapol.original))
        return
    frame.dhcp = _parse_dhcp(dot11)


def parse_eapol(raw: bytes) -> EapolInfo:
    """Parse an EAPOL frame starting at its 4-byte header:
    Protocol Version (1) | Packet Type (1) | Body Length (2, big-endian)."""
    if len(raw) < 4:
        return EapolInfo(packet_type=-1, error=f"EAPOL header truncated: {len(raw)} of 4 bytes")
    ptype = raw[1]
    (length,) = struct.unpack_from(">H", raw, 2)
    info = EapolInfo(packet_type=ptype)
    if ptype != EAPOL_TYPE_KEY:
        return info
    body = raw[4:4 + length]  # anything past `length` is link-layer padding
    if len(body) < length:
        info.error = f"EAPOL-Key truncated: body length says {length}, captured {len(body)}"
        return info
    if len(body) < EAPOL_KEY_MIC_OFFSET:
        info.error = f"EAPOL-Key body too short: {len(body)} bytes, fixed fields need {EAPOL_KEY_MIC_OFFSET}"
        return info

    (info.key_info,) = struct.unpack_from(">H", body, 1)
    (info.replay_counter,) = struct.unpack_from(">Q", body, 5)
    info.nonce_zero = body[13:45] == bytes(32)

    for mic_len in MIC_LENGTH_CANDIDATES:
        off = EAPOL_KEY_MIC_OFFSET + mic_len
        if off + 2 > len(body):
            continue
        (kdl,) = struct.unpack_from(">H", body, off)
        if off + 2 + kdl == len(body):
            info.mic_len, info.key_data_len = mic_len, kdl
            break
    else:
        info.error = "EAPOL-Key Key Data Length doesn't match the body length for any known MIC size"
        return info

    info.message = identify_key_message(info.key_info, info.key_data_len, info.mic_len, info.nonce_zero)
    return info


def identify_key_message(key_info: int, key_data_len: int, mic_len: int, nonce_zero: bool) -> str:
    """Name an EAPOL-Key frame: 4-way handshake M1-M4, group key G1/G2, or a request.

    Follows the logic in Wireshark's dissector (packet-ieee80211.c, the
    "Message 2 of 4" / "Message 4 of 4" decision) because real clients
    don't all follow IEEE 802.11-2020 12.7.6 to the letter:

      * The Ack bit means "sent by the AP, reply expected". Ack without
        Install is M1; Ack with Install is M3 (the AP tells the client to
        install the pairwise key).
      * M2 and M4 both come from the client with the MIC bit set. By the
        standard, M4 has Secure=1 and M2 doesn't. But Windows sets Secure on
        M2 when rekeying, so the Secure bit alone isn't reliable. The
        dependable difference is Key Data: M2 carries the client's RSN
        element, and M4 carries nothing (or 12 bytes in Wi-Fi 7 multi-link).
        Only when Key Data is empty do we look at Secure and the nonce: M2
        always has the client's nonce (SNonce), and M4 usually has a zero nonce.
    """
    if key_info & KI_REQUEST:
        return "REQUEST"  # client asking the AP to start a rekey (or reporting a MIC failure)
    if not key_info & KI_KEY_TYPE_PAIRWISE:
        # Group key handshake (GTK rekey after connection): 2 messages.
        return "G1" if key_info & KI_ACK else "G2"
    if key_info & KI_ACK:
        return "M3" if key_info & KI_INSTALL else "M1"
    if mic_len == 0:
        # AEAD ciphers (FILS) have no separate MIC; encrypted Key Data in M2 is
        # longer than the 16-byte AES-SIV tag that an otherwise-empty M4 carries.
        return "M2" if key_data_len > 16 else "M4"
    if key_data_len not in (0, 12):
        return "M2"
    if key_data_len == 0 and not key_info & KI_SECURE and not nonce_zero:
        return "M2"
    return "M4"


def _parse_dhcp(layer) -> DhcpInfo | None:
    bootp = layer.getlayer(BOOTP)
    dhcp = layer.getlayer(DHCP)
    if bootp is None or dhcp is None:
        return None
    msg_type = None
    for opt in dhcp.options:
        # Option 53 "DHCP Message Type" (RFC 2132 9.6)
        if isinstance(opt, tuple) and opt[0] == "message-type":
            msg_type = int(opt[1])
            break
    if msg_type is None:
        return None  # plain BOOTP, not DHCP
    chaddr = bytes(bootp.chaddr)[:6]
    return DhcpInfo(
        message=DHCP_MESSAGE_TYPES.get(msg_type, f"type {msg_type}"),
        xid=int(bootp.xid),
        client_mac=":".join(f"{b:02x}" for b in chaddr),
        your_ip=bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else None,
    )


def _parse_ethernet(pkt: RawPacket, frame: Frame) -> Frame:
    if len(pkt.data) < 14:  # Destination (6) + Source (6) + EtherType (2)
        frame.error = f"truncated: {len(pkt.data)} bytes, Ethernet header needs 14"
        return frame
    try:
        eth = Ether(pkt.data)
    except Exception as exc:
        frame.error = f"scapy decode failed: {exc}"
        return frame
    frame.da, frame.sa = eth.dst, eth.src
    frame.dhcp = _parse_dhcp(eth)
    return frame


def _mac(data: bytes, offset: int) -> str:
    return ":".join(f"{b:02x}" for b in data[offset:offset + 6])

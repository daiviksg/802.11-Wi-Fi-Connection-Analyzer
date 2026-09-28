"""Parsing 802.11 frames into plain dataclasses.

Milestone 0 covers the 802.11 MAC header (every frame) plus the SSID of
management frames. RSN IE, EAPOL and DHCP parsing come in Milestone 1.

802.11 MAC header (IEEE 802.11-2020, clause 9.2.3):

  Frame Control (2) | Duration/ID (2) | Addr1 (6) | Addr2 (6) | Addr3 (6) |
  Sequence Control (2) | [Addr4 (6)] | [QoS Control (2)] | ...

Not every frame has every field, so the header length depends on the frame
type. See `min_header_len`.
"""

from __future__ import annotations

import zlib
from dataclasses import asdict, dataclass

from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap

from .capture import DLT_IEEE802_11_RADIO, RadiotapError, RawPacket, dot11_bytes

TYPE_MGMT, TYPE_CTRL, TYPE_DATA, TYPE_EXT = 0, 1, 2, 3
TYPE_NAMES = {TYPE_MGMT: "mgmt", TYPE_CTRL: "ctrl", TYPE_DATA: "data", TYPE_EXT: "ext"}

# Management subtypes, IEEE 802.11-2020 Table 9-1. Subtypes 7 and 15 are reserved.
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

# Management subtypes whose body carries an SSID element. The Beacon and Probe
# Response bodies start with fixed fields, then elements; Probe Request has only
# elements. (Re)Association Requests include the SSID the client is joining.
# Scapy knows each body layout, so we just search its parsed elements.
SSID_SUBTYPES = {0, 2, 4, 5, 8}

# Frame Control flag bits (second byte of the FC field), IEEE 802.11-2020 9.2.4.1.
FC_TO_DS = 0x01
FC_FROM_DS = 0x02
FC_RETRY = 0x08
FC_PROTECTED = 0x40

ELEMENT_ID_SSID = 0


@dataclass
class Dot11Frame:
    idx: int
    ts: float
    type: int | None = None
    subtype: int | None = None
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    seq: int | None = None
    retry: bool | None = None
    protected: bool | None = None
    to_ds: bool | None = None
    from_ds: bool | None = None
    ssid: str | None = None
    fcs_ok: bool | None = None  # None: the capture has no FCS to check
    error: str | None = None  # set when the frame couldn't be fully parsed

    @property
    def name(self) -> str:
        if self.type is None:
            return "Malformed"
        if self.type == TYPE_MGMT:
            return MGMT_SUBTYPE_NAMES.get(self.subtype, f"Mgmt subtype {self.subtype}")
        return f"{TYPE_NAMES[self.type].capitalize()} subtype {self.subtype}"

    def to_dict(self) -> dict:
        return asdict(self)


def min_header_len(ftype: int, subtype: int, flags: int) -> int:
    """Bytes of MAC header we need before trusting the address/sequence fields.

    IEEE 802.11-2020 clause 9.3:
      * Management frames: FC, Duration, Addr1-3, Seq Ctrl = 24 bytes.
      * Data frames: the same 24, plus Addr4 (6) when both ToDS and FromDS are
        set (wireless distribution system), plus QoS Control (2) for QoS data
        subtypes (subtype bit 3 set).
      * Control frames are short. ACK and CTS carry only Addr1 (10 bytes).
        RTS, PS-Poll, CF-End, BlockAckReq and BlockAck also carry Addr2 (16).
    """
    if ftype == TYPE_MGMT:
        return 24
    if ftype == TYPE_DATA:
        n = 24
        if flags & FC_TO_DS and flags & FC_FROM_DS:
            n += 6
        if subtype & 0x8:
            n += 2
        return n
    if ftype == TYPE_CTRL:
        return 16 if subtype in (8, 9, 10, 11, 14, 15) else 10
    return 10  # extension frames (e.g. DMG beacon): at least FC + Duration + Addr1


def parse_frame(pkt: RawPacket) -> Dot11Frame | None:
    """Parse one captured packet. Returns None if it isn't an 802.11 frame
    (e.g. Ethernet). Never raises on malformed input; sets `error` instead."""
    frame = Dot11Frame(idx=pkt.idx, ts=pkt.ts)
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
    if pkt.linktype == DLT_IEEE802_11_RADIO and _radiotap_says_fcs(pkt.data):
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

    need = min_header_len(frame.type, frame.subtype, flags)
    if len(body) < need:
        frame.error = f"truncated: {len(body)} bytes, {frame.name} header needs {need}"
        return frame

    # The header is all there, so Scapy can decode it. Decoding from the
    # radiotap layer (not the stripped bytes) lets Scapy see the radiotap
    # "FCS at end" flag and drop the 4-byte checksum before parsing elements.
    try:
        decoded = RadioTap(pkt.data) if pkt.linktype == DLT_IEEE802_11_RADIO else Dot11(body)
    except Exception as exc:  # Scapy can raise many types on garbage input
        frame.error = f"scapy decode failed: {exc}"
        return frame
    dot11 = decoded.getlayer(Dot11)
    if dot11 is None:
        frame.error = "scapy found no 802.11 layer"
        return frame

    # Scapy leaves fields a frame type doesn't have (e.g. Addr3 on a
    # control frame) as None, which is what we want.
    frame.addr1 = dot11.addr1
    frame.addr2 = dot11.addr2
    frame.addr3 = dot11.addr3
    if dot11.SC is not None:
        # Sequence Control: low 4 bits fragment number, high 12 bits sequence number.
        frame.seq = dot11.SC >> 4

    if frame.type == TYPE_MGMT and frame.subtype in SSID_SUBTYPES and not frame.protected:
        frame.ssid = _find_ssid(dot11)
    return frame


def _radiotap_says_fcs(data: bytes) -> bool:
    """True if the radiotap Flags field is present with the FCS-at-end bit (0x10).

    Finding Flags means walking the radiotap "present" bitmaps and field
    alignments. Scapy already does that; the C parser does it by hand.
    """
    try:
        rt = RadioTap(data)
    except Exception:
        return False
    return bool(rt.present and rt.present.Flags and rt.Flags is not None and rt.Flags.FCS)


def _find_ssid(dot11: Dot11) -> str | None:
    elt = dot11.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == ELEMENT_ID_SSID:
            # SSIDs are 0-32 arbitrary bytes, usually UTF-8. A zero-length (or
            # all-zero) SSID means a hidden network or a wildcard probe.
            return bytes(elt.info).decode("utf-8", errors="replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return None

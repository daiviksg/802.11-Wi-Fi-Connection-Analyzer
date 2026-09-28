"""Reading capture files and handling pcap link types.

A capture file tells us, through its *link type* (a "DLT" number), what the
first byte of every packet is. We support three:

  * DLT_IEEE802_11_RADIO (127): a radiotap header, then the 802.11 frame.
    Radiotap is metadata added by the capturing driver (signal strength,
    channel, data rate...). It is not sent over the air. Its length varies
    with the fields present, so we always read it from the header.
  * DLT_IEEE802_11 (105): the 802.11 frame starts at byte 0.
  * DLT_EN10MB (1): Ethernet. There are no 802.11 frames here; only the
    DHCP analysis applies (wired-side captures).

We read the *raw bytes* ourselves (not Scapy's pre-decoded packets). If
Scapy can't decode a truncated frame it falls back to a generic `Raw`
packet, and then we'd lose both the link type and the frame. Keeping the
bytes lets us report exactly how truncated a frame is.

DLT numbers: https://www.tcpdump.org/linktypes.html
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Scapy warns at import time on Windows if Npcap isn't installed. We only
# read files, so the warning is noise.
for _name in ("scapy.runtime", "scapy.loading"):
    logging.getLogger(_name).setLevel(logging.ERROR)

from scapy.utils import RawPcapNgReader, RawPcapReader  # noqa: E402

DLT_EN10MB = 1
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127

LINKTYPE_NAMES = {
    DLT_EN10MB: "Ethernet",
    DLT_IEEE802_11: "802.11",
    DLT_IEEE802_11_RADIO: "802.11 + radiotap",
}

# Radiotap header layout (https://www.radiotap.org/):
#   it_version (u8, always 0), it_pad (u8), it_len (u16 little-endian), it_present (u32 LE)...
# it_len covers the whole radiotap header, including all present fields.
RADIOTAP_MIN_LEN = 8


class RadiotapError(ValueError):
    """The radiotap header is malformed or longer than the captured bytes."""


@dataclass(frozen=True)
class RawPacket:
    idx: int  # 1-based, same numbering as Wireshark's frame.number
    ts: float  # seconds since the Unix epoch
    linktype: int
    data: bytes  # exactly the captured bytes (caplen of them)


def read_packets(path: str | Path) -> Iterator[RawPacket]:
    """Yield every packet in a .pcap or .pcapng file, in file order."""
    # RawPcapReader looks at the file's magic number and returns a
    # RawPcapNgReader instead when the file is pcapng.
    with RawPcapReader(str(path)) as reader:
        for idx, (data, meta) in enumerate(reader, start=1):
            if isinstance(reader, RawPcapNgReader):
                # pcapng: each interface has its own link type and timestamp
                # resolution; the timestamp is a 64-bit count of units.
                ticks = (meta.tshigh << 32) | meta.tslow
                ts = ticks / meta.tsresol
                linktype = meta.linktype
            else:
                # classic pcap: one link type for the whole file. The "usec"
                # field holds nanoseconds when the file uses the nanosecond magic.
                ts = meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
                linktype = reader.linktype
            yield RawPacket(idx=idx, ts=ts, linktype=linktype, data=bytes(data))


def radiotap_length(data: bytes) -> int:
    """Return it_len, the number of bytes to skip to reach the 802.11 header."""
    if len(data) < RADIOTAP_MIN_LEN:
        raise RadiotapError(f"radiotap header truncated: {len(data)} of {RADIOTAP_MIN_LEN} bytes")
    if data[0] != 0:
        # Only version 0 has ever been defined; anything else isn't radiotap.
        raise RadiotapError(f"unknown radiotap version {data[0]}")
    (it_len,) = struct.unpack_from("<H", data, 2)
    if it_len < RADIOTAP_MIN_LEN:
        raise RadiotapError(f"radiotap it_len {it_len} is smaller than the fixed header")
    if it_len > len(data):
        raise RadiotapError(f"radiotap it_len {it_len} exceeds captured length {len(data)}")
    return it_len


def dot11_bytes(pkt: RawPacket) -> bytes | None:
    """Return the 802.11 frame bytes (radiotap stripped), or None if this
    link type doesn't carry 802.11. Raises RadiotapError on a bad header."""
    if pkt.linktype == DLT_IEEE802_11_RADIO:
        return pkt.data[radiotap_length(pkt.data):]
    if pkt.linktype == DLT_IEEE802_11:
        return pkt.data
    return None


# radiotap it_present bits (radiotap.org "Defined fields") and Flags bits.
RADIOTAP_PRESENT_TSFT = 1 << 0  # u64, aligned to 8 bytes
RADIOTAP_PRESENT_FLAGS = 1 << 1  # u8
RADIOTAP_PRESENT_EXT = 1 << 31  # another present word follows
RADIOTAP_FLAG_FCS_AT_END = 0x10


def radiotap_has_fcs(data: bytes) -> bool:
    """True if the radiotap Flags field says the frame ends with its 4-byte FCS.

    The present bitmaps come first (another u32 follows while bit 31 is set),
    then the fields in bit order, each aligned to its size, counted from the
    start of the header. Only TSFT (bit 0, u64) can come before Flags (bit 1).
    We read Flags even if later fields are malformed: its position doesn't
    depend on them. Every read stays inside it_len.
    """
    try:
        it_len = radiotap_length(data)
    except RadiotapError:
        return False
    (present0,) = struct.unpack_from("<I", data, 4)
    off, word = 4, present0
    while word & RADIOTAP_PRESENT_EXT:
        off += 4
        if off + 4 > it_len:
            return False
        (word,) = struct.unpack_from("<I", data, off)
    off += 4
    if present0 & RADIOTAP_PRESENT_TSFT:
        off = (off + 7) // 8 * 8 + 8
    if present0 & RADIOTAP_PRESENT_FLAGS and off < it_len:
        return bool(data[off] & RADIOTAP_FLAG_FCS_AT_END)
    return False

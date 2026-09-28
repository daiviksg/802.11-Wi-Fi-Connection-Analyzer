"""Shared test helpers.

Synthetic frames use *locally administered* MAC addresses (second-lowest bit
of the first byte set, e.g. 02:...). No real device ever has one of those
burned in, so test data can't leak anyone's hardware address.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.dot11 import (
    Dot11,
    Dot11Auth,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
)
from scapy.utils import wrpcap

AP = "02:00:00:00:00:aa"
STA = "02:00:00:00:00:01"
BCAST = "ff:ff:ff:ff:ff:ff"

PUBLIC_DIR = Path(__file__).parent / "data" / "public"


def beacon(ssid: str = "LabNet", seq: int = 100) -> Dot11:
    return (
        Dot11(type=0, subtype=8, addr1=BCAST, addr2=AP, addr3=AP, SC=seq << 4)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=ssid.encode())
    )


def probe_req(ssid: str = "LabNet", seq: int = 1) -> Dot11:
    return (
        Dot11(type=0, subtype=4, addr1=BCAST, addr2=STA, addr3=BCAST, SC=seq << 4)
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=ssid.encode())
    )


def auth_req(seq: int = 2) -> Dot11:
    return Dot11(type=0, subtype=11, addr1=AP, addr2=STA, addr3=AP, SC=seq << 4) / Dot11Auth(
        algo=0, seqnum=1, status=0
    )


@pytest.fixture
def write_pcap(tmp_path):
    """Write packets (Scapy packets or raw bytes) to a pcap with a given link type."""

    def _write(name: str, packets, linktype: int) -> Path:
        path = tmp_path / name
        # Fixed timestamps keep the files deterministic.
        for i, p in enumerate(packets):
            if not isinstance(p, bytes):
                p.time = 1_700_000_000 + i * 0.001
        wrpcap(str(path), packets, linktype=linktype)
        return path

    return _write


@pytest.fixture
def radiotap_capture(write_pcap):
    frames = [RadioTap() / beacon(), RadioTap() / probe_req(), RadioTap() / auth_req()]
    return write_pcap("basic.pcap", frames, linktype=127)

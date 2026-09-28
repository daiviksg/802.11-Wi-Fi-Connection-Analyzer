"""Shared test fixtures. Frame builders live in builders.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from scapy.layers.dot11 import RadioTap
from scapy.utils import wrpcap

sys.path.insert(0, str(Path(__file__).parent))  # so tests can `import builders`

from builders import auth, beacon, probe_req  # noqa: E402

PUBLIC_DIR = Path(__file__).parent / "data" / "public"
SYNTHETIC_DIR = Path(__file__).parent / "data" / "synthetic"


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
    frames = [RadioTap() / beacon(rsn=None), RadioTap() / probe_req(), RadioTap() / auth(True)]
    return write_pcap("basic.pcap", frames, linktype=127)

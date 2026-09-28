"""Checks against real public captures (see tests/data/public/SOURCES.md).

These files aren't committed. Run `python tests/data/public/fetch.py` first;
the tests are skipped if a file is missing.

The expected values were read with this parser. The bad-FCS count was
confirmed by recomputing each CRC-32 independently. Milestone 4 checks
the header fields against tshark automatically.
"""

from __future__ import annotations

from collections import Counter

import pytest
from click.testing import CliRunner
from conftest import PUBLIC_DIR

from wifi_analyzer.capture import read_packets
from wifi_analyzer.cli import main
from wifi_analyzer.frames import parse_frame

WPA_INDUCTION = PUBLIC_DIR / "wpa-Induction.pcap"
AP = "00:0c:41:82:b2:55"
CLIENT = "00:0d:93:82:36:3a"

needs_wpa_induction = pytest.mark.skipif(
    not WPA_INDUCTION.exists(), reason="run tests/data/public/fetch.py to download"
)


@needs_wpa_induction
def test_wpa_induction_frames():
    frames = [parse_frame(p) for p in read_packets(WPA_INDUCTION)]
    assert len(frames) == 1093
    assert all(f is not None for f in frames)

    # This capture keeps the FCS; 13 frames were received corrupted.
    assert Counter(f.fcs_ok for f in frames) == {True: 1080, False: 13}
    good = [f for f in frames if f.fcs_ok]
    assert all(f.error is None for f in good)

    beacons = [f for f in good if f.type == 0 and f.subtype == 8]
    assert beacons and all(f.ssid == "Coherer" and f.addr2 == AP for f in beacons)

    # The client's join sequence: authentication, association, and later disassociation.
    client_mgmt = [
        (f.idx, f.name) for f in good
        if f.type == 0 and CLIENT in (f.addr1, f.addr2) and f.subtype not in (4, 5)
    ]
    assert client_mgmt == [
        (78, "Authentication"),
        (80, "Authentication"),
        (82, "Assoc Request"),
        (84, "Assoc Response"),
        (1050, "Disassociation"),
    ]


@needs_wpa_induction
def test_wpa_induction_cli():
    result = CliRunner().invoke(main, ["frames", "--limit", "1", str(WPA_INDUCTION)])
    assert result.exit_code == 0
    assert 'Beacon' in result.output and 'ssid="Coherer"' in result.output

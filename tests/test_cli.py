"""Tests for the `wifi-analyzer frames` command."""

from __future__ import annotations

import json

from click.testing import CliRunner
from builders import STA, auth, beacon
from scapy.layers.dot11 import Dot11, RadioTap

from wifi_analyzer.cli import main


def run(*args):
    result = CliRunner().invoke(main, [str(a) for a in args])
    assert result.exit_code == 0, result.output
    return result.output.splitlines()


def test_frames_lists_management_only_by_default(write_pcap):
    ack = Dot11(type=1, subtype=13, addr1=STA)
    path = write_pcap("mix.pcap", [RadioTap() / beacon(), RadioTap() / ack, RadioTap() / auth(True)], 127)
    lines = run("frames", path)
    assert len(lines) == 2
    assert "Beacon" in lines[0] and 'ssid="LabNet"' in lines[0]
    assert "Authentication" in lines[1]
    assert len(run("frames", "--all", path)) == 3


def test_frames_limit_and_json(radiotap_capture):
    lines = run("frames", "--limit", 2, "--format", "json", radiotap_capture)
    records = [json.loads(line) for line in lines]
    assert [r["idx"] for r in records] == [1, 2]
    assert records[0]["subtype"] == 8 and records[0]["mgmt"]["ssid"] == "LabNet"


def test_frames_shows_malformed(write_pcap):
    cut = bytes(RadioTap() / auth(True))[:20]
    path = write_pcap("t.pcap", [cut], 127)
    (line,) = run("frames", path)
    assert "ERROR: truncated" in line

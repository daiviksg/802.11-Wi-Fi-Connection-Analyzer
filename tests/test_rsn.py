"""RSN element parsing and security type detection (SPEC.md 4.3)."""

from __future__ import annotations

import struct

from builders import TRANSITION_RSN, WPA2_RSN, WPA3_RSN, rsn_body

from wifi_analyzer.rsn import classify_security, cipher_name, parse_rsn


def test_wpa2_personal():
    rsn = parse_rsn(WPA2_RSN)
    assert (rsn.version, rsn.group_cipher, rsn.pairwise_ciphers, rsn.akms) == (1, 4, [4], [2])
    assert not rsn.mfpc and not rsn.mfpr and rsn.error is None
    sec = classify_security(rsn, privacy=True)
    assert sec.name == "WPA2-Personal" and sec.pmf == "disabled"
    assert str(sec) == "WPA2-Personal (PSK)"
    assert cipher_name(rsn.group_cipher) == "CCMP-128"


def test_wpa3_personal_requires_pmf():
    rsn = parse_rsn(WPA3_RSN)
    assert rsn.akms == [8] and rsn.mfpc and rsn.mfpr
    sec = classify_security(rsn, privacy=True)
    assert str(sec) == "WPA3-Personal (SAE, PMF required)"
    assert sec.notes == []


def test_wpa3_without_pmf_is_flagged():
    sec = classify_security(parse_rsn(rsn_body(akms=(8,), caps=0)), privacy=True)
    assert sec.name == "WPA3-Personal"
    assert any("requires PMF" in n for n in sec.notes)


def test_transition_mode():
    rsn = parse_rsn(TRANSITION_RSN)
    assert rsn.akms == [2, 8] and rsn.mfpc and not rsn.mfpr
    sec = classify_security(rsn, privacy=True)
    assert str(sec) == "WPA3-Personal transition (PSK, SAE, PMF capable)"
    assert sec.notes == []


def test_enterprise_and_owe():
    assert classify_security(parse_rsn(rsn_body(akms=(1,))), True).name == "Enterprise (802.1X)"
    assert classify_security(parse_rsn(rsn_body(akms=(12,), caps=0xC0)), True).name == "WPA3-Enterprise 192-bit"
    assert classify_security(parse_rsn(rsn_body(akms=(18,), caps=0xC0)), True).name == "Enhanced Open (OWE)"


def test_open_wep_and_legacy_wpa():
    assert str(classify_security(None, privacy=False)) == "Open"
    assert classify_security(None, privacy=True).name == "WEP"
    assert classify_security(None, privacy=True, has_wpa1_ie=True).name == "WPA (legacy)"
    assert not classify_security(None, privacy=False).uses_rsn
    assert classify_security(parse_rsn(WPA2_RSN), True).uses_rsn


def test_vendor_akm_kept_as_string():
    body = struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    body += struct.pack("<H", 1) + b"\x00\x40\x96\x00"  # vendor OUI
    rsn = parse_rsn(body)
    assert rsn.akms == ["00-40-96:0"]
    assert rsn.capabilities is None  # optional field left off the end: legal


def test_version_only_is_legal():
    rsn = parse_rsn(struct.pack("<H", 1))
    assert rsn.version == 1 and rsn.error is None and rsn.akms == []


def test_truncated_list_reports_error():
    # Claims 2 AKM suites but only carries one.
    body = WPA2_RSN[:12] + struct.pack("<H", 2) + b"\x00\x0f\xac\x02"
    rsn = parse_rsn(body)
    assert rsn.akms == []
    assert "AKM list" in rsn.error
    assert parse_rsn(b"\x01").error.startswith("RSN element truncated in version")

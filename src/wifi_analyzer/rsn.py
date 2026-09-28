"""RSN element parsing and security-type detection.

The RSN element (Element ID 48, IEEE 802.11-2020 9.4.2.24) is how an AP
advertises its security in Beacons and Probe Responses. A client puts its
own RSN element in the (Re)Association Request to say which options it chose.
All multi-byte fields are little-endian:

  Version (2) | Group Data Cipher Suite (4) |
  Pairwise Cipher Suite Count (2) | Pairwise Cipher Suite List (4 * n) |
  AKM Suite Count (2) | AKM Suite List (4 * m) |
  RSN Capabilities (2) | PMKID Count (2) | PMKID List (16 * p) |
  Group Management Cipher Suite (4)

Everything after Version may be left off the end, and a parser must accept
that. A suite selector is a 3-byte OUI plus a 1-byte type. For the standard
suites the OUI is 00-0F-AC.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .codes import AKM_SUITES, CIPHER_SUITES

ELEMENT_ID_RSN = 48
STANDARD_OUI = b"\x00\x0f\xac"

# RSN Capabilities bits. Masks as in Wireshark's fields
# wlan.rsn.capabilities.mfpr (0x0040) and wlan.rsn.capabilities.mfpc (0x0080).
RSN_CAP_MFPR = 0x0040  # Management Frame Protection Required
RSN_CAP_MFPC = 0x0080  # Management Frame Protection Capable

AKM_8021X = {1, 3, 5, 11, 12, 13}
AKM_PSK = {2, 4, 6}
AKM_SAE = {8, 9, 24, 25}
AKM_OWE = {18}
AKM_SUITE_B_192 = {12, 13}

Suite = int | str  # int: type under 00-0F-AC; str: "aa-bb-cc:t" for vendor suites


@dataclass
class RsnInfo:
    version: int | None = None
    group_cipher: Suite | None = None
    pairwise_ciphers: list[Suite] = field(default_factory=list)
    akms: list[Suite] = field(default_factory=list)
    capabilities: int | None = None
    error: str | None = None  # set if the element was cut short mid-field

    @property
    def mfpc(self) -> bool:
        return bool(self.capabilities and self.capabilities & RSN_CAP_MFPC)

    @property
    def mfpr(self) -> bool:
        return bool(self.capabilities and self.capabilities & RSN_CAP_MFPR)


def _suite(raw: bytes) -> Suite:
    if raw[:3] == STANDARD_OUI:
        return raw[3]
    return f"{raw[0]:02x}-{raw[1]:02x}-{raw[2]:02x}:{raw[3]}"


def parse_rsn(data: bytes) -> RsnInfo:
    """Parse the body of an RSN element (the bytes after ID and Length)."""
    info = RsnInfo()
    pos = 0

    def need(n: int, what: str) -> bool:
        # Every read goes through here, so we never index past the end.
        if pos + n > len(data):
            info.error = f"RSN element truncated in {what}: need {n} bytes at offset {pos}, have {len(data) - pos}"
            return False
        return True

    if not need(2, "version"):
        return info
    (info.version,) = struct.unpack_from("<H", data, pos)
    pos += 2
    if pos == len(data):
        return info  # legal: only the version is present

    if not need(4, "group cipher"):
        return info
    info.group_cipher = _suite(data[pos:pos + 4])
    pos += 4
    if pos == len(data):
        return info

    for label, target in (("pairwise cipher list", info.pairwise_ciphers), ("AKM list", info.akms)):
        if not need(2, f"{label} count"):
            return info
        (count,) = struct.unpack_from("<H", data, pos)
        pos += 2
        if not need(4 * count, label):
            return info
        for i in range(count):
            target.append(_suite(data[pos + 4 * i:pos + 4 * i + 4]))
        pos += 4 * count
        if pos == len(data):
            return info

    if not need(2, "RSN capabilities"):
        return info
    (info.capabilities,) = struct.unpack_from("<H", data, pos)
    # PMKID list and group management cipher follow; we don't need them.
    return info


@dataclass
class Security:
    name: str  # e.g. "WPA3-Personal", "Open"
    akms: list[str] = field(default_factory=list)
    pmf: str = "disabled"  # "required", "capable" or "disabled"
    notes: list[str] = field(default_factory=list)

    @property
    def uses_rsn(self) -> bool:
        """True if joining requires the EAPOL 4-way handshake."""
        return self.name not in ("Open", "WEP", "Unknown")

    def __str__(self) -> str:
        details = ", ".join(self.akms)
        if self.pmf != "disabled":
            details = f"{details}, PMF {self.pmf}" if details else f"PMF {self.pmf}"
        return f"{self.name} ({details})" if details else self.name


def classify_security(rsn: RsnInfo | None, privacy: bool | None, has_wpa1_ie: bool = False) -> Security:
    """Name a network's security from its RSN element and Privacy capability bit."""
    if rsn is None:
        if has_wpa1_ie:
            # Pre-802.11i WPA uses a vendor element (OUI 00-50-F2, type 1) instead of RSN.
            return Security("WPA (legacy)")
        if privacy:
            # Privacy bit set but no RSN or WPA element: static WEP.
            return Security("WEP")
        if privacy is None:
            return Security("Unknown")
        return Security("Open")

    std = {a for a in rsn.akms if isinstance(a, int)}
    akm_names = [AKM_SUITES.get(a, f"AKM {a}") if isinstance(a, int) else f"vendor AKM {a}" for a in rsn.akms]
    pmf = "required" if rsn.mfpr else "capable" if rsn.mfpc else "disabled"
    notes: list[str] = []

    has_sae, has_psk = bool(std & AKM_SAE), bool(std & AKM_PSK)
    if has_sae and has_psk:
        # Transition mode: WPA3 clients use SAE, older clients use PSK on the same SSID.
        name = "WPA3-Personal transition"
    elif has_sae:
        name = "WPA3-Personal"
    elif has_psk:
        name = "WPA2-Personal"
    elif std & AKM_SUITE_B_192:
        name = "WPA3-Enterprise 192-bit"
    elif std & AKM_8021X:
        name = "Enterprise (802.1X)"
    elif std & AKM_OWE:
        name = "Enhanced Open (OWE)"
    else:
        name = "RSN"

    # WPA3 requires Protected Management Frames: SAE-only networks must set
    # MFPR; transition mode must at least set MFPC (Wi-Fi Alliance WPA3 Specification,
    # WPA3-Personal Only Mode and WPA3-Personal Transition Mode).
    if has_sae and not has_psk and not rsn.mfpr:
        notes.append("WPA3-Personal requires PMF (MFPR=1), but this network does not require it")
    elif has_sae and not rsn.mfpc:
        notes.append("WPA3 transition mode requires PMF capable (MFPC=1)")
    if rsn.error:
        notes.append(rsn.error)
    return Security(name, akm_names, pmf, notes)


def cipher_name(suite: Suite | None) -> str:
    if suite is None:
        return "none"
    if isinstance(suite, str):
        return f"vendor {suite}"
    return CIPHER_SUITES.get(suite, f"cipher {suite}")

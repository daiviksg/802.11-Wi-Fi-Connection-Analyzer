"""Lookup tables for 802.11 status codes, reason codes, and other numbered fields.

Sources:
  * IEEE Std 802.11-2020, 9.4.1.7 (Reason Code field) and 9.4.1.9 (Status Code field).
  * Wireshark's 802.11 dissector, epan/dissectors/packet-ieee80211.c
    (tables `ieee80211_reason_code`, `ieee80211_status_code`, `auth_alg`,
    `ieee80211_rsn_keymgmt_vals`, `ieee80211_rsn_cipher_vals`; master branch,
    read 2026-09-28). The text below is copied from those tables, so our
    output uses the same wording a Wireshark user would see.

Only codes that come up in connection troubleshooting are listed. Unknown
codes are reported as "unknown code N", never guessed.
"""

from __future__ import annotations

# --- Status codes (Authentication / (Re)Association Response) ---------------
STATUS_CODES: dict[int, str] = {
    0: "Successful",
    1: "Unspecified failure",
    10: "Cannot support all requested capabilities in the Capability Information field",
    11: "Reassociation denied due to inability to confirm that association exists",
    12: "Association denied due to reason outside the scope of this standard",
    13: "Responding STA does not support the specified authentication algorithm",
    14: "Received an Authentication frame with authentication transaction sequence number out of expected sequence",
    15: "Authentication rejected because of challenge failure",
    16: "Authentication rejected due to timeout waiting for next frame in sequence",
    17: "Association denied because AP is unable to handle additional associated STAs",
    18: "Association denied due to requesting STA not supporting all of the data rates in the BSSBasicRateSet parameter, the Basic HT-MCS Set field of the HT Operation parameter, or the Basic VHT-MCS and NSS Set field in the VHT Operation parameter",
    19: "Association denied due to requesting STA not supporting the short preamble option",
    22: "Association request rejected because spectrum management capability is required",
    23: "Association request rejected because the information in the Power Capability element is unacceptable",
    24: "Association request rejected because the information in the Supported Channels element is unacceptable",
    25: "Association denied due to requesting STA not supporting short slot time",
    27: "Association denied because the requesting STA does not support HT features",
    30: "Association request rejected temporarily; try again later",
    31: "Robust management frame policy violation",
    32: "Unspecified, QoS-related failure",
    33: "Association denied because QoS AP or PCP has insufficient bandwidth to handle another QoS STA",
    34: "Association denied due to excessive frame loss rates and/ or poor conditions on current operating channel",
    35: "Association (with QoS BSS) denied because the requesting STA does not support the QoS facility",
    37: "The request has been declined",
    38: "The request has not been successful as one or more parameters have invalid values",
    40: "Invalid element, i.e., an element defined in this standard for which the content does not meet the specifications in Clause 9 (Frame formats)",
    41: "Invalid group cipher",
    42: "Invalid pairwise cipher",
    43: "Invalid AKMP",
    44: "Unsupported RSNE version",
    45: "Invalid RSNE capabilities",
    46: "Cipher suite rejected because of security policy",
    51: "Association denied because the listen interval is too large",
    53: "Invalid pairwise master key identifier (PMKID)",
    54: "Invalid MDE",
    55: "Invalid FTE",
    72: "Invalid contents of RSNE, other than unsupported RSNE version or invalid RSNE capabilities, AKMP or pairwise cipher",
    76: "Authentication is rejected because an anti-clogging token is required",
    77: "Authentication is rejected because the offered finite cyclic group is not supported",
    82: "Rejected with suggested BSS transition",
    92: "(Re)Association refused for some external reason",
    93: "(Re)Association refused because of memory limits at the AP",
    94: "(Re)Association refused because emergency services are not supported at the AP",
    104: "Association denied because the requesting STA does not support VHT features",
    112: "Authentication rejected due to FILS authentication failure",
    113: "Authentication rejected due to unknown Authentication Server",
    123: "Authentication rejected because the password identifier is unknown",
    126: "SAE authentication uses direct hashing, instead of looping, to obtain the PWE",
    135: "Association denied because the requesting STA does not support EHT features",
}

# Status codes that are *not* failures in an Authentication frame.
#   126 (SAE_HASH_TO_ELEMENT): an SAE commit sent with status 126 means "I'm
#       using the hash-to-element PWE derivation"; the exchange is proceeding.
#   76 (anti-clogging token required): the AP is under load and asks the client
#       to resend its SAE commit with a token; the exchange goes on.
AUTH_STATUS_OK = {0, 126}
AUTH_STATUS_RETRY = {76}

# --- Reason codes (Deauthentication / Disassociation) ------------------------
REASON_CODES: dict[int, str] = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving (or has left) the BSS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving (or has left) BSS",
    9: "STA requesting (re)association is not authenticated with responding STA",
    10: "Disassociated because the information in the Power Capability element is unacceptable",
    11: "Disassociated because the information in the Supported Channels element is unacceptable",
    12: "Disassociated due to BSS transition management",
    13: "Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 9",
    14: "Message integrity code (MIC) failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Element in 4-way handshake different from (Re)Association Request/Probe Response/Beacon frame",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of the security policy",
    32: "Disassociated for unspecified, QoS-related reason",
    33: "Disassociated because QoS AP lacks sufficient bandwidth for this QoS STA",
    34: "Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions",
    35: "Disassociated because STA is transmitting outside the limits of its TXOPs",
    36: "Requested from peer STA as the STA is leaving the BSS (or resetting)",
    37: "Requesting STA is no longer using the stream or session",
    38: "Requesting STA received frames using a mechanism for which a setup has not been completed",
    39: "Requested from peer STA due to timeout",
    46: "Disassociated because authorized access limit reached",
    47: "Disassociated due to external service requirements",
    48: "Invalid FT Action frame count",
    49: "Invalid pairwise master key identifier (PMKID)",
    50: "Invalid MDE",
    51: "Invalid FTE",
    71: "Disassociated due to poor RSSI",
}

# Reason codes a client uses when it leaves on purpose (switching networks,
# turning Wi-Fi off). After a successful connection, these aren't failures.
REASON_LEAVING = {3, 8}

# --- Authentication algorithm numbers (802.11-2020 9.4.1.1) ------------------
AUTH_ALGORITHMS: dict[int, str] = {
    0: "Open System",
    1: "Shared key",
    2: "Fast BSS Transition",
    3: "Simultaneous Authentication of Equals (SAE)",
    4: "FILS Shared Key authentication without PFS",
    5: "FILS Shared Key authentication with PFS",
    6: "FILS Public Key authentication",
}
AUTH_ALGO_OPEN = 0
AUTH_ALGO_SAE = 3

# --- RSN suite selectors under OUI 00-0F-AC (802.11-2020 9.4.2.24) ---------
AKM_SUITES: dict[int, str] = {
    1: "802.1X",
    2: "PSK",
    3: "FT over 802.1X",
    4: "FT using PSK",
    5: "802.1X (SHA256)",
    6: "PSK (SHA256)",
    8: "SAE",
    9: "FT using SAE",
    11: "802.1X Suite B (SHA256)",
    12: "802.1X Suite B (SHA384)",
    13: "FT over 802.1X (SHA384)",
    18: "OWE",
    24: "SAE (group-dependent hash)",
    25: "FT using SAE (group-dependent hash)",
}

CIPHER_SUITES: dict[int, str] = {
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

# --- DHCP message types (RFC 2132 section 9.6) -------------------------------
DHCP_MESSAGE_TYPES: dict[int, str] = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


def _lookup(table: dict[int, str], code: int | None) -> str:
    if code is None:
        return "unknown"
    return table.get(code, f"unknown code {code}")


def status_text(code: int | None) -> str:
    return _lookup(STATUS_CODES, code)


def reason_text(code: int | None) -> str:
    return _lookup(REASON_CODES, code)


def auth_algo_text(algo: int | None) -> str:
    return _lookup(AUTH_ALGORITHMS, algo)

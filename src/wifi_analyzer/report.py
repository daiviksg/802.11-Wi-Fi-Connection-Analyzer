"""Human-readable text for frames (and, from Milestone 2, analysis reports)."""

from __future__ import annotations

from .codes import AUTH_ALGO_SAE, auth_algo_text, reason_text, status_text
from .frames import (
    MGMT_ASSOC_REQ,
    MGMT_ASSOC_RESP,
    MGMT_AUTH,
    MGMT_BEACON,
    MGMT_DEAUTH,
    MGMT_DISASSOC,
    MGMT_PROBE_REQ,
    MGMT_PROBE_RESP,
    MGMT_REASSOC_REQ,
    MGMT_REASSOC_RESP,
    Frame,
)
from .rsn import classify_security


def auth_label(algo: int | None, seq: int | None) -> str:
    """SAE authentication has two rounds per side: transaction sequence
    1 = Commit (exchange public values), 2 = Confirm (prove the same key was
    derived). Open System has a request (1) and a response (2)."""
    if algo == AUTH_ALGO_SAE:
        return {1: "SAE commit", 2: "SAE confirm"}.get(seq, f"SAE seq {seq}")
    if algo == 0:
        return {1: "Open System request", 2: "Open System response"}.get(seq, f"Open System seq {seq}")
    return f"{auth_algo_text(algo)} seq {seq}"


def describe_frame(f: Frame) -> str:
    """One-line summary of what a frame says (beyond its addresses)."""
    if f.eapol is not None:
        e = f.eapol
        if e.error:
            return f"EAPOL error: {e.error}"
        if e.message is None:
            return f"EAPOL packet type {e.packet_type}"
        return f"key info 0x{e.key_info:04x}  replay counter {e.replay_counter}  key data {e.key_data_len} bytes"
    if f.dhcp is not None:
        d = f.dhcp
        text = f"xid 0x{d.xid:08x}  client {d.client_mac}"
        return text + (f"  yiaddr {d.your_ip}" if d.your_ip else "")
    m = f.mgmt
    if m is None:
        return ""
    if f.protected:
        return "body encrypted (Protected Management Frame)"
    st = f.subtype
    parts: list[str] = []
    if m.ssid is not None:
        parts.append(f'ssid="{m.ssid}"' if m.ssid else "ssid=<wildcard/hidden>")
    if st in (MGMT_BEACON, MGMT_PROBE_RESP):
        if m.channel is not None:
            parts.append(f"ch {m.channel}")
        parts.append(str(classify_security(m.rsn, m.privacy, m.wpa1)))
    elif st in (MGMT_ASSOC_REQ, MGMT_REASSOC_REQ) and m.rsn is not None:
        parts.append(f"client chose {classify_security(m.rsn, True)}")
    elif st == MGMT_AUTH:
        parts.append(f"{auth_label(m.auth_algo, m.auth_seq)}  status {m.status} ({status_text(m.status)})")
    elif st in (MGMT_ASSOC_RESP, MGMT_REASSOC_RESP):
        parts.append(f"status {m.status} ({status_text(m.status)})  AID {m.aid}")
    elif st in (MGMT_DEAUTH, MGMT_DISASSOC):
        parts.append(f"reason {m.reason} ({reason_text(m.reason)})")
    elif st == MGMT_PROBE_REQ and m.ssid is None:
        parts.append("no SSID element")
    return "  ".join(parts)

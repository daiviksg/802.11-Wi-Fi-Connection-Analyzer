"""Output: one-line frame descriptions, and the analysis report.

`build_report` produces a plain dict: the JSON output, documented in
docs/OUTPUT_SCHEMA.md. The text report is rendered *from that dict*, so both
formats always carry the same data.
"""

from __future__ import annotations

from pathlib import Path

from .capture import read_packets
from .classify import classify
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
    parse_frame,
)
from .rsn import classify_security
from .timeline import Event, build

SCHEMA_VERSION = 1


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


# --- analysis report ---------------------------------------------------------

def build_report(capture: str | Path, client: str | None = None, bssid: str | None = None) -> dict:
    analysis = build(parse_frame(p) for p in read_packets(capture))
    client = client.lower() if client else None
    bssid = bssid.lower() if bssid else None

    clients = []
    for tl in analysis.timelines:
        if client and tl.client != client:
            continue
        if bssid and tl.bssid != bssid:
            continue
        net = analysis.networks.get(tl.bssid) if tl.bssid else None
        res = classify(tl, net)
        t0 = tl.events[0].ts if tl.events else 0.0
        clients.append({
            "client": tl.client,
            "bssid": tl.bssid,
            "ssid": net.ssid if net and net.ssid else _ssid_from_events(tl.events),
            "result": {
                "code": res.code,
                "summary": res.summary,
                "likely_cause": res.likely_cause,
                "status_code": res.status_code,
                "reason_code": res.reason_code,
                "code_meaning": res.code_meaning,
                "notes": res.notes,
            },
            "dhcp": res.dhcp,
            "attempts": res.attempts,
            "events": _events_json(tl.events, t0),
        })

    wanted = {c["bssid"] for c in clients}
    networks = [
        {
            "bssid": n.bssid,
            "ssid": n.ssid,
            "channel": n.channel,
            "security": {
                "name": n.security.name,
                "akms": n.security.akms,
                "pmf": n.security.pmf,
                "notes": n.security.notes,
                "description": str(n.security),
            } if n.security else None,
        }
        for n in analysis.networks.values() if n.bssid in wanted
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "capture": {
            "file": Path(capture).name,
            "packets": analysis.packets,
            "frames_80211": analysis.frames_80211,
            "bad_fcs": analysis.bad_fcs,
            "malformed": analysis.malformed,
            "retransmissions_skipped": analysis.retransmissions_skipped,
        },
        "networks": networks,
        "clients": clients,
    }


def _ssid_from_events(events: list[Event]) -> str | None:
    for ev in events:
        m = ev.frame.mgmt
        if m and m.ssid:
            return m.ssid
    return None


def _events_json(events: list[Event], t0: float) -> list[dict]:
    out = []
    seen_eapol: set[str] = set()
    for ev in events:
        f, m = ev.frame, ev.frame.mgmt
        label, detail = _event_text(ev)
        eapol_msg = f.eapol.message if f.eapol else None
        # A second copy of the same handshake message (with a new replay
        # counter) means the AP re-sent it: it didn't get the reply it wanted.
        if eapol_msg:
            if eapol_msg in seen_eapol:
                label += f" (retry, replay counter {f.eapol.replay_counter})"
            seen_eapol.add(eapol_msg)
        out.append({
            "idx": f.idx,
            "ts": round(f.ts, 6),
            "t": round(f.ts - t0, 6),
            "kind": ev.kind,
            "from": _direction(ev),
            "label": label,
            "detail": detail,
            "status": m.status if m else None,
            "reason": m.reason if m else None,
            "auth_algo": m.auth_algo if m else None,
            "auth_seq": m.auth_seq if m else None,
            "aid": m.aid if m else None,
            "eapol_message": eapol_msg,
            "replay_counter": f.eapol.replay_counter if f.eapol else None,
            "dhcp_message": f.dhcp.message if f.dhcp else None,
            "xid": f.dhcp.xid if f.dhcp else None,
            "ip": f.dhcp.your_ip if f.dhcp else None,
            "broadcast": ev.broadcast,
        })
    return out


def _direction(ev: Event) -> str | None:
    if ev.from_client is None:
        return None
    if ev.kind == "dhcp":
        return "client" if ev.from_client else "server"
    return "client" if ev.from_client else "ap"


def _event_text(ev: Event) -> tuple[str, str]:
    """(label, detail) for one timeline line, e.g. ("Auth (SAE commit)", "status 0  from AP")."""
    f, m = ev.frame, ev.frame.mgmt
    k = ev.kind
    if k == "probe_req":
        return (f'Probe Request -> "{m.ssid}"' if m and m.ssid else "Probe Request (wildcard)"), ""
    if k == "probe_resp":
        return "Probe Response", ""
    if k == "auth":
        detail = f"status {m.status}" + (f" ({status_text(m.status)})" if m.status else "")
        who = "client" if ev.from_client else "AP"
        kind = auth_label(m.auth_algo, m.auth_seq).replace(" request", "").replace(" response", "")
        return f"Auth ({kind})", f"{detail}  from {who}"
    if k in ("assoc_req", "reassoc_req"):
        return ("Reassoc Request" if k == "reassoc_req" else "Assoc Request"), ""
    if k in ("assoc_resp", "reassoc_resp"):
        name = "Reassoc Response" if k == "reassoc_resp" else "Assoc Response"
        return name, f"status {m.status} ({status_text(m.status)})  AID {m.aid}"
    if k in ("deauth", "disassoc"):
        name = "Deauth" if k == "deauth" else "Disassoc"
        who = "client" if ev.from_client else "AP" + (" (broadcast)" if ev.broadcast else "")
        if f.protected or m is None or m.reason is None:
            return name, f"reason hidden (protected frame)  from {who}"
        return name, f"reason {m.reason} ({reason_text(m.reason)})  from {who}"
    if k == "eapol":
        return f"EAPOL {f.eapol.message or 'packet'}", ""
    if k == "dhcp":
        d = f.dhcp
        return f"DHCP {d.message}", f"xid 0x{d.xid:08x}" + (f"  {d.your_ip}" if d.your_ip else "")
    return k, ""


def render_text(report: dict) -> str:
    cap = report["capture"]
    lines = [
        f"Capture: {cap['file']}  ({cap['packets']} packets; skipped {cap['bad_fcs']} with bad FCS, "
        f"{cap['malformed']} malformed, {cap['retransmissions_skipped']} retransmissions)",
    ]
    if not report["clients"]:
        lines += ["", "No connection attempts found."]
        return "\n".join(lines) + "\n"

    networks = {n["bssid"]: n for n in report["networks"]}
    order: list[str | None] = []
    for c in report["clients"]:
        if c["bssid"] not in order:
            order.append(c["bssid"])

    for bssid in order:
        lines.append("")
        if bssid is None:
            lines.append("Wired (Ethernet) DHCP")
        elif bssid in networks:
            net = networks[bssid]
            ssid = f'"{net["ssid"]}"' if net["ssid"] else "<hidden>"
            sec = net["security"]["description"] if net["security"] else "unknown"
            chan = f"  Channel {net['channel']}" if net["channel"] else ""
            lines.append(f"Network: {ssid}  BSSID {bssid}  Security: {sec}{chan}")
            for note in (net["security"] or {}).get("notes", []):
                lines.append(f"  Warning: {note}")
        else:
            lines.append(f"Network: BSSID {bssid}  (no Beacon or Probe Response captured)")

        for c in report["clients"]:
            if c["bssid"] != bssid:
                continue
            lines.append("")
            lines.append(f"Client {c['client']}")
            for e in c["events"]:
                detail = f"  {e['detail']}" if e["detail"] else ""
                lines.append(f"  {e['t']:7.3f}s  {e['label']:<24}{detail}".rstrip())
            r = c["result"]
            text = r["summary"] + (f" {r['likely_cause']}" if r["likely_cause"] else "")
            lines.append(f"  RESULT: {r['code']} -> {text}")
            if c["dhcp"] != "n/a":
                lines.append(f"  DHCP: {c['dhcp']}")
            for note in r["notes"]:
                lines.append(f"  Note: {note}")
    return "\n".join(lines) + "\n"

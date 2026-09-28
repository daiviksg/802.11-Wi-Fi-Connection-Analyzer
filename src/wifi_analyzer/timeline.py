"""Grouping parsed frames into one timeline per (client MAC, BSSID).

A "client" is the station trying to join; the BSSID identifies the AP radio
it's joining. Management frames tell us which side sent them: if the
source address equals the BSSID, the AP sent it; otherwise the client did.
DHCP is keyed by the client hardware address inside the DHCP message
(chaddr). The server's replies may be broadcast, so the 802.11 destination
doesn't always name the client.

Only *usable* frames are evidence: no parse error and no bad FCS. A single
corrupted frame must not invent a deauthentication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

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
    TYPE_DATA,
    TYPE_MGMT,
    Frame,
)
from .rsn import Security, classify_security

MGMT_EVENT_KINDS = {
    MGMT_PROBE_REQ: "probe_req",
    MGMT_PROBE_RESP: "probe_resp",
    MGMT_AUTH: "auth",
    MGMT_ASSOC_REQ: "assoc_req",
    MGMT_ASSOC_RESP: "assoc_resp",
    MGMT_REASSOC_REQ: "reassoc_req",
    MGMT_REASSOC_RESP: "reassoc_resp",
    MGMT_DEAUTH: "deauth",
    MGMT_DISASSOC: "disassoc",
}

# DHCP messages sent by the client; the rest (OFFER, ACK, NAK) come from the server.
DHCP_CLIENT_MESSAGES = {"DISCOVER", "REQUEST", "DECLINE", "RELEASE", "INFORM"}


def is_group_address(mac: str | None) -> bool:
    """Broadcast/multicast: the least-significant bit of the first octet is 1."""
    return mac is not None and int(mac.split(":")[0], 16) & 1 == 1


@dataclass
class Event:
    kind: str  # probe_req, auth, assoc_resp, eapol, dhcp, deauth, ...
    from_client: bool | None  # None when direction doesn't apply
    frame: Frame
    broadcast: bool = False  # e.g. an AP deauthenticating all its clients at once

    @property
    def idx(self) -> int:
        return self.frame.idx

    @property
    def ts(self) -> float:
        return self.frame.ts


@dataclass
class Network:
    bssid: str
    ssid: str | None = None
    channel: int | None = None
    security: Security | None = None


@dataclass
class Timeline:
    client: str
    bssid: str | None  # None for DHCP seen on a wired (Ethernet) capture
    events: list[Event] = field(default_factory=list)
    protected_data_frames: int = 0  # encrypted data between client and AP

    @property
    def wired(self) -> bool:
        return self.bssid is None


@dataclass
class Analysis:
    packets: int = 0
    frames_80211: int = 0
    bad_fcs: int = 0
    malformed: int = 0
    retransmissions_skipped: int = 0
    networks: dict[str, Network] = field(default_factory=dict)
    timelines: list[Timeline] = field(default_factory=list)


def build(frames: Iterable[Frame | None]) -> Analysis:
    result = Analysis()
    timelines: dict[tuple[str, str | None], Timeline] = {}
    probe_reqs: dict[str, list[Event]] = {}
    probe_resps: dict[tuple[str, str], list[Event]] = {}
    last_seq: dict[str, tuple[int, int, int]] = {}

    def timeline(client: str, bssid: str | None) -> Timeline:
        key = (client, bssid)
        if key not in timelines:
            timelines[key] = Timeline(client, bssid)
        return timelines[key]

    for f in frames:
        if f is None:
            continue
        result.packets += 1
        if f.type is not None:
            result.frames_80211 += 1
        if f.fcs_ok is False:
            result.bad_fcs += 1
            continue
        if f.error is not None:
            result.malformed += 1
            continue

        # A MAC-level retransmission (Retry bit, same transmitter and sequence
        # number) is a copy of a frame we already have: the receiver's ACK was
        # lost. Counting it twice would look like the sender repeating itself.
        if f.seq is not None and f.addr2 is not None:
            key = (f.seq, f.type, f.subtype)
            if f.retry and last_seq.get(f.addr2) == key:
                result.retransmissions_skipped += 1
                continue
            last_seq[f.addr2] = key

        if f.type == TYPE_MGMT:
            _add_mgmt(f, result, timeline, timelines, probe_reqs, probe_resps)
        elif f.eapol is not None and f.bssid is not None:
            from_client = f.sa != f.bssid
            client = f.sa if from_client else f.da
            timeline(client, f.bssid).events.append(Event("eapol", from_client, f))
        elif f.dhcp is not None:
            # On an Ethernet capture there's no BSSID; the timeline is wired.
            from_client = f.dhcp.message in DHCP_CLIENT_MESSAGES
            timeline(f.dhcp.client_mac, f.bssid).events.append(Event("dhcp", from_client, f))
        elif f.type == TYPE_DATA and f.protected and f.bssid is not None:
            client = f.sa if f.sa != f.bssid else f.da
            if (client, f.bssid) in timelines:
                timelines[(client, f.bssid)].protected_data_frames += 1

    for tl in timelines.values():
        _attach_probes(tl, result.networks.get(tl.bssid or ""), probe_reqs, probe_resps)
        tl.events.sort(key=lambda e: e.idx)
    result.timelines = sorted(timelines.values(), key=lambda t: t.events[0].idx if t.events else 0)
    return result


def _add_mgmt(f, result, timeline, timelines, probe_reqs, probe_resps) -> None:
    m = f.mgmt
    if f.subtype in (MGMT_BEACON, MGMT_PROBE_RESP) and f.bssid is not None:
        net = result.networks.setdefault(f.bssid, Network(f.bssid))
        if m is not None:
            if m.ssid and net.ssid is None:
                net.ssid = m.ssid
            if m.channel is not None and net.channel is None:
                net.channel = m.channel
            if net.security is None and m.privacy is not None:
                net.security = classify_security(m.rsn, m.privacy, m.wpa1)
    kind = MGMT_EVENT_KINDS.get(f.subtype)
    if kind is None or f.bssid is None:
        return
    if kind == "probe_req":
        probe_reqs.setdefault(f.sa, []).append(Event(kind, True, f))
        return
    from_ap = f.sa == f.bssid
    client = f.da if from_ap else f.sa
    if kind == "probe_resp":
        if not is_group_address(client):
            probe_resps.setdefault((client, f.bssid), []).append(Event(kind, False, f))
        return
    if is_group_address(client):
        # A broadcast deauth/disassoc from the AP applies to every client of that BSS.
        if kind in ("deauth", "disassoc"):
            for (c, b), tl in timelines.items():
                if b == f.bssid:
                    tl.events.append(Event(kind, False, f, broadcast=True))
        return
    timeline(client, f.bssid).events.append(Event(kind, not from_ap, f))


def _attach_probes(tl: Timeline, net: Network | None, probe_reqs, probe_resps) -> None:
    """Add the probing that came before this client's first join frame:
    probe requests for this network's SSID (or wildcard ones), and the AP's
    probe responses to this client."""
    if tl.wired or not tl.events:
        return
    first = min(e.idx for e in tl.events)
    ssid = net.ssid if net else None
    for ev in probe_reqs.get(tl.client, []):
        probe_ssid = ev.frame.mgmt.ssid if ev.frame.mgmt else None
        if ev.idx < first and (probe_ssid in ("", None) or probe_ssid == ssid):
            tl.events.append(ev)
    for ev in probe_resps.get((tl.client, tl.bssid), []):
        if ev.idx < first:
            tl.events.append(ev)

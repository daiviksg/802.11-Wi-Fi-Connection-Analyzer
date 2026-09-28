"""Turning a client's timeline into exactly one result code (SPEC.md 4.5).

The join sequence is a series of gates:

  802.11 authentication -> (re)association -> EAPOL 4-way handshake -> DHCP

We walk the events of the client's *last attempt* in order and track which
gates it passed. The first explicit failure (a non-zero status, or a deauth)
ends the walk. If the capture ends without one, we look at where the client
got stuck.

Two rules keep the results honest:
  * A missing message counts as a failure only with evidence that the peer
    gave up or retried: a deauth, or the AP re-sending its message with a
    new replay counter. A capture that simply stops is INCOMPLETE.
  * A client that disconnects on purpose (reason 3 or 8, sent by the client)
    after a successful connection is still CONNECTED. The disconnect is
    reported as a note.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .codes import (
    AUTH_ALGO_SAE,
    AUTH_STATUS_OK,
    AUTH_STATUS_RETRY,
    REASON_LEAVING,
    reason_text,
    status_text,
)
from .timeline import Event, Network, Timeline

CONNECTED = "CONNECTED"
AUTH_FAILED = "AUTH_FAILED"
SAE_FAILED = "SAE_FAILED"
ASSOC_REJECTED = "ASSOC_REJECTED"
HANDSHAKE_NO_M2 = "HANDSHAKE_NO_M2"
HANDSHAKE_NO_M3 = "HANDSHAKE_NO_M3"
HANDSHAKE_NO_M4 = "HANDSHAKE_NO_M4"
HANDSHAKE_TIMEOUT = "HANDSHAKE_TIMEOUT"
MIC_FAILURE = "MIC_FAILURE"
DHCP_NO_OFFER = "DHCP_NO_OFFER"
DHCP_NAK = "DHCP_NAK"
DEAUTHENTICATED = "DEAUTHENTICATED"
INCOMPLETE = "INCOMPLETE"

RESULT_CODES = [
    CONNECTED, AUTH_FAILED, SAE_FAILED, ASSOC_REJECTED, HANDSHAKE_NO_M2, HANDSHAKE_NO_M3,
    HANDSHAKE_NO_M4, HANDSHAKE_TIMEOUT, MIC_FAILURE, DHCP_NO_OFFER, DHCP_NAK, DEAUTHENTICATED, INCOMPLETE,
]

REASON_MIC_FAILURE = 14
REASON_4WAY_TIMEOUT = 15

# Likely causes for association rejections, by status code.
ASSOC_CAUSES = {
    17: "The AP has reached its client limit.",
    18: "The client doesn't support the AP's required (basic) data rates.",
    30: "The AP still has a protected association for this client and is checking it (PMF SA Query); try again shortly.",
    31: "Protected Management Frames policy mismatch: the AP requires PMF and the client didn't enable it (or vice versa).",
    41: "Security settings mismatch: the client asked for a group cipher the AP doesn't offer.",
    42: "Security settings mismatch: the client asked for a pairwise cipher the AP doesn't offer.",
    43: "Security settings mismatch: the client asked for an AKM (e.g. PSK vs SAE) the AP doesn't offer.",
    46: "The client's cipher suite is disallowed by the AP's security policy.",
    72: "The client's RSN element doesn't match what the AP offers.",
}


@dataclass
class Result:
    code: str
    summary: str
    likely_cause: str | None = None
    status_code: int | None = None
    reason_code: int | None = None
    code_meaning: str | None = None  # text for status_code or reason_code
    dhcp: str = "n/a"
    attempts: int = 1
    notes: list[str] = field(default_factory=list)


def split_attempts(events: list[Event]) -> list[list[Event]]:
    """Split a timeline where the client starts over.

    A new attempt starts when the client sends Authentication (transaction 1),
    or a (Re)Association Request, after the current attempt already got past
    that stage or failed. SAE commits re-sent within one exchange (e.g. after
    an anti-clogging token request) stay in the same attempt.
    """
    attempts: list[list[Event]] = [[]]
    for ev in events:
        cur = attempts[-1]
        m = ev.frame.mgmt
        starts_over = False
        if ev.from_client and ev.kind == "auth" and m and m.auth_seq == 1:
            starts_over = any(_past_auth(e) or _failed(e) for e in cur)
        elif ev.from_client and ev.kind in ("assoc_req", "reassoc_req"):
            starts_over = any(e.kind in ("assoc_resp", "reassoc_resp", "deauth", "disassoc", "eapol") for e in cur)
        if starts_over and cur:
            attempts.append([])
        attempts[-1].append(ev)
    return [a for a in attempts if a]


def _past_auth(e: Event) -> bool:
    return e.kind not in ("probe_req", "probe_resp", "auth")


def _failed(e: Event) -> bool:
    m = e.frame.mgmt
    return (
        e.kind == "auth" and not e.from_client and m is not None and m.status is not None
        and m.status not in AUTH_STATUS_OK | AUTH_STATUS_RETRY
    )


def classify(tl: Timeline, network: Network | None) -> Result:
    attempts = split_attempts(tl.events)
    result = _classify_attempt(attempts[-1] if attempts else [], tl, network)
    result.attempts = len(attempts)
    if len(attempts) > 1:
        result.notes.append(f"{len(attempts)} connection attempts in this capture; the result is for the last one")
    return result


def _needs_handshake(events: list[Event], tl: Timeline, network: Network | None) -> bool:
    """Does joining this network require the 4-way handshake? Yes if the AP
    advertises RSN, if the client put an RSN element in its association
    request, or if any EAPOL-Key frame appears."""
    if network and network.security:
        if network.security.uses_rsn:
            return True
    for ev in events:
        m = ev.frame.mgmt
        if ev.kind in ("assoc_req", "reassoc_req") and m and m.rsn is not None:
            return True
        if ev.kind == "eapol":
            return True
    return False


class _State:
    """What the attempt has achieved so far."""

    def __init__(self) -> None:
        self.sae = False
        self.sae_client_commits = 0
        self.sae_client_confirms = 0
        self.sae_ap_commit_ok = False
        self.authenticated = False
        self.associated = False
        self.eapol: dict[str, list[Event]] = {"M1": [], "M2": [], "M3": [], "M4": []}
        self.m1_after_m2 = False  # AP restarted the handshake after the client's M2
        self.dhcp: list[Event] = []

    @property
    def handshake_started(self) -> bool:
        return any(self.eapol.values())


def _classify_attempt(events: list[Event], tl: Timeline, network: Network | None) -> Result:
    if tl.wired:
        return _finish_dhcp(_State(), events, tl, needs_hs=False)
    needs_hs = _needs_handshake(events, tl, network)
    s = _State()

    for ev in events:
        m = ev.frame.mgmt
        if ev.kind == "auth" and m is not None:
            if m.auth_algo == AUTH_ALGO_SAE:
                s.sae = True
            if ev.from_client:
                if s.sae:
                    if m.auth_seq == 1:
                        s.sae_client_commits += 1
                    elif m.auth_seq == 2:
                        s.sae_client_confirms += 1
                continue
            if m.status in AUTH_STATUS_RETRY:
                continue  # e.g. SAE anti-clogging token requested; the client re-commits
            if m.status not in AUTH_STATUS_OK:
                code = SAE_FAILED if s.sae else AUTH_FAILED
                cause = None
                if m.status == 13:
                    cause = "The client used an authentication algorithm the AP doesn't allow (e.g. Open System on a WPA3-only network)."
                return Result(
                    code,
                    f"AP rejected {'SAE' if s.sae else '802.11'} authentication: status {m.status} ({status_text(m.status)}).",
                    cause, status_code=m.status, code_meaning=status_text(m.status),
                )
            if s.sae:
                # SAE: the AP's Commit (seq 1) then its Confirm (seq 2) with success status.
                if m.auth_seq == 1:
                    s.sae_ap_commit_ok = True
                elif m.auth_seq == 2:
                    s.authenticated = True
            else:
                s.authenticated = True

        elif ev.kind in ("assoc_resp", "reassoc_resp") and m is not None and m.status is not None:
            if m.status != 0:
                what = "reassociation" if ev.kind == "reassoc_resp" else "association"
                return Result(
                    ASSOC_REJECTED,
                    f"AP rejected the {what}: status {m.status} ({status_text(m.status)}).",
                    ASSOC_CAUSES.get(m.status), status_code=m.status, code_meaning=status_text(m.status),
                )
            s.associated = True

        elif ev.kind == "eapol" and ev.frame.eapol and ev.frame.eapol.message in s.eapol:
            msg = ev.frame.eapol.message
            # The AP only starts the handshake after a successful association,
            # so M1 proves association even if the capture missed the response.
            s.associated = s.associated or msg == "M1"
            if msg == "M1" and s.eapol["M2"]:
                s.m1_after_m2 = True
            s.eapol[msg].append(ev)

        elif ev.kind == "dhcp":
            # Unencrypted DHCP between client and AP means the link is up
            # (open network, or a capture that was decrypted).
            s.associated = True
            s.dhcp.append(ev)

        elif ev.kind in ("deauth", "disassoc"):
            return _on_deauth(ev, s, events, tl, needs_hs)

    return _on_capture_end(s, events, tl, needs_hs)


def _link_up(s: _State, needs_hs: bool) -> bool:
    return s.associated and (bool(s.eapol["M4"]) or not needs_hs or bool(s.dhcp))


def _handshake_gap(s: _State) -> str | None:
    if s.eapol["M4"]:
        return None
    if s.eapol["M3"]:
        return HANDSHAKE_NO_M4
    if s.eapol["M2"]:
        return HANDSHAKE_NO_M3
    if s.eapol["M1"]:
        return HANDSHAKE_NO_M2
    return None


GAP_TEXT = {
    HANDSHAKE_NO_M2: (
        "Client never answered M1 with M2.",
        "The client isn't taking part in the handshake: it may be missing or rejecting the network's security settings, or it moved out of range.",
    ),
    HANDSHAKE_NO_M3: (
        "AP never sent M3 after M2.",
        "Most likely cause: wrong passphrase. The AP checks M2's MIC with its own key; a different passphrase gives a different key, so the check fails and the AP drops M2.",
    ),
    HANDSHAKE_NO_M4: (
        "Client never sent M4 after M3.",
        "The client rejected M3 (for example, the RSN element in M3 doesn't match the Beacon's) or M4 was lost over the air.",
    ),
}


def _on_deauth(ev: Event, s: _State, events: list[Event], tl: Timeline, needs_hs: bool) -> Result:
    m = ev.frame.mgmt
    reason = m.reason if m else None
    who = "Client" if ev.from_client else "AP"
    frame_name = "Deauthentication" if ev.kind == "deauth" else "Disassociation"
    reason_str = f"reason {reason} ({reason_text(reason)})" if reason is not None else "reason hidden (protected frame)"
    common = dict(reason_code=reason, code_meaning=reason_text(reason) if reason is not None else None)

    if not s.associated:
        if s.sae and not s.authenticated and s.sae_client_commits:
            return _sae_incomplete(s, extra=f" {who} then sent {frame_name}, {reason_str}.", **common)
        return Result(DEAUTHENTICATED, f"{who} sent {frame_name} before association completed: {reason_str}.", **common)

    if needs_hs and not s.eapol["M4"]:
        if reason == REASON_MIC_FAILURE:
            return Result(
                MIC_FAILURE,
                f"{who} sent {frame_name} with reason 14 (MIC failure) during the 4-way handshake.",
                "The two sides derived different keys, most often because of a wrong passphrase.",
                **common,
            )
        gap = _handshake_gap(s)
        if gap:
            summary, cause = GAP_TEXT[gap]
            return Result(gap, f"{summary} {who} then sent {frame_name}, {reason_str}.", cause, **common)
        if reason == REASON_4WAY_TIMEOUT:
            return Result(
                HANDSHAKE_TIMEOUT,
                f"{who} ended the connection with reason 15 (4-way handshake timeout); no EAPOL frames were captured.",
                "The client never completed the handshake, or the capture missed the EAPOL frames (e.g. the capture card was channel hopping).",
                **common,
            )
        return Result(DEAUTHENTICATED, f"{who} sent {frame_name} after association, before the handshake completed: {reason_str}.", **common)

    # The link was up. Report a DHCP failure first: it's why the client left.
    dhcp = _dhcp_outcome(s.dhcp)
    if dhcp in ("NAK", "NO_OFFER"):
        return _finish_dhcp(s, events, tl, needs_hs, notes=[f"{who} later sent {frame_name}, {reason_str}"])
    if ev.from_client and reason in REASON_LEAVING:
        result = _connected(s, tl, needs_hs)
        result.notes.append(f"Client later left on purpose: {frame_name}, {reason_str}")
        return result
    return Result(DEAUTHENTICATED, f"{who} ended the connection: {frame_name}, {reason_str}.", dhcp=_dhcp_text(s, tl, needs_hs), **common)


def _on_capture_end(s: _State, events: list[Event], tl: Timeline, needs_hs: bool) -> Result:
    if _link_up(s, needs_hs):
        return _finish_dhcp(s, events, tl, needs_hs)

    gap = _handshake_gap(s)
    if gap:
        # Need evidence the peer gave up waiting: the AP re-sent its message.
        retried = (
            (gap == HANDSHAKE_NO_M2 and len(s.eapol["M1"]) >= 2)
            or (gap == HANDSHAKE_NO_M3 and s.m1_after_m2)
            or (gap == HANDSHAKE_NO_M4 and len(s.eapol["M3"]) >= 2)
        )
        if retried:
            summary, cause = GAP_TEXT[gap]
            return Result(gap, f"{summary} The AP retried, then the capture ends.", cause)
        return Result(INCOMPLETE, f"Capture ends during the 4-way handshake (last message: {_last_eapol(s)}); no failure seen.")

    if s.sae and not s.authenticated and s.sae_client_commits:
        # Evidence of failure: the client repeated its Confirm, or kept committing.
        if s.sae_client_confirms >= 2 or s.sae_client_commits >= 3:
            return _sae_incomplete(s, extra=" The client kept retrying, then the capture ends.")
        return Result(INCOMPLETE, "Capture ends during the SAE exchange; no failure seen.")

    stage = (
        "association" if s.associated else
        "authentication" if s.authenticated else
        "an authentication request" if any(e.kind == "auth" for e in events) else
        "probing"
    )
    if s.associated and needs_hs:
        stage = "association, before the 4-way handshake started"
    return Result(INCOMPLETE, f"Capture ends after {stage}; no failure seen.")


def _sae_incomplete(s: _State, extra: str = "", **kw) -> Result:
    if s.sae_ap_commit_ok and s.sae_client_confirms:
        return Result(
            SAE_FAILED,
            "SAE exchange never completed: the AP never sent its Confirm." + extra,
            "Most likely cause: wrong password. With different passwords both sides compute different keys, so the AP can't verify the client's Confirm and silently discards it.",
            **kw,
        )
    return Result(SAE_FAILED, "SAE exchange never completed: the AP never answered the client's Commit." + extra, **kw)


def _last_eapol(s: _State) -> str:
    seen = [(e.idx, msg) for msg, evs in s.eapol.items() for e in evs]
    return max(seen)[1] if seen else "none"


def _dhcp_outcome(dhcp: list[Event]) -> str:
    """Summarise the DHCP exchange: ACK, NAK, NO_OFFER, PENDING, or NONE.

    DISCOVERs after the last server message count as unanswered. Two or more
    unanswered DISCOVERs mean the client retried with no reply: NO_OFFER.
    """
    if not dhcp:
        return "NONE"
    last_server = None
    unanswered_discovers = 0
    for ev in dhcp:
        msg = ev.frame.dhcp.message
        if msg in ("OFFER", "ACK", "NAK"):
            last_server = msg
            unanswered_discovers = 0
        elif msg == "DISCOVER":
            unanswered_discovers += 1
    if unanswered_discovers >= 2 and last_server != "ACK":
        return "NO_OFFER"
    if last_server in ("ACK", "NAK"):
        return last_server
    return "PENDING"


def _dhcp_text(s: _State, tl: Timeline, needs_hs: bool) -> str:
    outcome = _dhcp_outcome(s.dhcp)
    if outcome == "ACK":
        ip = next((e.frame.dhcp.your_ip for e in reversed(s.dhcp) if e.frame.dhcp.message == "ACK"), None)
        return f"ACK ({ip})" if ip else "ACK"
    if outcome == "NONE":
        if needs_hs and not tl.wired:
            return "not observable: encrypted"
        return "not seen"
    return {"NAK": "NAK", "NO_OFFER": "no offer", "PENDING": "in progress"}[outcome]


def _connected(s: _State, tl: Timeline, needs_hs: bool) -> Result:
    dhcp = _dhcp_text(s, tl, needs_hs)
    if tl.wired:
        summary = "DHCP completed on the wired side."
    elif needs_hs:
        summary = "Completed authentication, association and the 4-way handshake."
    else:
        summary = "Completed authentication and association (open network)."
    if dhcp.startswith("ACK"):
        summary += f" DHCP {dhcp}."
    elif dhcp == "not observable: encrypted":
        summary += " DHCP not observable: it travels in encrypted data frames."
    elif dhcp == "not seen":
        summary += " No DHCP seen (static IP, or DHCP not captured)."
    return Result(CONNECTED, summary, dhcp=dhcp)


def _finish_dhcp(s: _State, events: list[Event], tl: Timeline, needs_hs: bool, notes: list[str] | None = None) -> Result:
    """The link is up; the DHCP exchange decides the result."""
    if not s.dhcp:
        s.dhcp = [e for e in events if e.kind == "dhcp"]
    outcome = _dhcp_outcome(s.dhcp)
    if outcome == "NAK":
        r = Result(DHCP_NAK, "The DHCP server refused the client's request (NAK).",
                   "The client asked for an address that isn't valid here (e.g. it remembered a lease from another network).", dhcp="NAK")
    elif outcome == "NO_OFFER":
        n = sum(1 for e in s.dhcp if e.frame.dhcp.message == "DISCOVER")
        r = Result(DHCP_NO_OFFER, f"The client sent {n} DHCP Discovers and no server answered.",
                   "No DHCP server is reachable from this network (e.g. wrong VLAN, broken DHCP relay, or the server is down).", dhcp="no offer")
    elif outcome == "PENDING":
        r = Result(INCOMPLETE, "Capture ends during DHCP; no failure seen.", dhcp="in progress")
    else:
        r = _connected(s, tl, needs_hs)
    r.notes.extend(notes or [])
    return r

# `analyze --format json` output schema

Schema version **1**. Every key below is always present; a value that doesn't apply is `null`. New keys may be added in later versions, but existing keys won't change meaning without bumping `schema_version`. The text output is rendered from this same data.

```jsonc
{
  "schema_version": 1,
  "capture": {
    "file": "handshake_no_m3.pcap",   // file name only
    "packets": 12,                    // packets read (all link types)
    "frames_80211": 12,               // packets with a parsed 802.11 Frame Control field
    "bad_fcs": 0,                     // frames whose FCS (CRC-32) didn't match: ignored as evidence
    "malformed": 0,                   // truncated/unparseable frames: ignored as evidence
    "retransmissions_skipped": 0      // MAC-level duplicates (Retry bit + same sequence number)
  },
  "networks": [                       // only networks that have a client in "clients"
    {
      "bssid": "02:00:00:00:00:aa",
      "ssid": "LabNet",               // null if hidden or no Beacon/Probe Response seen
      "channel": 6,                   // from the DS Parameter Set or HT Operation element
      "security": {                   // null if no Beacon/Probe Response was captured
        "name": "WPA3-Personal",      // Open | WEP | WPA (legacy) | WPA2-Personal | WPA3-Personal |
                                      // WPA3-Personal transition | Enterprise (802.1X) |
                                      // WPA3-Enterprise 192-bit | Enhanced Open (OWE) | RSN
        "akms": ["SAE"],              // AKM suite names from the RSN element
        "pmf": "required",            // required | capable | disabled
        "notes": [],                  // e.g. "WPA3-Personal requires PMF (MFPR=1), but ..."
        "description": "WPA3-Personal (SAE, PMF required)"
      }
    }
  ],
  "clients": [                        // one entry per (client MAC, BSSID)
    {
      "client": "02:00:00:00:00:01",
      "bssid": "02:00:00:00:00:aa",   // null for DHCP seen on an Ethernet capture
      "ssid": "LabNet",
      "result": {
        "code": "HANDSHAKE_NO_M3",    // see "Result codes" below
        "summary": "AP never sent M3 after M2. AP then sent Deauthentication, reason 15 (4-way handshake timeout).",
        "likely_cause": "Most likely cause: wrong passphrase. ...",   // null if there's no good guess
        "status_code": null,          // the 802.11 status code behind AUTH_FAILED / SAE_FAILED / ASSOC_REJECTED
        "reason_code": 15,            // the deauth/disassoc reason code behind the result, if any
        "code_meaning": "4-way handshake timeout",   // text for status_code or reason_code
        "notes": []                   // e.g. "Client later left on purpose: ...", "2 connection attempts ..."
      },
      "dhcp": "not observable: encrypted",
        // "ACK (<ip>)" | "NAK" | "no offer" | "in progress" | "not seen" | "not observable: encrypted" | "n/a"
      "attempts": 1,                  // connection attempts found; the result is for the last one
      "events": [
        {
          "idx": 11,                  // frame number in the capture (1-based, same as Wireshark)
          "ts": 1700000000.02,        // absolute timestamp, seconds since the Unix epoch
          "t": 1.020,                 // seconds since this client's first event
          "kind": "eapol",            // probe_req | probe_resp | auth | assoc_req | assoc_resp |
                                      // reassoc_req | reassoc_resp | eapol | dhcp | deauth | disassoc
          "from": "ap",               // client | ap | server (DHCP) | null
          "label": "EAPOL M1 (retry, replay counter 2)",
          "detail": "",               // e.g. "status 0 (Successful)  AID 3"
          "status": null,             // auth / (re)assoc response status code
          "reason": null,             // deauth / disassoc reason code (null if the frame is PMF-protected)
          "auth_algo": null,          // 0 Open System, 3 SAE, ...
          "auth_seq": null,           // authentication transaction sequence (SAE: 1 commit, 2 confirm)
          "aid": null,                // association ID from a successful (re)assoc response
          "eapol_message": "M1",      // M1 | M2 | M3 | M4 | G1 | G2 | REQUEST
          "replay_counter": 2,
          "dhcp_message": null,       // DISCOVER | OFFER | REQUEST | ACK | NAK | DECLINE | RELEASE | INFORM
          "xid": null,                // DHCP transaction ID (integer)
          "ip": null,                 // yiaddr from an OFFER / ACK
          "broadcast": false          // true for a broadcast deauth/disassoc that applied to every client
        }
      ]
    }
  ]
}
```

## Result codes

| Code | Meaning |
|---|---|
| `CONNECTED` | Authentication, association and (if the network uses RSN) the 4-way handshake completed; DHCP got an ACK or couldn't be observed. |
| `AUTH_FAILED` | The AP answered 802.11 authentication with a failure status. |
| `SAE_FAILED` | WPA3 SAE was rejected by status code, or never completed (the AP never sent its Confirm and the client retried or gave up). |
| `ASSOC_REJECTED` | (Re)association response with a non-zero status. |
| `HANDSHAKE_NO_M2` | M1 sent, the client never answered, and the AP retried or deauthenticated. |
| `HANDSHAKE_NO_M3` | M2 sent, the AP never sent M3 (usually a wrong passphrase), and the AP retried or deauthenticated. |
| `HANDSHAKE_NO_M4` | M3 sent, the client never sent M4, and the AP retried or deauthenticated. |
| `HANDSHAKE_TIMEOUT` | Deauth with reason 15 and no EAPOL frames captured to say which message was missing. |
| `MIC_FAILURE` | Deauth with reason 14 during the handshake. |
| `DHCP_NO_OFFER` | Two or more DHCP Discovers with no Offer. |
| `DHCP_NAK` | The DHCP server's last answer was a NAK. |
| `DEAUTHENTICATED` | Deauth or disassociation that isn't explained by a more specific code above. |
| `INCOMPLETE` | The capture ends mid-sequence with no evidence of failure. |

Precedence when a deauth arrives during the handshake: reason 14 → `MIC_FAILURE`; otherwise the missing message (`HANDSHAKE_NO_M2/M3/M4`) if any EAPOL frame was seen; otherwise reason 15 → `HANDSHAKE_TIMEOUT`; otherwise `DEAUTHENTICATED`.

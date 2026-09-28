# Learning notes

One section per milestone: the protocol ideas it relies on and the design decisions, in plain language.

## M0: Reading captures and 802.11 headers

### What's in a capture file

A `.pcap` file has a global header, then one record per packet: a timestamp, the captured length (`caplen`), the original length on the wire, and `caplen` bytes of data. The global header's **link type** (DLT) says what those bytes start with:

- **127, radiotap + 802.11.** Monitor-mode captures. Radiotap is *not* transmitted over the air. The capturing driver adds it to describe how the frame was received (channel, rate, signal strength, flags). Its length varies with which fields are present, so we read `it_len` (little-endian u16 at byte offset 2) and skip exactly that many bytes. We never assume a fixed length.
- **105, raw 802.11.** The frame starts at byte 0.
- **1, Ethernet.** Wired side. No 802.11 frames here, but DHCP is visible (used in M1/M2).

`.pcapng` works the same way, except each capture interface declares its own link type and timestamp resolution.

**Decision: read raw bytes, not Scapy's decoded packets.** If Scapy can't decode a packet (a truncated frame, for example), it silently turns it into a generic `Raw` packet, and we'd lose both the link type and the frame. `capture.py` reads the raw bytes and link type itself. `frames.py` checks lengths explicitly and only then asks Scapy to decode the fields. Packets are numbered from 1, like Wireshark's `frame.number`, so every tool can refer to the same frame.

### The 802.11 MAC header

```
Frame Control (2) | Duration (2) | Addr1 (6) | Addr2 (6) | Addr3 (6) | Seq Ctrl (2) | [Addr4 (6)] | [QoS (2)]
```

- **Frame Control, byte 0:** protocol version (bits 0-1, always 0 for normal frames), **type** (bits 2-3: 0 = management, 1 = control, 2 = data, 3 = extension), **subtype** (bits 4-7). Byte 1 holds flags: ToDS (0x01), FromDS (0x02), Retry (0x08), Protected (0x40), and others.
- **Management frames** (beacon, probe, authentication, association, deauth) are how a client finds and joins a network. They're what this tool mostly tracks, and they're sent unencrypted (except deauth/disassoc/action frames on PMF networks).
- **Address meaning depends on direction.** In management frames, Addr1 = receiver, Addr2 = transmitter, Addr3 = BSSID. In data frames, ToDS/FromDS decide which address is the BSSID, source, or destination; that matters in M1.
- **Header length depends on frame type,** so "do we have enough bytes?" can't be a single constant: management = 24 bytes; data = 24, +6 if ToDS and FromDS (4 addresses), +2 for QoS subtypes; ACK/CTS = only 10 bytes (FC, Duration, Addr1); RTS/BlockAck etc. = 16. `min_header_len()` encodes this (IEEE 802.11-2020 clause 9.3).
- **Sequence Control:** the low 4 bits are the fragment number; the high 12 bits are the sequence number. A retransmission has the Retry flag set and the *same* sequence number (visible in the sample: repeated Probe Responses with `seq=4036 R`).

### Corrupted frames and the FCS

Every 802.11 frame ends with a 4-byte **Frame Check Sequence**, a CRC-32 over the whole MAC frame. A normal receiver drops frames that fail it. In monitor mode, drivers often pass them up anyway, and the radiotap Flags field says whether the FCS was captured (bit 0x10).

The public sample `wpa-Induction.pcap` has 13 corrupted frames out of 1093. Their protocol versions (2, 3) don't exist, and one "Probe Request" has random addresses. The driver *didn't* set radiotap's "bad FCS" bit, so we recompute the CRC-32 ourselves (`zlib.crc32` of the frame compared with the last 4 bytes, read little-endian). Frames get `fcs_ok = True/False/None`. The parser still decodes bad-FCS frames (Wireshark does too), but **the classifier in M2 must ignore them**. Otherwise a single corrupted bit could invent a "deauthentication" and blame the wrong stage.

### Malformed input

The parser never raises on bad input. It fills in whatever it could read and sets `error`, for example `truncated: 20 bytes, Authentication header needs 24`. The `frames` command always prints error records, even when filtering to management frames, because hiding them would hide bugs. The C parser (M3) follows the same rule.

### Test data

Synthetic frames are built with Scapy in the tests and use *locally administered* MAC addresses (`02:...`), which no real device ships with. Public captures are downloaded by `tests/data/public/fetch.py` with a pinned SHA-256 and are never committed: their license isn't stated, and they contain real MAC addresses.

### Questions to be ready for

- *Why can't you hard-code the radiotap length?* Its length depends on which fields the driver included. Different drivers produce different lengths, even within one file.
- *How do you know where the 802.11 header ends?* It depends on type, subtype, and the ToDS/FromDS flags. See `min_header_len`.
- *What happens with a corrupted frame?* The FCS check marks it. It's shown for debugging but never used as evidence.

## M1: Management frames, RSN, EAPOL and DHCP

### How a client joins a WPA2/WPA3 network

1. **Discovery.** The AP sends a **Beacon** about 10 times a second, and a client can also send a **Probe Request** and get a **Probe Response**. Both carry the SSID, the channel, and the **RSN element** describing the security.
2. **802.11 Authentication.** For WPA2 this is "Open System": a request and a response with a status code, and no real security (the name is historical). For WPA3 it's **SAE**. Each side sends a *Commit* (transaction sequence 1), then a *Confirm* (sequence 2). SAE turns the password into a key that an eavesdropper can't brute-force offline.
3. **(Re)Association.** The client asks to join and puts its chosen cipher and AKM in its own RSN element. The AP answers with a status code and an **AID** (association ID; the field's top two bits are always set, so we mask with `0x3FFF`). Reassociation is the same exchange when the client moves (roams) to another AP of the same network.
4. **EAPOL 4-way handshake.** Both sides turn the shared secret (PMK) into session keys, and each proves it has the same secret without sending it.
5. **DHCP.** The client gets an IP address. From here on everything is encrypted, so DHCP is only visible on open networks, decrypted captures, or the wired side.

**Addresses depend on the ToDS/FromDS bits.** In a data frame from the client to the AP (ToDS=1), Addr1 is the BSSID, Addr2 the source, and Addr3 the final destination. From the AP to the client (FromDS=1), Addr1 is the destination, Addr2 the BSSID, and Addr3 the original source. `_resolve_addresses` turns these into `sa` / `da` / `bssid` so later code never has to think about it.

### RSN element (`rsn.py`)

It contains a version, a group cipher, a list of pairwise ciphers, a list of **AKM** suites (how keys are agreed: 2 = PSK, 8 = SAE, 1 = 802.1X, 18 = OWE), and RSN Capabilities. Two capability bits matter here: **MFPC** (0x80, "I can do Protected Management Frames") and **MFPR** (0x40, "I require them"). WPA3-Personal requires PMF. Transition mode advertises both PSK and SAE with MFPC set, so older WPA2 clients can still join.

Every field after Version is optional, so the parser checks each read against the remaining length and reports "truncated in AKM list" rather than reading past the end. No RSN element plus the Privacy capability bit means WEP; no RSN element and no Privacy bit means Open.

### EAPOL-Key messages (`frames.py`)

EAPOL comes from 802.1X, so its fields are **big-endian**, while 802.11 fields are little-endian. That's a classic interview trap. The **Key Information** field identifies the message:

| | Ack | MIC | Install | Secure | Key Data |
|---|---|---|---|---|---|
| M1 (AP) | 1 | 0 | 0 | 0 | none (or a PMKID) |
| M2 (client) | 0 | 1 | 0 | 0 | client's RSN element |
| M3 (AP) | 1 | 1 | 1 | 1 | encrypted group key |
| M4 (client) | 0 | 1 | 0 | 1 | none |

- **Ack** means "sent by the AP, reply expected", so Ack alone is M1 and Ack+Install is M3.
- **M2 vs M4** is the subtle case. The standard says M4 has Secure=1 and M2 doesn't, but Windows sets Secure on M2 when rekeying. So, like Wireshark, we decide by **Key Data**: M2 always carries the client's RSN element and M4 carries none. Only if Key Data is empty do we use Secure and the nonce (M2 always has the client's SNonce, M4 usually has zeros).
- The **replay counter** increases with each AP message and the client echoes it back. A second M1 with a higher counter means the AP gave up waiting and restarted. That's how M2 is matched to M1 and M4 to M3.
- **MIC length** isn't in the frame: 16 bytes for PSK and SAE, 24 or 32 for newer AKMs. We try each size and keep the one where the Key Data Length field exactly accounts for the rest of the frame.

### DHCP

DORA: **D**iscover (client broadcast), **O**ffer (server), **R**equest, **A**CK, or **NAK** if the server refuses. `xid` ties one exchange together. `chaddr` holds the client's MAC even when the reply is broadcast, so DHCP events are keyed by `chaddr`, not by the 802.11 destination.

### Where the numbers come from

Status, reason, AKM and cipher tables (`codes.py`) are copied from Wireshark's `packet-ieee80211.c`, so the wording matches what a Wireshark user sees. Checking there caught one mistake: reason code 45, which I'd have added from memory, isn't a defined reason code. Status **126** isn't a failure either: it means "SAE using hash-to-element" and appears in successful WPA3 exchanges.

### Bugs caught by testing against real bytes

- Scapy doesn't know about the 4-byte **HT Control** field that follows the header when the Order bit is set. We strip it before handing the frame to Scapy, and `header_len` accounts for it.
- The test builder was producing beacons with the Privacy bit byte-swapped (Scapy's `cap` field wants flag names, not an int). The parser reads the field by hand, as little-endian at a fixed offset, and the public capture confirmed it was right: bytes `11 04` = 0x0411 = ESS + Privacy + Short Slot. Using a second, independent parser is what caught this.

### Questions to be ready for

- *How do you tell M2 from M4?* Key Data first (M2 carries the RSN element), then Secure and the nonce. Not the Secure bit alone, because of the Windows rekey behavior.
- *Why can't you see DHCP on a WPA2 network?* It's inside encrypted data frames, sent after the 4-way handshake installs the keys. The handshake itself is unencrypted because the keys don't exist yet.
- *What's PMF and why does WPA3 require it?* It protects deauth/disassoc/action frames. Without it, anyone can forge a deauth and kick clients off.

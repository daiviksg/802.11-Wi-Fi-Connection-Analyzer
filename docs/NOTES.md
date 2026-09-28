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

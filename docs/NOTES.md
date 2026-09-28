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

## M2: Timelines and failure classification

### From frames to a verdict

1. **Keep only evidence** (`timeline.py`). Skip frames with a bad FCS or a parse error. Also skip MAC-level **retransmissions**: a frame with the Retry bit and the same transmitter + sequence number as the previous one is a copy sent because an ACK was lost, not a new message. Without this, one lost ACK would look like "the AP re-sent M1".
2. **Group by (client, BSSID).** For management and EAPOL frames, if the source is the BSSID the AP sent it, otherwise the client did. DHCP is grouped by `chaddr` because the server's replies are often broadcast. A broadcast deauth from an AP (Addr1 = ff:ff:ff:ff:ff:ff) is added to every client of that BSSID. Probe requests don't name a BSSID, so they're attached to a client's timeline if they came before the first join frame and asked for that network's SSID (or any SSID).
3. **Split into attempts** (`classify.py`). A client often tries more than once: after a failure it starts over with a new Authentication request. We classify the **last** attempt and note how many there were. SAE commits re-sent inside one exchange (after an anti-clogging request, status 76) don't start a new attempt.
4. **Walk the gates in order:** auth → association → 4-way handshake → DHCP. The first explicit failure (a failure status, or a deauth) decides the result; otherwise, where the client stopped decides it.

### Decisions worth defending

- **"Missing message" needs evidence.** "M1 seen, no M2" could just mean the capture stopped. We report `HANDSHAKE_NO_M2/M3/M4` only if something shows the other side gave up: a deauth, or the AP re-sending its message with a **new replay counter**. Otherwise the result is `INCOMPLETE`. The same rule applies to DHCP (two or more unanswered Discovers) and SAE (repeated Confirms).
- **Precedence during the handshake.** Deauth reason 14 (MIC failure) is an explicit statement, so it wins. Otherwise the *missing message* is more useful than reason 15 ("timeout" says it failed, the gap says where), which matches the spec's example (M2 then deauth 15 → `HANDSHAKE_NO_M3`). `HANDSHAKE_TIMEOUT` is for reason 15 when no EAPOL frames were captured at all.
- **Why "no M3" means "wrong passphrase".** The AP derives the session key from the passphrase, both nonces and both MACs, then checks M2's MIC with it. With a different passphrase the client computed a different key, so the MIC doesn't match and the AP silently drops M2. It never sends M3, and eventually it retries M1 or times out. The SAE equivalent: the AP can't verify the client's Confirm, so it never sends its own.
- **Leaving isn't failing.** If a client completes the connection and later sends deauth/disassoc reason 3 or 8 ("I'm leaving"), the result is `CONNECTED` with a note. The public sample ends exactly like this. A deauth from the AP after connecting (e.g. reason 4, inactivity) is `DEAUTHENTICATED`.
- **Missing frames are inferred carefully.** An AP only sends M1 after a successful association, so M1 proves association even if the Assoc Response wasn't captured. Unencrypted DHCP between client and AP proves the link is up. Whether the handshake is needed comes from the Beacon's RSN element, or failing that from the client's Assoc Request.
- **DHCP on WPA2/WPA3.** No DHCP frames on an RSN network gives "not observable: encrypted", never a DHCP failure (SPEC 4.6). On an open network, no DHCP frames gives "not seen" (static IP, or the capture missed it).

### Test data

`tests/gen_captures.py` writes 21 deterministic captures (every result code, plus WPA3 anti-clogging, roaming, a client leaving, a truncated frame and a wired DHCP exchange), each with an `.expected.json`. It writes the pcap format directly: a 24-byte global header, then a 16-byte header per packet. That keeps timestamps exact and lets a truncated byte string sit between normal frames. A test regenerates everything and checks the committed files are byte-identical, so the data can't drift from the generator.

### Questions to be ready for

- *A user says "Wi-Fi doesn't work". What do you look at?* The client's last attempt: did authentication, association and the 4-way handshake complete? Which message is missing, and did the AP retry? Then DHCP, if it's visible.
- *Why would the AP re-send M1?* It didn't get a valid M2 in time: the client didn't answer, or its MIC was wrong.
- *How do you avoid blaming the wrong stage?* Ignore corrupted frames, drop MAC-level duplicates, require evidence before calling a failure, and prefer explicit reason and status codes over inference.

## M3: The C parser (`c/wifiparse.c`)

### What it does

It opens a capture with libpcap (`pcap_open_offline`, which reads both pcap and pcapng), checks the link type (`pcap_datalink`), and loops over `pcap_next_ex`. For each packet it prints one JSON line with type, subtype, the flag bits, Addr1-4, SA/DA/BSSID, the sequence number, and the FCS verdict. A frame it can't parse still produces a line, with `"error"` set. `--quiet` prints only a summary (frames, errors, seconds), which M5 uses for the speed measurement.

### Walk through the code

1. **`parse_radiotap`**: at least 8 bytes, version 0, then `it_len` (little-endian u16 at offset 2). Reject `it_len < 8` and `it_len > caplen`. Then find the **Flags** field so we know whether the frame ends with an FCS:
   - The present bitmaps come first. Keep reading 32-bit words while bit 31 (EXT) is set.
   - The fields start after the last word. Only **TSFT** (bit 0, a u64) can come before Flags (bit 1).
   - TSFT is **8-byte aligned, counted from the start of the radiotap header**, so round the offset up to a multiple of 8, then skip 8.
   - Flags is the next byte, and bit 0x10 means "FCS at end".

   Every read stays below `it_len`.
2. **FCS**: if present, the last 4 bytes are a CRC-32 (reflected polynomial 0xEDB88320, init and final XOR 0xFFFFFFFF, the same CRC as Ethernet and zlib), stored least-significant byte first. The CRC is computed over the frame without those 4 bytes and compared.
3. **`parse_80211`**: Frame Control gives version, type, subtype and flags. Refuse versions other than 0. Compute **`header_len`** from type/subtype/flags, and only after checking `len >= header_len` read the addresses and Sequence Control. So every offset used afterwards is provably in bounds.
4. **`resolve_addresses`**: the ToDS/FromDS table (the same one Wireshark uses). The special cases are A-MSDU, PS-Poll and CF-End.

### C decisions worth defending

- **No pointer casts for multi-byte fields.** `*(uint16_t *)p` is undefined behaviour when `p` is unaligned (and radiotap/802.11 fields often are), and it depends on host endianness. `le16()` / `le32()` assemble the value byte by byte: always correct, and UBSan-clean.
- **`caplen`, never `len`.** `pcap_pkthdr.len` is the size on the wire; `caplen` is what was actually saved (a snap length can cut packets). All bounds use `caplen`.
- **No allocation per packet.** The frame struct lives on the stack and address fields point into libpcap's buffer, valid until the next `pcap_next_ex`. The only heap object is the pcap handle, closed on every return path. There's nothing to leak.
- **Error strings need no JSON escaping.** They're our own `snprintf` output with no quotes or backslashes. MACs are printed as hex, so no bytes from the packet ever reach the output as text.
- **Build flags**: `-std=c11 -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wconversion -Wstrict-prototypes -Wmissing-prototypes`. `-D_DEFAULT_SOURCE` is needed because `pcap.h` uses BSD types (`u_char`) that glibc hides in strict C11 mode. `make debug` adds `-fsanitize=address,undefined -fno-sanitize-recover=all`, so any finding aborts with a non-zero status and fails the test that ran it.

### How it's tested (`tests/test_c_parser.py`)

The C output is compared, field by field, with the Python parser on every capture, plus inputs designed to break it:
- every synthetic frame cut at **every possible length** (with and without radiotap);
- 5,000 **random frames** (fixed seed), most behind random radiotap headers;
- radiotap edge cases: empty packet, `it_len` too small or too large, an EXT bit with no second word, and TSFT alignment with one and with two present words;
- 4-address and A-MSDU frames, pcapng input, `--limit` / `--quiet`, and bad arguments or files.

In CI this all runs against the ASan/UBSan build, and valgrind runs over every capture. A frame counts as matching only if every field matches **and** C reports an error exactly when Python couldn't read the header.

### What the cross-check found (in the Python side)

A local run over the synthetic captures, every truncation point, the public capture and 20,000 random frames (550,500 field comparisons) found 1,923 mismatches, all in the random frames and all Python bugs:
- **Scapy mis-reads newer control subtypes.** It expects different fields for Trigger, NDP Announcement and Control Frame Extension frames than our length check allows for, so it threw on otherwise valid frames. Python now reads control and extension headers directly, and both parsers treat Trigger (2), Beamforming Report Poll (4) and NDP Announcement (5) as RA + TA frames.
- **Scapy discards radiotap Flags** when later radiotap fields are malformed, even though Flags sits at a fixed offset. Python now walks the radiotap bitmap by hand, like C.

After the fixes: **0 mismatches**. Checking one parser against another in a different language, then fuzzing both, found problems neither unit tests nor the real capture had shown.

### Questions to be ready for

- *Walk me through reading one frame safely.* caplen ≥ 8 → version → it_len within caplen → FCS flag → strip and verify the FCS → FC (2 bytes) → version 0 → `header_len` → only then read addresses.
- *Why is TSFT aligned to 8 bytes, and 8 from where?* Radiotap aligns each field to its natural size, measured from the start of the radiotap header (not the packet, not the present word).
- *How do you know there are no leaks?* One allocation (the pcap handle) with `pcap_close` on every path, checked by LeakSanitizer and valgrind in CI.

## M4: Validation against Wireshark

### The `compare` command

`wifi-analyzer compare <capture>` runs three parsers on the same file and compares them field by field, keyed by frame number:

| Source | How |
|---|---|
| Python | `frames.py` (Scapy for management/data frames, plus our own length and radiotap checks) |
| C | `c/wifiparse` (found via `--wifiparse`, `$WIFIPARSE`, `c/wifiparse`, or `PATH`) |
| tshark | `tshark -T fields -e frame.number -e wlan.fc.type -e wlan.fc.subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.seq -e wlan.fc.retry -e wlan.fc.protected -e wlan.fcs.status`, with `-o wlan.check_checksum:TRUE` so Wireshark also validates the FCS |

Agreement = matching (frame, field) pairs / all (frame, field) pairs. A frame missing from one side counts as a disagreement on every field, so gaps can't make the number look better. The report shows two figures:
- **Clean frames**: valid FCS and a complete header. This is the fair comparison: every parser should give the same answer.
- **All frames**: including corrupted and truncated ones, where "the right answer" is partly a matter of policy.

### Results (CI, Wireshark from Ubuntu's tshark package)

Across 21 captures (20 synthetic 802.11 captures + the public `wpa-Induction.pcap`), 1,306 frames, of which 1,292 are clean:

| Pair | Clean frames | All frames |
|---|---|---|
| Python vs tshark | **100%** (11,628 / 11,628 fields) | 99.234% (11,664 / 11,754) |
| C vs tshark | **100%** (11,628 / 11,628 fields) | 99.234% (11,664 / 11,754) |
| Python vs C | **100%** (19,380 / 19,380 fields) | 100% (19,590 / 19,590) |

The 90 non-matching fields are exactly **10 corrupted frames × 9 fields** in the public capture: frames whose Frame Control claims protocol version 2 or 3, which doesn't exist. Wireshark doesn't dissect them as 802.11 at all. We report their type and subtype, mark them as errors, and never use them as evidence. Fields also match on the other 3 bad-FCS frames and on the truncated frame.

In CI, all 150 tests pass on the **ASan + UBSan** build with none skipped: that includes the tshark comparisons, every-truncation-point tests and random-byte fuzzing. **Valgrind** reports no errors or leaks on any capture. The job publishes these numbers as annotations and a job summary, and uploads the full reports as an artifact.

### Why three parsers?

- Python vs C proves the C code does what the (easier to read) Python does, byte for byte, including on malformed input.
- Both vs tshark proves that shared understanding matches Wireshark, the tool network engineers actually trust. Before writing the address logic I read Wireshark's source to see how it defines `wlan.sa` / `wlan.da` / `wlan.bssid` (4-address frames, A-MSDU, PS-Poll, CF-End), so the fields mean the same thing on each side.
- Agreeing on clean frames but reporting disagreements on corrupted ones (instead of hiding them) is what makes the number trustworthy.

### Questions to be ready for

- *How did you validate the C parser?* Field-by-field against a Scapy-based parser and against Wireshark's dissector on 1,306 frames (100% on clean frames), plus fuzzing and truncation at every byte under ASan/UBSan and valgrind in CI.
- *What didn't match, and why?* Ten frames corrupted in the air claim a nonexistent protocol version. Wireshark refuses to dissect them; we flag them. That's a policy difference on garbage input, not a parsing bug.

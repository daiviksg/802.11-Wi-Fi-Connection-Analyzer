# SPEC: 802.11 Wi-Fi Connection Analyzer

Repo: https://github.com/daiviksg/802.11-Wi-Fi-Connection-Analyzer
Owner: Daivik S Gokhale

## 1. Purpose

A command-line tool that reads a packet capture (`.pcap` / `.pcapng`) of Wi-Fi traffic and tells you, for each client, **where its connection attempt succeeded or failed**:

```
probe -> 802.11 authentication -> association -> EAPOL 4-way handshake -> DHCP -> connected
```

It has two parts:

1. **Python analyzer (Scapy):** parses 802.11 management frames, EAPOL frames, and DHCP. It builds a per-client timeline and classifies the failure stage.
2. **C parser (libpcap):** a small, fast, independent parser for radiotap and 802.11 frame headers. Its output is cross-checked against the Python analyzer and against Wireshark/tshark.

The project must honestly support these resume claims:

- Pinpoints where a Wi-Fi connection fails (authentication, association, WPA2/WPA3 4-way handshake, or DHCP) by parsing management frames and EAPOL exchanges with Scapy.
- A C/libpcap parser for radiotap and 802.11 frame headers, validated against Wireshark dissections through an automated pytest suite.

> **Note for the owner:** You will be interviewed on this code, including by a Cisco wireless team. After each milestone, read the code and the `docs/NOTES.md` entry until you can explain every decision without looking. You should write the C parser (Milestone 3) yourself or pair on it line by line, because "walk me through your C code" is a likely interview question.

## 2. Non-goals

- Live capture or monitor-mode setup. The tool only reads files.
- Decrypting data traffic. DHCP analysis only works on open networks, captures already decrypted in Wireshark, or wired-side captures (see 4.6).
- A GUI or web UI.

## 3. Tech stack

| Part | Choice |
|---|---|
| Python | 3.11+, `scapy`, `pytest`, `click` for the CLI, optional `rich` for colored output |
| C | C11, `libpcap`, `make`, gcc/clang with `-Wall -Wextra -Werror`, debug build with `-fsanitize=address,undefined` |
| Validation | `tshark` (Wireshark CLI). Tests that need it are skipped if it isn't installed. |
| CI | GitHub Actions: build C (normal + ASan), run pytest, run the C-vs-Python-vs-tshark comparison |

## 4. Protocol requirements

### 4.1 Link types

Support these pcap link types:

- `DLT_IEEE802_11_RADIO` (127): radiotap header + 802.11. This is the main target.
- `DLT_IEEE802_11` (105): raw 802.11, no radiotap.
- `DLT_EN10MB` (1): Ethernet. Only DHCP analysis applies here, for wired-side captures.

The radiotap header length is the little-endian `it_len` field at byte offset 2. Skip that many bytes to reach the 802.11 header.

### 4.2 Frames to track

| Frame | Type / subtype | What to record |
|---|---|---|
| Probe request / response | mgmt 4 / 5 | SSID, client MAC, BSSID |
| Beacon | mgmt 8 | SSID, BSSID, RSN IE (security type), channel |
| Authentication | mgmt 11 | algorithm (0 = open system, 3 = SAE), transaction sequence, status code |
| Association request / response | mgmt 0 / 1 | status code, AID, RSN IE from request |
| Reassociation request / response | mgmt 2 / 3 | same as association (roaming) |
| Deauthentication / disassociation | mgmt 12 / 10 | reason code, direction (AP to client or client to AP) |
| EAPOL-Key | data frame, LLC/SNAP ethertype `0x888E` | which handshake message (M1 to M4), replay counter |
| DHCP | UDP 67/68 | Discover, Offer, Request, ACK, NAK, with transaction ID |

### 4.3 Security type detection (from the RSN IE, element ID 48)

- AKM suite `00-0F-AC:2` = WPA2-Personal (PSK)
- AKM suite `00-0F-AC:8` = WPA3-Personal (SAE)
- AKM suite `00-0F-AC:1` = 802.1X / Enterprise
- Both 2 and 8 advertised = WPA3 transition mode
- RSN capabilities bits MFPC (bit 7) and MFPR (bit 6) = Protected Management Frames capable / required. WPA3 requires PMF.
- No RSN IE and the privacy bit off = open network

### 4.4 EAPOL 4-way handshake message identification

Use the Key Information field:

| Message | ACK | MIC | Install | Secure | Key data |
|---|---|---|---|---|---|
| M1 (AP to client) | 1 | 0 | 0 | 0 | usually empty |
| M2 (client to AP) | 0 | 1 | 0 | 0 | non-empty (client RSN IE) |
| M3 (AP to client) | 1 | 1 | 1 | 1 | non-empty (encrypted GTK) |
| M4 (client to AP) | 0 | 1 | 0 | 1 | empty |

Tell M2 from M4 by the Secure bit and the key data length, since some implementations differ. Match messages within a handshake using the replay counter.

### 4.5 Failure classification

For each client (client MAC + BSSID), build an ordered timeline and output exactly one result:

| Result code | Rule |
|---|---|
| `CONNECTED` | M4 seen and (DHCP ACK seen, or DHCP not observable) |
| `AUTH_FAILED` | Authentication response with status code not equal to 0 |
| `SAE_FAILED` | SAE commit/confirm exchange incomplete or rejected (WPA3) |
| `ASSOC_REJECTED` | Association response with status code not equal to 0 (report the code and its meaning) |
| `HANDSHAKE_NO_M2` | M1 seen, no M2 from the client (client not responding or wrong network settings) |
| `HANDSHAKE_NO_M3` | M2 seen, no M3 (likely wrong passphrase or MIC failure on the AP side) |
| `HANDSHAKE_NO_M4` | M3 seen, no M4 |
| `HANDSHAKE_TIMEOUT` | Deauth with reason 15 (4-way handshake timeout) |
| `MIC_FAILURE` | Deauth with reason 14 (MIC failure) |
| `DHCP_NO_OFFER` | DHCP Discover seen, no Offer |
| `DHCP_NAK` | DHCP NAK received |
| `DEAUTHENTICATED` | Deauth or disassociation after association, with the reason code |
| `INCOMPLETE` | Capture ends mid-sequence with no clear failure |

Include lookup tables for common IEEE 802.11 **status codes** and **reason codes**, taken from the IEEE 802.11 standard and cross-checked with Wireshark's dissector names, so the output shows a readable meaning next to each code.

### 4.6 DHCP visibility

Over the air on WPA2/WPA3 networks, DHCP is inside encrypted data frames. The tool must say this clearly in its output ("DHCP not observable: encrypted"), not report a false DHCP failure. DHCP analysis works on open networks, on captures decrypted in Wireshark and re-exported, and on Ethernet captures.

## 5. CLI

```
wifi-analyzer analyze <capture> [--client MAC] [--bssid MAC] [--format text|json]
wifi-analyzer frames  <capture> [--limit N]     # dump parsed frames, for debugging
wifi-analyzer compare <capture>                 # Python vs C parser vs tshark agreement report
```

Example text output:

```
Network: "LabNet"  BSSID aa:bb:cc:dd:ee:ff  Security: WPA3-Personal (SAE, PMF required)

Client 11:22:33:44:55:66
  0.000s  Probe Request       -> "LabNet"
  0.004s  Auth (SAE commit)   status 0
  0.009s  Auth (SAE confirm)  status 0
  0.012s  Assoc Response      status 0 (Success)  AID 3
  0.015s  EAPOL M1
  0.018s  EAPOL M2
  1.020s  EAPOL M1 (retry, replay counter 2)
  2.021s  Deauth              reason 15 (4-way handshake timeout)
  RESULT: HANDSHAKE_NO_M3 -> AP never sent M3 after M2. Most likely cause: wrong passphrase.
```

JSON output must contain the same data in a stable schema, documented in `docs/OUTPUT_SCHEMA.md`.

## 6. C parser

`c/wifiparse.c` reads a capture with libpcap and prints one JSON line per 802.11 frame:

```json
{"idx": 42, "ts": 1717000000.123456, "type": 0, "subtype": 11, "addr1": "...", "addr2": "...", "addr3": "...", "seq": 1203, "retry": false, "protected": false}
```

Requirements:

- Parse the radiotap header length and skip it correctly, without assuming a fixed length.
- Parse the 802.11 Frame Control field (protocol version, type, subtype, ToDS/FromDS, retry, protected bits), the address fields based on ToDS/FromDS, and the sequence number.
- **Never read past the captured length.** Check every access against `caplen` and handle truncated frames by printing an error record, not crashing.
- No memory leaks. Must pass ASan/UBSan in CI, and valgrind if available.
- Makefile targets: `make`, `make debug` (sanitizers), `make clean`.

## 7. Test data

1. **Synthetic captures (main test source):** a script `tests/gen_captures.py` uses Scapy to write deterministic `.pcap` files for every result code in 4.5: success (WPA2), success (WPA3/SAE), each failure type, a roaming (reassociation) case, a truncated frame, and a DHCP success/failure on an open network. Each capture comes with an expected-result JSON file.
2. **Real public captures:** download 802.11 captures from the Wireshark SampleCaptures wiki (for example, one with a WPA2 4-way handshake) into `tests/data/public/`, with a `SOURCES.md` listing where each came from. Don't commit anything with unclear licensing.
3. **Own captures (optional):** captured on the owner's own network in monitor mode. Remove or anonymize any third-party MAC addresses before committing.

## 8. Tests (pytest)

- One test per result code, using the synthetic captures.
- EAPOL M1 to M4 identification tests, including the M2-vs-M4 edge case.
- RSN IE parsing tests: WPA2, WPA3, transition mode, PMF flags, open network.
- C parser tests: run the binary on each capture and compare type, subtype, addresses, and sequence number with the Python parser. Then compare with `tshark -T fields -e frame.number -e wlan.fc.type -e wlan.fc.subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.seq`. Tests needing tshark are skipped when it isn't installed.
- A truncated or malformed frame test for both parsers.
- `compare` command test: agreement percentage reported correctly.

## 9. Repo layout

```
.
├── README.md                 # what it does, demo output, how to run, architecture diagram
├── SPEC.md                   # this file
├── pyproject.toml
├── src/wifi_analyzer/
│   ├── cli.py
│   ├── capture.py            # reading pcaps, link-type handling
│   ├── frames.py             # 802.11 / EAPOL / DHCP parsing into dataclasses
│   ├── rsn.py                # RSN IE parsing, security type detection
│   ├── timeline.py           # per-client timelines
│   ├── classify.py           # result-code rules
│   ├── codes.py              # status and reason code tables
│   └── report.py             # text and JSON output
├── c/
│   ├── Makefile
│   ├── wifiparse.c
│   └── radiotap.h / ieee80211.h
├── tests/
│   ├── gen_captures.py
│   ├── data/synthetic/  data/public/
│   └── test_*.py
├── docs/
│   ├── NOTES.md              # learning notes, one section per milestone
│   └── OUTPUT_SCHEMA.md
└── .github/workflows/ci.yml
```

## 10. Milestones

Work one milestone at a time. After each one: all tests pass, CI is green, a commit is made, and a short entry is added to `docs/NOTES.md` explaining the protocol concepts and design decisions in plain language.

| # | Milestone | Done when |
|---|---|---|
| M0 | Repo setup: README with scope and roadmap, pyproject, CI skeleton, `frames` command listing management frames | CI runs; `frames` works on one public capture |
| M1 | Python parsing: management frames, RSN IE, EAPOL M1 to M4, DHCP | Parsing tests pass on synthetic and public captures |
| M2 | Timelines and classification: all result codes, text and JSON output | One passing test per result code |
| M3 | C parser: radiotap + 802.11 headers, JSON output, Makefile, ASan build | C output matches Python on all test captures |
| M4 | Validation: `compare` command, tshark comparison tests in CI | Agreement report generated; CI runs sanitizer build |
| M5 | Polish: README with demo output and architecture diagram, metrics section | Metrics in section 11 filled in |

## 11. Metrics to record (for the resume)

Record these in the README when M5 is done:

- Number of distinct failure types detected
- Number of captures tested (synthetic + public)
- Number of pytest cases
- C parser vs tshark field agreement (%) across N frames
- Python vs C parser agreement (%)
- Parse speed of the C parser (frames/second on the largest capture) compared with the Python parser

## 12. Instructions for Claude Code

- Read this whole spec before writing code. Start with M0 and stop after each milestone for review.
- Write tests alongside code, and never mark a milestone done with failing tests.
- Prefer clear, commented code over clever code. Comments should explain the protocol reason for each check (for example, why the Secure bit tells M2 from M4).
- Never read past buffer bounds in C. Every offset check should be explicit.
- Never invent protocol values. If unsure about a status code, reason code, or bit position, check the IEEE 802.11 standard or Wireshark's dissector and cite it in a comment.
- Don't commit captures containing real third-party MAC addresses.
- At the end of each milestone, add the `docs/NOTES.md` entry described in section 10.

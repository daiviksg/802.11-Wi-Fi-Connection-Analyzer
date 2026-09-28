# 802.11 Wi-Fi Connection Analyzer

A command-line tool that reads a Wi-Fi packet capture (`.pcap` / `.pcapng`) and tells you, for each client, **where its connection attempt succeeded or failed**:

```
probe -> 802.11 authentication -> association -> EAPOL 4-way handshake -> DHCP -> connected
```

It has two parts:

1. **Python analyzer (Scapy)**: parses 802.11 management frames, EAPOL-Key frames, and DHCP. It builds a per-client timeline and names the stage that failed (wrong passphrase, rejected association, handshake timeout, no DHCP offer, ...).
2. **C parser (libpcap)**: a small, fast, independent parser for radiotap and 802.11 headers. It is cross-checked against the Python analyzer and against Wireshark's `tshark`.

See [SPEC.md](SPEC.md) for the full specification.

## Status

| # | Milestone | Status |
|---|---|---|
| M0 | Repo setup, CI, `frames` command | ✅ done |
| M1 | Python parsing: management frames, RSN IE, EAPOL M1 to M4, DHCP | ✅ done |
| M2 | Per-client timelines, failure classification, text/JSON output | ✅ done |
| M3 | C/libpcap parser for radiotap + 802.11 headers, ASan build | ✅ done |
| M4 | `compare` command: Python vs C vs tshark, in CI | ✅ done |
| M5 | Polish: demo output, architecture diagram, metrics | ⏳ next |

## Quick start

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
python tests/data/public/fetch.py          # downloads public sample captures
wifi-analyzer analyze tests/data/synthetic/handshake_no_m3.pcap
make -C c                                  # C parser (needs libpcap-dev); `make -C c debug` for ASan/UBSan
wifi-analyzer compare tests/data/public/wpa-Induction.pcap
pytest                                     # C and tshark tests are skipped if not available
```

## `analyze`: where did the connection fail?

```
Capture: handshake_no_m3.pcap  (12 packets; skipped 0 with bad FCS, 0 malformed, 0 retransmissions)

Network: "LabNet"  BSSID 02:00:00:00:00:aa  Security: WPA3-Personal (SAE, PMF required)  Channel 6

Client 02:00:00:00:00:01
    0.000s  Probe Request -> "LabNet"
    0.004s  Auth (SAE commit)         status 0  from client
    0.005s  Auth (SAE commit)         status 0  from AP
    0.008s  Auth (SAE confirm)        status 0  from client
    0.009s  Auth (SAE confirm)        status 0  from AP
    0.010s  Assoc Request
    0.012s  Assoc Response            status 0 (Successful)  AID 3
    0.015s  EAPOL M1
    0.018s  EAPOL M2
    1.020s  EAPOL M1 (retry, replay counter 2)
    2.021s  Deauth                    reason 15 (4-way handshake timeout)  from AP
  RESULT: HANDSHAKE_NO_M3 -> AP never sent M3 after M2. AP then sent Deauthentication, reason 15 (4-way handshake timeout). Most likely cause: wrong passphrase. The AP checks M2's MIC with its own key; a different passphrase gives a different key, so the check fails and the AP drops M2.
```

`wifi-analyzer analyze <capture> [--client MAC] [--bssid MAC] [--format text|json]`. The JSON output has the same data in a stable schema: [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md).

Result codes: `CONNECTED`, `AUTH_FAILED`, `SAE_FAILED`, `ASSOC_REJECTED`, `HANDSHAKE_NO_M2`, `HANDSHAKE_NO_M3`, `HANDSHAKE_NO_M4`, `HANDSHAKE_TIMEOUT`, `MIC_FAILURE`, `DHCP_NO_OFFER`, `DHCP_NAK`, `DEAUTHENTICATED`, `INCOMPLETE`. A missing message only counts as a failure with evidence (a deauth, or the AP retrying); otherwise the result is `INCOMPLETE`. Corrupted (bad FCS) frames and MAC-level retransmissions are never used as evidence.

## `frames`: what did the parser see?

`wifi-analyzer frames <capture>` lists parsed management, EAPOL and DHCP frames (here from the public `wpa-Induction.pcap`):

```
     1    0.000000s  Beacon                 sa=00:0c:41:82:b2:55  da=ff:ff:ff:ff:ff:ff  bssid=00:0c:41:82:b2:55  seq=3973     ssid="Coherer"  ch 1  WPA2-Personal (PSK)
    80    5.644958s  Authentication         sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4041     Open System response  status 0 (Successful)
    84    5.647953s  Assoc Response         sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4042     status 0 (Successful)  AID 1
    87    5.649953s  EAPOL M1               sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4043     key info 0x008a  replay counter 0  key data 22 bytes
    92    5.655957s  EAPOL M3               sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4044     key info 0x13ca  replay counter 1  key data 80 bytes
   575   15.924259s  Probe Request          sa=4a:91:5a:a3:e4:0b  da=ef:bf:b9:f8:fe:3b  bssid=f4:9f:8f:ea:7b:e6  seq= 557     no SSID element  [bad FCS]
```

Options: `--all` includes every frame (control, data), `--limit N`, and `--format json` prints one JSON object per frame. Malformed or truncated frames are always shown with an `ERROR:` note; they never crash the parser.

## `wifiparse` and `compare`: is the parsing right?

`c/wifiparse` is an independent C/libpcap parser for radiotap and 802.11 headers. It prints one JSON line per frame, checks every read against the captured length, and reports malformed frames instead of crashing:

```
$ c/wifiparse --limit 1 tests/data/public/wpa-Induction.pcap
{"idx":1,"ts":1167891285.859308,"caplen":168,"type":0,"subtype":8,"to_ds":false,"from_ds":false,"retry":false,"protected":false,"addr1":"ff:ff:ff:ff:ff:ff","addr2":"00:0c:41:82:b2:55","addr3":"00:0c:41:82:b2:55","addr4":null,"sa":"00:0c:41:82:b2:55","da":"ff:ff:ff:ff:ff:ff","bssid":"00:0c:41:82:b2:55","seq":3973,"fcs_ok":true,"error":null}
```

`wifi-analyzer compare <capture>` checks the Python parser, the C parser and Wireshark's `tshark` against each other, field by field (type, subtype, SA, DA, BSSID, sequence number, Retry, Protected, FCS verdict). Results in CI over 21 captures (1,306 frames):

| | Clean frames (valid FCS, complete header) | All frames |
|---|---|---|
| Python vs tshark | 100% | 99.23% |
| C vs tshark | 100% | 99.23% |
| Python vs C | 100% | 100% |

The only disagreements are 10 frames corrupted in the air that claim a nonexistent 802.11 protocol version: Wireshark doesn't dissect them, and we flag them as errors. CI also runs every test (including byte-by-byte truncation and random-input fuzzing) against an AddressSanitizer + UndefinedBehaviorSanitizer build, and valgrind on every capture. Details are in [docs/NOTES.md](docs/NOTES.md).

## Supported inputs

| Link type | DLT | Used for |
|---|---|---|
| 802.11 + radiotap | 127 | Main target: monitor-mode captures |
| 802.11 | 105 | Raw 802.11 frames |
| Ethernet | 1 | DHCP analysis of wired-side captures |

## Limits

- Reads capture files only; no live capture.
- Doesn't decrypt traffic. On WPA2/WPA3 networks, DHCP travels inside encrypted data frames, so it is reported as "not observable" rather than as a failure.

## Test data

- `tests/data/synthetic/`: 21 deterministic captures made by `tests/gen_captures.py`, one or more per result code, each with an `.expected.json`. All MAC addresses are locally administered (`02:...`).
- `tests/data/public/`: public Wireshark sample captures, downloaded by `fetch.py` (not committed). See [SOURCES.md](tests/data/public/SOURCES.md).

Design notes for each milestone are in [docs/NOTES.md](docs/NOTES.md).

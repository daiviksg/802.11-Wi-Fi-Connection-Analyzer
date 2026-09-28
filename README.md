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
| M1 | Python parsing: management frames, RSN IE, EAPOL M1 to M4, DHCP | ⏳ next |
| M2 | Per-client timelines, failure classification, text/JSON output | |
| M3 | C/libpcap parser for radiotap + 802.11 headers, ASan build | |
| M4 | `compare` command: Python vs C vs tshark, in CI | |
| M5 | Polish: demo output, architecture diagram, metrics | |

## Quick start

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
python tests/data/public/fetch.py          # downloads public sample captures
wifi-analyzer frames tests/data/public/wpa-Induction.pcap --limit 5
pytest
```

`wifi-analyzer frames` lists parsed 802.11 frames:

```
     1    0.000000s  Beacon                 a1=ff:ff:ff:ff:ff:ff  a2=00:0c:41:82:b2:55  a3=00:0c:41:82:b2:55  seq=3973     ssid="Coherer"
    78    5.643955s  Authentication         a1=00:0c:41:82:b2:55  a2=00:0d:93:82:36:3a  a3=00:0c:41:82:b2:55  seq=  23
   575   15.924259s  Probe Request          a1=ef:bf:b9:f8:fe:3b  a2=4a:91:5a:a3:e4:0b  a3=f4:9f:8f:ea:7b:e6  seq= 557     [bad FCS]
```

Options: `--all` includes control and data frames, `--limit N`, and `--format json` prints one JSON object per frame. Malformed or truncated frames are always shown with an `ERROR:` note; they never crash the parser.

## Supported inputs

| Link type | DLT | Used for |
|---|---|---|
| 802.11 + radiotap | 127 | Main target: monitor-mode captures |
| 802.11 | 105 | Raw 802.11 frames |
| Ethernet | 1 | DHCP analysis of wired-side captures (M1+) |

## Limits

- Reads capture files only; no live capture.
- Doesn't decrypt traffic. On WPA2/WPA3 networks, DHCP travels inside encrypted data frames, so it is reported as "not observable" rather than as a failure.

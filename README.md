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
| M2 | Per-client timelines, failure classification, text/JSON output | ⏳ next |
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

`wifi-analyzer frames` lists parsed management, EAPOL and DHCP frames:

```
     1    0.000000s  Beacon                 sa=00:0c:41:82:b2:55  da=ff:ff:ff:ff:ff:ff  bssid=00:0c:41:82:b2:55  seq=3973     ssid="Coherer"  ch 1  WPA2-Personal (PSK)
    80    5.644958s  Authentication         sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4041     Open System response  status 0 (Successful)
    84    5.647953s  Assoc Response         sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4042     status 0 (Successful)  AID 1
    87    5.649953s  EAPOL M1               sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4043     key info 0x008a  replay counter 0  key data 22 bytes
    92    5.655957s  EAPOL M3               sa=00:0c:41:82:b2:55  da=00:0d:93:82:36:3a  bssid=00:0c:41:82:b2:55  seq=4044     key info 0x13ca  replay counter 1  key data 80 bytes
   575   15.924259s  Probe Request          sa=4a:91:5a:a3:e4:0b  da=ef:bf:b9:f8:fe:3b  bssid=f4:9f:8f:ea:7b:e6  seq= 557     no SSID element  [bad FCS]
```

Options: `--all` includes every frame (control, data), `--limit N`, and `--format json` prints one JSON object per frame. Malformed or truncated frames are always shown with an `ERROR:` note; they never crash the parser.

## Supported inputs

| Link type | DLT | Used for |
|---|---|---|
| 802.11 + radiotap | 127 | Main target: monitor-mode captures |
| 802.11 | 105 | Raw 802.11 frames |
| Ethernet | 1 | DHCP analysis of wired-side captures (M1+) |

## Limits

- Reads capture files only; no live capture.
- Doesn't decrypt traffic. On WPA2/WPA3 networks, DHCP travels inside encrypted data frames, so it is reported as "not observable" rather than as a failure.

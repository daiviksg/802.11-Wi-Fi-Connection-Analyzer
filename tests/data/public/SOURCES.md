# Public capture sources

These captures are **not committed**. `fetch.py` downloads them and checks each one against a pinned SHA-256.

| File | Source | SHA-256 | Contents |
|---|---|---|---|
| `wpa-Induction.pcap` | [Wireshark SampleCaptures wiki](https://wiki.wireshark.org/SampleCaptures) ([direct link](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap)) | `2b57dca7…d170c8` | 1093 frames, radiotap + 802.11 with FCS. WPA2-PSK network "Coherer" (passphrase "Induction", as published on the wiki). One client probes, authenticates, associates, completes the 4-way handshake, and later disassociates. 13 frames have a bad FCS. |

Why the files aren't committed: the wiki doesn't state a license for individual captures, and the files contain real devices' MAC addresses (SPEC.md §7).

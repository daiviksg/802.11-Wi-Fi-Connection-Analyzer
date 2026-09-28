"""Download the public test captures listed in SOURCES.md.

We don't commit these files: their redistribution terms aren't stated, and
they contain real devices' MAC addresses. Each download is checked against
a pinned SHA-256, so a changed upstream file fails loudly instead of
silently changing test results.

Usage: python tests/data/public/fetch.py
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent

CAPTURES = {
    "wpa-Induction.pcap": (
        "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap",
        "2b57dca7fa2c3bd0e942060b546028d961bfb698fb12ed8b2947b13f88d170c8",
    ),
}


def main() -> int:
    failed = False
    for name, (url, sha256) in CAPTURES.items():
        dest = HERE / name
        if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha256:
            print(f"ok       {name}")
            continue
        print(f"fetching {name}")
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != sha256:
            print(f"ERROR    {name}: sha256 {digest} != expected {sha256}", file=sys.stderr)
            failed = True
            continue
        dest.write_bytes(data)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

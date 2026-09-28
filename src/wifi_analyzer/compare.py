"""Cross-checking three independent 802.11 header parsers:

  * Python: frames.py (Scapy for management/data headers, plus our own checks)
  * C:      c/wifiparse (hand-written, libpcap)
  * tshark: Wireshark's dissector, the reference

Each produces one row per frame, keyed by frame number (1-based, like
Wireshark's frame.number), with the same field names. `agreement` counts,
field by field, how often two sources give the same value.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .capture import DLT_EN10MB, read_packets
from .frames import parse_frame

# Fields every source can produce, compared between all pairs.
# (tshark's names: wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.da, wlan.bssid,
# wlan.seq, wlan.fc.retry, wlan.fc.protected, wlan.fcs.status)
COMMON_FIELDS = ("type", "subtype", "sa", "da", "bssid", "seq", "retry", "protected", "fcs_ok")
# Python and C also report the raw addresses and DS bits.
PY_C_FIELDS = COMMON_FIELDS + ("to_ds", "from_ds", "addr1", "addr2", "addr3", "addr4")

TSHARK_FIELDS = (
    "frame.number", "wlan.fc.type", "wlan.fc.subtype", "wlan.sa", "wlan.da", "wlan.bssid",
    "wlan.seq", "wlan.fc.retry", "wlan.fc.protected", "wlan.fcs.status",
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class ParserError(RuntimeError):
    pass


# --- rows from each source ----------------------------------------------------

def python_rows(path: str | Path) -> dict[int, dict]:
    rows = {}
    for pkt in read_packets(path):
        if pkt.linktype == DLT_EN10MB:
            continue  # no 802.11 header to compare
        f = parse_frame(pkt)
        if f is None:
            continue
        d = f.to_dict()
        row = {k: d[k] for k in PY_C_FIELDS}
        row["error"] = f.error
        rows[f.idx] = row
    return rows


def find_wifiparse(explicit: str | None = None) -> str | None:
    """The C parser: --wifiparse, $WIFIPARSE, c/wifiparse in the repo, or on PATH."""
    candidates = [explicit, os.environ.get("WIFIPARSE"), str(REPO_ROOT / "c" / "wifiparse"), shutil.which("wifiparse")]
    for c in candidates:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return c
    return None


def c_rows(path: str | Path, binary: str) -> dict[int, dict]:
    proc = subprocess.run([binary, str(path)], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ParserError(f"wifiparse exited with {proc.returncode}: {proc.stderr.strip()}")
    rows = {}
    for line in proc.stdout.splitlines():
        rec = json.loads(line)
        row = {k: rec[k] for k in PY_C_FIELDS}
        row["error"] = rec["error"]
        rows[rec["idx"]] = row
    return rows


def find_tshark(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("TSHARK") or shutil.which("tshark")


def _tshark_bool(v: str) -> bool | None:
    # Older tshark prints booleans as 1/0, newer as True/False.
    if v in ("1", "True", "true"):
        return True
    if v in ("0", "False", "false"):
        return False
    return None


def _tshark_fcs(v: str) -> bool | None:
    # wlan.fcs.status uses Wireshark's checksum values: 0 Bad, 1 Good, 2 Unverified.
    if v in ("1", "Good"):
        return True
    if v in ("0", "Bad"):
        return False
    return None


def tshark_rows(path: str | Path, tshark: str) -> dict[int, dict]:
    cmd = [
        tshark, "-n", "-r", str(path),
        "-o", "wlan.check_checksum:TRUE",  # validate the FCS when the capture has one
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ParserError(f"tshark exited with {proc.returncode}: {proc.stderr.strip()}")
    return parse_tshark_fields(proc.stdout)


def parse_tshark_fields(text: str) -> dict[int, dict]:
    """Parse `tshark -T fields` output (tab-separated, columns as TSHARK_FIELDS)."""
    rows = {}
    for line in text.splitlines():
        cols = line.split("\t") + [""] * len(TSHARK_FIELDS)
        num, ftype, subtype, sa, da, bssid, seq, retry, prot, fcs = cols[: len(TSHARK_FIELDS)]
        if not ftype:
            continue  # not an 802.11 frame (or not dissected as one)
        rows[int(num)] = {
            "type": int(ftype, 0),
            "subtype": int(subtype, 0) if subtype else None,
            "sa": sa or None,
            "da": da or None,
            "bssid": bssid or None,
            "seq": int(seq) if seq else None,
            "retry": _tshark_bool(retry),
            "protected": _tshark_bool(prot),
            "fcs_ok": _tshark_fcs(fcs),
            "error": None,
        }
    return rows


# --- agreement ----------------------------------------------------------------

@dataclass
class Agreement:
    fields: tuple[str, ...]
    per_field: dict[str, list[int]] = field(default_factory=dict)  # field -> [agree, total]
    frames: int = 0
    only_in_a: list[int] = field(default_factory=list)
    only_in_b: list[int] = field(default_factory=list)
    disagreements: list[tuple[int, str, object, object]] = field(default_factory=list)

    @property
    def agree(self) -> int:
        return sum(a for a, _ in self.per_field.values())

    @property
    def total(self) -> int:
        return sum(t for _, t in self.per_field.values())

    @property
    def percent(self) -> float:
        return 100.0 * self.agree / self.total if self.total else 100.0


def agreement(a: dict[int, dict], b: dict[int, dict], fields=COMMON_FIELDS, only: set[int] | None = None) -> Agreement:
    """Field-by-field agreement between two sources.

    Every (frame, field) pair counts once. A frame present in only one source
    counts as a disagreement on every field. `only` restricts the frame set.
    """
    res = Agreement(tuple(fields), {f: [0, 0] for f in fields})
    idxs = set(a) | set(b)
    if only is not None:
        idxs &= only
    for idx in sorted(idxs):
        res.frames += 1
        ra, rb = a.get(idx), b.get(idx)
        if ra is None:
            res.only_in_b.append(idx)
        elif rb is None:
            res.only_in_a.append(idx)
        for f in fields:
            res.per_field[f][1] += 1
            va = ra.get(f) if ra else None
            vb = rb.get(f) if rb else None
            if ra is not None and rb is not None and va == vb:
                res.per_field[f][0] += 1
            else:
                res.disagreements.append((idx, f, va, vb))
    return res


def clean_frames(py: dict[int, dict]) -> set[int]:
    """Frames that are well-formed and not corrupted in the air: the fair basis
    for comparing parsers. (For a corrupted or truncated frame, "the right
    answer" is a matter of policy: we refuse to report a half-read header.)"""
    return {i for i, r in py.items() if r["error"] is None and r["fcs_ok"] is not False}


def compare_capture(path: str | Path, wifiparse: str | None = None, tshark: str | None = None) -> dict:
    """Run every available parser on one capture and summarise agreement."""
    py = python_rows(path)
    clean = clean_frames(py)
    sources = {"python": py}
    missing = {}
    binary = find_wifiparse(wifiparse)
    if binary:
        sources["c"] = c_rows(path, binary)
    else:
        missing["c"] = "wifiparse binary not found (build it with `make -C c`, or pass --wifiparse)"
    ts = find_tshark(tshark)
    if ts:
        sources["tshark"] = tshark_rows(path, ts)
    else:
        missing["tshark"] = "tshark not found"

    pairs = []
    for a, b in (("python", "c"), ("python", "tshark"), ("c", "tshark")):
        if a in sources and b in sources:
            fields = PY_C_FIELDS if (a, b) == ("python", "c") else COMMON_FIELDS
            pairs.append({
                "a": a,
                "b": b,
                "all": agreement(sources[a], sources[b], fields),
                "clean": agreement(sources[a], sources[b], fields, only=clean),
            })
    return {
        "capture": Path(path).name,
        "frames": len(py),
        "clean_frames": len(clean),
        "clean_set": clean,  # frame numbers; not part of the JSON output
        "sources": sorted(sources),
        "missing": missing,
        "pairs": pairs,
    }


def _agreement_json(ag: Agreement, max_disagreements: int) -> dict:
    return {
        "frames": ag.frames,
        "agree": ag.agree,
        "total": ag.total,
        "percent": round(ag.percent, 3),
        "per_field": {f: {"agree": a, "total": t} for f, (a, t) in ag.per_field.items()},
        "only_in_a": ag.only_in_a,
        "only_in_b": ag.only_in_b,
        "disagreements": [
            {"idx": i, "field": f, "a": va, "b": vb} for i, f, va, vb in ag.disagreements[:max_disagreements]
        ],
    }


def report_json(result: dict, max_disagreements: int = 50) -> dict:
    out = {k: v for k, v in result.items() if k not in ("pairs", "clean_set")}
    out["pairs"] = [
        {
            "a": p["a"],
            "b": p["b"],
            "all": _agreement_json(p["all"], max_disagreements),
            "clean": _agreement_json(p["clean"], max_disagreements),
        }
        for p in result["pairs"]
    ]
    return out


def report_text(result: dict, max_disagreements: int = 10) -> str:
    lines = [
        f"Capture: {result['capture']}  ({result['frames']} 802.11 frames, {result['clean_frames']} clean: "
        f"valid FCS and fully parsed)",
        f"Parsers: {', '.join(result['sources'])}",
    ]
    for name, why in result["missing"].items():
        lines.append(f"  (skipped {name}: {why})")
    if not result["pairs"]:
        lines.append("Nothing to compare: only one parser available.")
        return "\n".join(lines) + "\n"

    for p in result["pairs"]:
        title = f"{p['a']} vs {p['b']}"
        clean, allf = p["clean"], p["all"]
        lines += ["", f"{title}: {clean.percent:.2f}% of fields agree on clean frames "
                      f"({clean.agree}/{clean.total}); {allf.percent:.2f}% on all frames ({allf.agree}/{allf.total})"]
        lines.append(f"  {'field':<10} {'clean frames':>20} {'all frames':>20}")
        for f in clean.fields:
            ca, ct = clean.per_field[f]
            aa, at = allf.per_field[f]
            lines.append(f"  {f:<10} {ca:>9}/{ct:<6} {_pct(ca, ct):>5} {aa:>9}/{at:<6} {_pct(aa, at):>5}")
        if allf.disagreements:
            lines.append(f"  first disagreements (frame, field, {p['a']}, {p['b']}):")
            for idx, f, va, vb in allf.disagreements[:max_disagreements]:
                tag = "" if idx in result["clean_set"] else "  [bad FCS / malformed]"
                lines.append(f"    #{idx:<6} {f:<9} {va!s:<20} {vb!s}{tag}")
    return "\n".join(lines) + "\n"


def _pct(a: int, t: int) -> str:
    return f"{100.0 * a / t:.1f}%" if t else "  -  "

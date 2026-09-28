"""Command-line entry point: `wifi-analyzer`."""

from __future__ import annotations

import json

import click

from . import __version__
from .capture import read_packets
from .frames import TYPE_MGMT, parse_frame


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Find where a Wi-Fi connection attempt succeeded or failed."""


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", type=int, default=None, help="Stop after N frames are printed.")
@click.option("--all", "show_all", is_flag=True, help="Include control and data frames, not just management.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
def frames(capture: str, limit: int | None, show_all: bool, fmt: str) -> None:
    """Dump parsed 802.11 frames (for debugging)."""
    printed = 0
    t0 = None
    for pkt in read_packets(capture):
        frame = parse_frame(pkt)
        if frame is None:
            continue
        # Malformed frames are always shown: hiding them would hide the bug.
        if not show_all and frame.error is None and frame.type != TYPE_MGMT:
            continue
        if limit is not None and printed >= limit:
            break
        if t0 is None:
            t0 = frame.ts
        if fmt == "json":
            click.echo(json.dumps(frame.to_dict()))
        else:
            click.echo(_format_text(frame, frame.ts - t0))
        printed += 1


def _format_text(frame, rel_ts: float) -> str:
    head = f"{frame.idx:>6}  {rel_ts:10.6f}s  "
    bad_fcs = "  [bad FCS]" if frame.fcs_ok is False else ""
    if frame.error:
        return head + f"{frame.name:<22} ERROR: {frame.error}{bad_fcs}"
    # R = retransmission, P = protected (encrypted) frame body
    flags = "".join(f for f, on in (("R", frame.retry), ("P", frame.protected)) if on)
    line = (
        f"{frame.name:<22} a1={frame.addr1 or '-':<17}  a2={frame.addr2 or '-':<17}  "
        f"a3={frame.addr3 or '-':<17}  seq={frame.seq if frame.seq is not None else '-':>4} {flags:<2}"
    )
    if frame.ssid is not None:
        line += f'  ssid="{frame.ssid}"'
    line += bad_fcs
    return (head + line).rstrip()


if __name__ == "__main__":
    main()

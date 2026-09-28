"""Command-line entry point: `wifi-analyzer`."""

from __future__ import annotations

import json

import click

from . import __version__
from .capture import read_packets
from .compare import ParserError, compare_capture, report_json, report_text
from .frames import TYPE_MGMT, Frame, parse_frame
from .report import build_report, describe_frame, render_text


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Find where a Wi-Fi connection attempt succeeded or failed."""


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False))
@click.option("--client", default=None, help="Only this client MAC.")
@click.option("--bssid", default=None, help="Only this AP (BSSID).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
def analyze(capture: str, client: str | None, bssid: str | None, fmt: str) -> None:
    """Show each client's connection attempt and where it succeeded or failed."""
    report = build_report(capture, client=client, bssid=bssid)
    if fmt == "json":
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo(render_text(report), nl=False)


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False))
@click.option("--wifiparse", "wifiparse_path", default=None, help="Path to the C parser (default: c/wifiparse, $WIFIPARSE, PATH).")
@click.option("--tshark", "tshark_path", default=None, help="Path to tshark (default: $TSHARK, PATH).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
def compare(capture: str, wifiparse_path: str | None, tshark_path: str | None, fmt: str) -> None:
    """Agreement report: Python parser vs C parser vs tshark, field by field."""
    try:
        result = compare_capture(capture, wifiparse=wifiparse_path, tshark=tshark_path)
    except ParserError as exc:
        raise click.ClickException(str(exc)) from exc
    if fmt == "json":
        click.echo(json.dumps(report_json(result), indent=2, default=str))
    else:
        click.echo(report_text(result), nl=False)


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", type=int, default=None, help="Stop after N frames are printed.")
@click.option("--all", "show_all", is_flag=True, help="Include every frame, not just management, EAPOL and DHCP.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
def frames(capture: str, limit: int | None, show_all: bool, fmt: str) -> None:
    """Dump parsed frames (for debugging)."""
    printed = 0
    t0 = None
    for pkt in read_packets(capture):
        frame = parse_frame(pkt)
        if frame is None:
            continue
        if not show_all and not _interesting(frame):
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


def _interesting(frame: Frame) -> bool:
    # Malformed frames are always shown: hiding them would hide the bug.
    return frame.error is not None or frame.type == TYPE_MGMT or frame.eapol is not None or frame.dhcp is not None


def _format_text(frame: Frame, rel_ts: float) -> str:
    head = f"{frame.idx:>6}  {rel_ts:10.6f}s  "
    bad_fcs = "  [bad FCS]" if frame.fcs_ok is False else ""
    if frame.error:
        return head + f"{frame.name:<22} ERROR: {frame.error}{bad_fcs}"
    # R = retransmission, P = protected (encrypted) frame body
    flags = "".join(f for f, on in (("R", frame.retry), ("P", frame.protected)) if on)
    line = (
        f"{frame.name:<22} sa={frame.sa or '-':<17}  da={frame.da or '-':<17}  "
        f"bssid={frame.bssid or '-':<17}  seq={frame.seq if frame.seq is not None else '-':>4} {flags:<2}"
    )
    detail = describe_frame(frame)
    if detail:
        line += "  " + detail
    return (head + line + bad_fcs).rstrip()


if __name__ == "__main__":
    main()

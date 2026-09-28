"""Summarise the validation job: test counts and parser agreement.

Reads pytest's JUnit XML and the `wifi-analyzer compare --format json`
reports, then writes:
  * a Markdown table to $GITHUB_STEP_SUMMARY (shown on the run's page), and
  * `::notice` annotations, which the GitHub API exposes publicly, so the
    numbers can be read without admin access to the logs.

Usage: python scripts/ci_summary.py reports/
"""

from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    tests, failures, errors, skipped = (int(suite.get(k, 0)) for k in ("tests", "failures", "errors", "skipped"))
    return {"tests": tests, "passed": tests - failures - errors - skipped, "failed": failures + errors, "skipped": skipped}


def main(report_dir: str) -> int:
    reports = Path(report_dir)
    notices: list[str] = []
    md = ["## Validation summary", ""]

    junit = reports / "junit.xml"
    if junit.exists():
        c = junit_counts(junit)
        line = f"pytest (sanitizer build): {c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped of {c['tests']}"
        notices.append(line)
        md += [line, ""]

    totals: dict[str, list[int]] = {}
    md += ["| capture | frames | clean | python vs c | python vs tshark | c vs tshark |", "|---|---|---|---|---|---|"]
    for path in sorted(reports.glob("*.json")):
        data = json.loads(path.read_text())
        cells = {}
        for p in data["pairs"]:
            key = f"{p['a']} vs {p['b']}"
            clean, allf = p["clean"], p["all"]
            cells[key] = f"{clean['percent']:.2f}% clean / {allf['percent']:.2f}% all"
            t = totals.setdefault(key, [0, 0, 0, 0])
            t[0] += clean["agree"]
            t[1] += clean["total"]
            t[2] += allf["agree"]
            t[3] += allf["total"]
            if allf["disagreements"]:
                first = allf["disagreements"][:3]
                notices.append(f"{data['capture']} {key}: {len(allf['disagreements'])}+ disagreements, first {first}")
        md.append(
            f"| {data['capture']} | {data['frames']} | {data['clean_frames']} | "
            + " | ".join(cells.get(k, "-") for k in ("python vs c", "python vs tshark", "c vs tshark"))
            + " |"
        )
    md.append("")
    for key, (ca, ct, aa, at) in totals.items():
        line = (f"{key}: {100 * ca / ct:.3f}% of fields agree on clean frames ({ca}/{ct}); "
                f"{100 * aa / at:.3f}% on all frames ({aa}/{at})") if ct and at else f"{key}: no frames"
        notices.append(line)
        md.append(f"- {line}")

    for n in notices:
        print(f"::notice title=validation::{n}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(md) + "\n")
    else:
        print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "reports"))

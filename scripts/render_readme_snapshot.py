#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "README.md"
TRACK_FOCUS = {
    "TryHackMe/00-foundations": "intro security, research workflow, tooling basics",
    "TryHackMe/10-web": "web fundamentals, HTTP, JavaScript, app testing basics",
    "TryHackMe/20-linux": "Linux fundamentals",
    "TryHackMe/30-windows": "Windows fundamentals",
    "TryHackMe/40-networking": "networking, protocols, packet analysis",
    "TryHackMe/50-crypto": "hashing, public-key crypto, cracking basics",
    "TryHackMe/60-forensics": "introductory forensic tooling",
    "TryHackMe/80-blue-team": "SIEM, detection, analyst notes",
    "TryHackMe/90-events": "event and challenge write-ups, sanitized for publication",
}
AT_A_GLANCE_RE = re.compile(
    r"(?ms)^## At A Glance\n\n.*?(?=^## Why This Repo Exists$)"
)
WHAT_YOU_WILL_FIND_RE = re.compile(
    r"(?ms)^## What You Will Find\n\n.*?(?=^## Start Here$)"
)


def tracked_markdown_files() -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "ls-files",
            "-z",
            "--",
            "TryHackMe/**/*.md",
            "notes/**/*.md",
        ],
        cwd=ROOT,
        shell=False,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        print(stderr or "git ls-files failed", file=sys.stderr)
        raise SystemExit(completed.returncode)

    return [
        path
        for path in completed.stdout.decode("utf-8", errors="replace").split("\0")
        if path and not path.startswith("TryHackMe/_meta/")
    ]


def build_at_a_glance(files: list[str]) -> str:
    total_notes = len(files)
    tryhackme_notes = sum(1 for path in files if path.startswith("TryHackMe/"))
    notes_tree_notes = sum(1 for path in files if path.startswith("notes/"))
    tryhackme_tracks = sorted(
        {"/".join(path.split("/")[:2]) for path in files if path.startswith("TryHackMe/")}
    )

    lines = [
        "## At A Glance",
        "",
        "Current public snapshot:",
        "",
        f"- `{total_notes}` active public notes",
        f"- `{tryhackme_notes}` active TryHackMe notes",
        f"- `{notes_tree_notes}` topic-organized notes under `notes/`",
        f"- `{len(tryhackme_tracks)}` organized TryHackMe learning tracks",
        "- public governance for taxonomy, placeholders, publication, and maintenance",
        "",
        "Best fit for readers who want:",
        "",
        "- structured security notes instead of transcript dumps",
        "- reusable concepts rather than challenge spoilers",
        "- a public-safe reference set for web, networking, crypto, forensics, and blue-team basics",
        "",
        "",
    ]
    return "\n".join(lines)


def build_what_you_will_find(files: list[str]) -> str:
    track_counts = Counter(
        "/".join(path.split("/")[:2]) for path in files if path.startswith("TryHackMe/")
    )
    notes_tree_notes = sum(1 for path in files if path.startswith("notes/"))

    lines = [
        "## What You Will Find",
        "",
        "The live public corpus is currently centered on **TryHackMe** and supplemented by a smaller topic-organized `notes/` tree.",
        "",
        "| Track | Notes | Focus |",
        "| --- | --- | --- |",
    ]
    for track, focus in TRACK_FOCUS.items():
        lines.append(f"| [{track}]({track}) | `{track_counts.get(track, 0)}` | {focus} |")

    lines.extend(
        [
            "",
            "Additional organized notes outside the TryHackMe tree:",
            "",
            f"- `notes/` currently contains `{notes_tree_notes}` active public notes",
            "",
            "",
        ]
    )
    return "\n".join(lines)


def render_readme(files: list[str]) -> str:
    text = README_PATH.read_text(encoding="utf-8")
    updated = AT_A_GLANCE_RE.sub(build_at_a_glance(files), text)
    updated = WHAT_YOU_WILL_FIND_RE.sub(build_what_you_will_find(files), updated)
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the tracked-note snapshot sections in the repository README."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit with status 1 if README.md is not up to date.",
    )
    args = parser.parse_args()

    files = tracked_markdown_files()
    rendered = render_readme(files)

    if args.check:
        existing = README_PATH.read_text(encoding="utf-8")
        if existing != rendered:
            print("README.md is out of date.")
            return 1
        print("README.md is up to date.")
        return 0

    README_PATH.write_text(rendered, encoding="utf-8")
    print("Rendered README.md snapshot from tracked Markdown files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

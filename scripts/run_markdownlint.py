#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BLOCKING_CONFIG = ROOT / ".markdownlint-cli2.jsonc"


def is_markdown_path(value: str) -> bool:
    return value.lower().endswith(".md")


def is_active_note_path(value: str) -> bool:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path

    try:
        rel_path = path.resolve().relative_to(ROOT).as_posix()
    except (OSError, ValueError):
        return False

    return (
        rel_path.endswith(".md")
        and (rel_path.startswith("TryHackMe/") or rel_path.startswith("notes/"))
        and not rel_path.startswith("TryHackMe/_meta/")
    )


def resolve_markdownlint_launcher() -> list[str]:
    if os.name == "nt":
        node_executable = next(
            (
                candidate
                for name in ("node.exe", "node")
                if (candidate := shutil.which(name)) is not None
            ),
            None,
        )
        if node_executable is None:
            raise SystemExit("Missing node; install Node.js or add node to PATH.")

        npx_cli = Path(node_executable).resolve().parent / "node_modules" / "npm" / "bin" / "npx-cli.js"
        if npx_cli.exists():
            return [node_executable, str(npx_cli)]

    npx_executable = shutil.which("npx")
    if npx_executable is None:
        raise SystemExit("Missing npx; install Node.js or add npx to PATH.")

    return [npx_executable]


def main() -> int:
    launcher = resolve_markdownlint_launcher()

    args = sys.argv[1:]
    markdown_args = [arg for arg in args if is_markdown_path(arg)]

    if markdown_args:
        passthrough_args: list[str] = []
        filtered_files: list[str] = []
        for arg in args:
            if is_markdown_path(arg):
                if is_active_note_path(arg):
                    filtered_files.append(arg)
            else:
                passthrough_args.append(arg)

        if not filtered_files:
            print("No active-note Markdown files provided to markdownlint; skipping.")
            return 0

        if "--config" not in passthrough_args and "-c" not in passthrough_args:
            passthrough_args = ["--config", str(BLOCKING_CONFIG), *passthrough_args]

        cmd = [*launcher, "--yes", "markdownlint-cli2@0.18.1", *passthrough_args, *filtered_files]
    elif args:
        cmd = [*launcher, "--yes", "markdownlint-cli2@0.18.1", *args]
    else:
        print("No Markdown files provided; skipping blocking markdownlint.")
        return 0

    completed = subprocess.run(cmd, cwd=ROOT, shell=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())

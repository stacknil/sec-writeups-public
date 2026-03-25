#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dependency error path
    raise SystemExit(
        "Missing dependency 'PyYAML'. Install with: python -m pip install -r requirements-lint.txt"
    ) from exc

try:
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover - dependency error path
    raise SystemExit(
        "Missing dependency 'jsonschema'. Install with: python -m pip install -r requirements-lint.txt"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = ("TryHackMe", "notes")
SKIP_PARTS = {"_meta"}
SCHEMA_BUNDLE_PATH = ROOT / "schemas" / "frontmatter.schema.json"
TAXONOMY_PATH = ROOT / "schemas" / "taxonomy.json"
VALID_FIRST_H2 = {"Summary", "Executive Summary"}
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.S)
HEADING_RE = re.compile(r"^(#{1,6}) (.+)$")


@dataclass
class Issue:
    path: str
    message: str


def iter_markdown_files(targets: list[str]) -> list[Path]:
    if not targets:
        targets = list(DEFAULT_ROOTS)

    files: set[Path] = set()
    for target in targets:
        target_path = (ROOT / target).resolve()
        if not target_path.exists():
            continue
        if target_path.is_file() and target_path.suffix.lower() == ".md":
            if not any(part in SKIP_PARTS for part in target_path.parts):
                files.add(target_path)
            continue
        if target_path.is_dir():
            for path in target_path.rglob("*.md"):
                if any(part in SKIP_PARTS for part in path.parts):
                    continue
                files.add(path.resolve())
    return sorted(files)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_frontmatter(text: str) -> tuple[dict | None, str | None]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return None, "missing YAML front matter"

    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        first_line = str(exc).splitlines()[0]
        return None, f"invalid YAML front matter: {first_line}"

    if not isinstance(data, dict):
        return None, "front matter must parse to a mapping"

    return normalize_yaml_value(data), None


def normalize_yaml_value(value):
    if isinstance(value, dict):
        return {str(key): normalize_yaml_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_yaml_value(item) for item in value]
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    return value


def schema_name_for_path(rel_path: str) -> str | None:
    if rel_path.startswith("TryHackMe/"):
        return "tryhackme"
    if rel_path.startswith("notes/"):
        return "notes"
    return None


def expected_topic(rel_path: str) -> str | None:
    parts = rel_path.split("/")
    if len(parts) < 2:
        return None
    if parts[0] in {"TryHackMe", "notes"}:
        return parts[1]
    return None


def real_headings(text: str) -> list[tuple[int, str, int]]:
    headings: list[tuple[int, str, int]] = []
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            headings.append((len(match.group(1)), match.group(2).strip(), lineno))
    return headings


def format_json_path(parts) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{part}"
    return path


def validate_schema(rel_path: str, data: dict, schema_bundle: dict) -> list[Issue]:
    schema_name = schema_name_for_path(rel_path)
    if schema_name is None:
        return []

    active_schema = {
        "$schema": schema_bundle.get("$schema"),
        "$defs": schema_bundle["$defs"],
        "$ref": f"#/$defs/{schema_name}",
    }
    validator = Draft202012Validator(active_schema)
    issues: list[Issue] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
        pointer = format_json_path(error.absolute_path)
        issues.append(Issue(rel_path, f"{pointer}: {error.message}"))
    return issues


def validate_taxonomy(rel_path: str, data: dict, taxonomy: dict) -> list[Issue]:
    issues: list[Issue] = []
    for field in ("domain", "skills", "artifacts"):
        values = data.get(field)
        if not isinstance(values, list):
            continue

        allowed = set(taxonomy[field]["allowed"])
        aliases = taxonomy[field].get("aliases", {})
        seen: set[str] = set()
        for item in values:
            if not isinstance(item, str):
                continue
            if item in seen:
                issues.append(Issue(rel_path, f"{field} contains a duplicate value: '{item}'"))
                continue
            seen.add(item)
            if item in aliases:
                issues.append(
                    Issue(
                        rel_path,
                        f"{field} uses alias '{item}'; use canonical value '{aliases[item]}'",
                    )
                )
            elif item not in allowed:
                issues.append(Issue(rel_path, f"{field} uses unknown value '{item}'"))
    return issues


def validate_structure(rel_path: str, text: str, data: dict) -> list[Issue]:
    issues: list[Issue] = []

    if data.get("path") and data["path"] != rel_path:
        issues.append(
            Issue(
                rel_path,
                f"path field mismatch: expected '{rel_path}', found '{data['path']}'",
            )
        )

    topic = expected_topic(rel_path)
    if topic and data.get("topic") and data["topic"] != topic:
        issues.append(
            Issue(
                rel_path,
                f"topic field mismatch: expected '{topic}', found '{data['topic']}'",
            )
        )

    headings = real_headings(text)
    h1s = [heading for heading in headings if heading[0] == 1]
    if len(h1s) != 1:
        detail = ", ".join(f"{title} @L{lineno}" for _, title, lineno in h1s) or "none"
        issues.append(
            Issue(
                rel_path,
                f"expected exactly one real H1 outside code fences, found {len(h1s)} ({detail})",
            )
        )

    h2s = [heading for heading in headings if heading[0] == 2]
    if not h2s:
        issues.append(Issue(rel_path, "missing real H2 outside code fences"))
    else:
        first_h2 = h2s[0][1]
        if first_h2 not in VALID_FIRST_H2:
            issues.append(
                Issue(
                    rel_path,
                    f"first real H2 must be Summary or Executive Summary, found '{first_h2}'",
                )
            )

    return issues


def check_file(path: Path, schema_bundle: dict, taxonomy: dict) -> list[Issue]:
    rel_path = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8")

    data, parse_error = parse_frontmatter(text)
    if parse_error:
        return [Issue(rel_path, parse_error)]

    issues: list[Issue] = []
    issues.extend(validate_schema(rel_path, data, schema_bundle))
    issues.extend(validate_taxonomy(rel_path, data, taxonomy))
    issues.extend(validate_structure(rel_path, text, data))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Markdown note conventions for public write-ups."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional file or directory paths relative to the repo root. Defaults to TryHackMe and notes.",
    )
    args = parser.parse_args()

    files = iter_markdown_files(args.targets)
    if not files:
        print("No Markdown files found to check.")
        return 0

    schema_bundle = load_json(SCHEMA_BUNDLE_PATH)
    taxonomy = load_json(TAXONOMY_PATH)

    issues: list[Issue] = []
    for path in files:
        issues.extend(check_file(path, schema_bundle, taxonomy))

    if issues:
        for issue in issues:
            print(f"FAIL {issue.path}: {issue.message}")
        print(f"\nFound {len(issues)} issue(s) across {len({issue.path for issue in issues})} file(s).")
        return 1

    print(f"All checks passed for {len(files)} Markdown file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

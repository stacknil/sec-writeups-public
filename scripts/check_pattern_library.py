#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "schemas" / "pattern-library.json"
FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
HEADING_RE = re.compile(r"^## (.+)$", re.MULTILINE)
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


@dataclass(frozen=True)
class Card:
    path: Path
    maturity: str
    last_reviewed: date
    sections: dict[str, str]


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_config() -> dict[str, object]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def parse_card(
    path: Path,
    required_sections: list[str],
    maturity_values: set[str],
    errors: list[str],
) -> Card | None:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    match = FRONT_MATTER_RE.match(text)
    if match is None:
        errors.append(f"{relative(path)}: missing YAML front matter")
        return None

    metadata = yaml.safe_load(match.group(1)) or {}
    maturity = metadata.get("maturity")
    if maturity not in maturity_values:
        errors.append(
            f"{relative(path)}: maturity must be one of "
            f"{', '.join(sorted(maturity_values))}"
        )
        return None

    reviewed_value = metadata.get("last_reviewed")
    try:
        reviewed = date.fromisoformat(str(reviewed_value))
    except (TypeError, ValueError):
        errors.append(f"{relative(path)}: last_reviewed must use YYYY-MM-DD")
        return None

    body = text[match.end() :]
    headings = list(HEADING_RE.finditer(body))
    heading_names = [heading.group(1) for heading in headings]
    if heading_names != required_sections:
        errors.append(
            f"{relative(path)}: expected sections {required_sections}, "
            f"found {heading_names}"
        )
        return None

    sections: dict[str, str] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(body)
        content = body[heading.end() : end].strip()
        if not content:
            errors.append(f"{relative(path)}: empty section {heading.group(1)!r}")
        sections[heading.group(1)] = content

    return Card(path, maturity, reviewed, sections)


def links(text: str) -> list[str]:
    return [match.group(1).strip() for match in LINK_RE.finditer(text)]


def resolve_local_link(source: Path, target: str) -> Path | None:
    parsed = urlparse(target)
    if parsed.scheme or target.startswith(("#", "mailto:")):
        return None

    link_path = unquote(target.split("#", 1)[0])
    if not link_path:
        return None

    resolved = (source.parent / link_path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return None
    return resolved


def is_core_project_link(target: str, prefixes: list[str]) -> bool:
    return any(target == prefix or target.startswith(f"{prefix}/") for prefix in prefixes)


def validate() -> tuple[list[str], int, int, int]:
    config = load_config()
    required_sections = list(config["required_sections"])
    maturity_values = set(config["maturity_values"])
    project_prefixes = [
        project["url_prefix"] for project in config["core_projects"]
    ]
    errors: list[str] = []

    card_paths = sorted(
        path
        for path in (ROOT / "patterns").rglob("*.md")
        if path.name != "README.md"
    )
    cards = [
        card
        for path in card_paths
        if (
            card := parse_card(
                path,
                required_sections,
                maturity_values,
                errors,
            )
        )
        is not None
    ]
    cards_by_path = {relative(card.path): card for card in cards}
    stable_source_notes: set[Path] = set()

    for card in cards:
        implementation_links = links(card.sections["Related implementation"])
        if not implementation_links:
            errors.append(f"{relative(card.path)}: missing related implementation link")

        supporting_links = links(card.sections["Supporting notes"])
        local_supporting_notes: list[Path] = []
        for target in supporting_links:
            resolved = resolve_local_link(card.path, target)
            if resolved is None:
                continue
            if not resolved.is_file():
                errors.append(
                    f"{relative(card.path)}: supporting note does not exist: {target}"
                )
                continue
            if resolved.suffix.lower() != ".md":
                errors.append(
                    f"{relative(card.path)}: supporting note is not Markdown: {target}"
                )
                continue
            local_supporting_notes.append(resolved)

        if not local_supporting_notes:
            errors.append(f"{relative(card.path)}: missing local supporting note")

        if card.maturity == "stable":
            source_notes = [
                path
                for path in local_supporting_notes
                if relative(path).startswith(("notes/", "TryHackMe/"))
            ]
            if not source_notes:
                errors.append(
                    f"{relative(card.path)}: stable card must link to a source note"
                )
            if not any(
                is_core_project_link(target, project_prefixes)
                for target in implementation_links
            ):
                errors.append(
                    f"{relative(card.path)}: stable card must link to a core project"
                )
            stable_source_notes.update(source_notes)

    featured_paths = list(config["featured_patterns"])
    if not 6 <= len(featured_paths) <= 8:
        errors.append("featured_patterns must contain between 6 and 8 cards")
    if len(featured_paths) != len(set(featured_paths)):
        errors.append("featured_patterns contains duplicate paths")
    for path in featured_paths:
        card = cards_by_path.get(path)
        if card is None:
            errors.append(f"featured pattern does not exist: {path}")
        elif card.maturity != "stable":
            errors.append(f"featured pattern is not stable: {path}")

    card_path_set = set(card_paths)
    for case_path_value in config["flagship_case_studies"]:
        case_path = ROOT / case_path_value
        if not case_path.is_file():
            errors.append(f"flagship case study does not exist: {case_path_value}")
            continue
        case_targets = {
            resolved
            for target in links(case_path.read_text(encoding="utf-8"))
            if (resolved := resolve_local_link(case_path, target)) is not None
        }
        if not case_targets.intersection(card_path_set):
            errors.append(
                f"{case_path_value}: flagship case study must link to a pattern"
            )

    stable_count = sum(card.maturity == "stable" for card in cards)
    supporting_count = len(stable_source_notes)
    metric = (
        f"Current extraction metric: **{stable_count} stable reusable security "
        f"patterns extracted from {supporting_count} distinct supporting notes**."
    )
    for surface_value in config["metric_surfaces"]:
        surface = ROOT / surface_value
        if not surface.is_file():
            errors.append(f"metric surface does not exist: {surface_value}")
        elif re.sub(r"\s+", " ", metric) not in re.sub(
            r"\s+", " ", surface.read_text(encoding="utf-8")
        ):
            errors.append(f"{surface_value}: expected metric line: {metric}")

    return errors, len(cards), stable_count, supporting_count


def main() -> int:
    errors, card_count, stable_count, supporting_count = validate()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "Pattern library is valid: "
        f"{stable_count} stable patterns from {supporting_count} supporting notes "
        f"across {card_count} total cards."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

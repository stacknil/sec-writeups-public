from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_markdown  # noqa: E402
import check_pattern_library  # noqa: E402
import check_placeholders  # noqa: E402


REQUIRED_PATTERN_SECTIONS = [
    "Signal",
    "Why it matters",
    "False-positive contexts",
    "Evidence limits",
    "Defensive next step",
    "Related implementation",
    "Supporting notes",
]


def pattern_card_text(
    *,
    title: str,
    maturity: str = "stable",
    last_reviewed: str = "2000-01-01",
    implementation_url: str = "https://github.com/stacknil/core-project",
) -> str:
    sections: list[str] = []
    for section in REQUIRED_PATTERN_SECTIONS:
        if section == "Related implementation":
            content = f"[Core project]({implementation_url})"
        elif section == "Supporting notes":
            content = "[Source note](../notes/source.md)"
        else:
            content = "Decision-bearing evidence."
        sections.append(f"## {section}\n\n{content}")

    return (
        "---\n"
        f"maturity: {maturity}\n"
        f"last_reviewed: {last_reviewed}\n"
        "---\n"
        f"# {title}\n\n"
        + "\n\n".join(sections)
        + "\n"
    )


class PatternLibraryContractTests(unittest.TestCase):
    def test_parse_card_future_review_date_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            card_path = temp_root / "patterns" / "future-review.md"
            card_path.parent.mkdir(parents=True)
            card_path.write_text(
                pattern_card_text(
                    title="Future review",
                    last_reviewed="2999-01-01",
                ),
                encoding="utf-8",
            )
            errors: list[str] = []

            with patch.object(check_pattern_library, "ROOT", temp_root):
                card = check_pattern_library.parse_card(
                    card_path,
                    REQUIRED_PATTERN_SECTIONS,
                    {"draft", "reviewed", "stable"},
                    errors,
                )

            self.assertIsNone(card)
            self.assertEqual(
                errors,
                [
                    "patterns/future-review.md: "
                    "last_reviewed must not be in the future"
                ],
            )

    def test_validate_stable_card_without_core_project_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            self._write_pattern_library(
                temp_root,
                implementation_overrides={0: "https://example.com/other-project"},
            )

            errors, card_count, stable_count, supporting_count = self._validate(
                temp_root
            )

            self.assertEqual((card_count, stable_count, supporting_count), (6, 6, 1))
            self.assertEqual(
                errors,
                [
                    "patterns/card-0.md: "
                    "stable card must link to a core project"
                ],
            )

    def test_validate_featured_reviewed_card_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            self._write_pattern_library(
                temp_root,
                maturity_overrides={0: "reviewed"},
            )

            errors, card_count, stable_count, supporting_count = self._validate(
                temp_root
            )

            self.assertEqual((card_count, stable_count, supporting_count), (6, 5, 1))
            self.assertEqual(
                errors,
                ["featured pattern is not stable: patterns/card-0.md"],
            )

    def _write_pattern_library(
        self,
        root: Path,
        *,
        implementation_overrides: dict[int, str] | None = None,
        maturity_overrides: dict[int, str] | None = None,
    ) -> None:
        implementation_overrides = implementation_overrides or {}
        maturity_overrides = maturity_overrides or {}
        patterns = root / "patterns"
        schemas = root / "schemas"
        notes = root / "notes"
        patterns.mkdir(parents=True)
        schemas.mkdir(parents=True)
        notes.mkdir(parents=True)
        (notes / "source.md").write_text("# Source\n", encoding="utf-8")

        featured: list[str] = []
        for index in range(6):
            relative_path = f"patterns/card-{index}.md"
            featured.append(relative_path)
            (root / relative_path).write_text(
                pattern_card_text(
                    title=f"Card {index}",
                    maturity=maturity_overrides.get(index, "stable"),
                    implementation_url=implementation_overrides.get(
                        index,
                        "https://github.com/stacknil/core-project",
                    ),
                ),
                encoding="utf-8",
            )

        config = {
            "version": 1,
            "maturity_values": ["draft", "reviewed", "stable"],
            "required_sections": REQUIRED_PATTERN_SECTIONS,
            "core_projects": [
                {
                    "name": "Core project",
                    "url_prefix": "https://github.com/stacknil/core-project",
                }
            ],
            "featured_patterns": featured,
            "flagship_case_studies": [],
            "metric_surfaces": [],
        }
        (schemas / "pattern-library.json").write_text(
            json.dumps(config),
            encoding="utf-8",
        )

    def _validate(
        self,
        root: Path,
    ) -> tuple[list[str], int, int, int]:
        with (
            patch.object(check_pattern_library, "ROOT", root),
            patch.object(
                check_pattern_library,
                "CONFIG_PATH",
                root / "schemas" / "pattern-library.json",
            ),
        ):
            return check_pattern_library.validate()


class FrontmatterContractTests(unittest.TestCase):
    def test_validate_structure_path_mismatch_is_reported(self) -> None:
        issues = check_markdown.validate_structure(
            "notes/10-web/example.md",
            "# Example\n\n## Summary\n\nSafe summary.\n",
            {
                "path": "notes/10-web/wrong.md",
                "topic": "10-web",
            },
        )

        self.assertEqual(
            [(issue.path, issue.message) for issue in issues],
            [
                (
                    "notes/10-web/example.md",
                    "path field mismatch: expected 'notes/10-web/example.md', "
                    "found 'notes/10-web/wrong.md'",
                )
            ],
        )


class PlaceholderContractTests(unittest.TestCase):
    def test_noncanonical_placeholder_does_not_flag_literal_identifier(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            note = temp_root / "notes" / "10-web" / "example.md"
            note.parent.mkdir(parents=True)
            note.write_text(
                "Use NONCANONICAL_TARGET, but preserve LD_PRELOAD.\n",
                encoding="utf-8",
            )
            literal_policy = check_placeholders.LiteralPolicy(
                exact_tokens=frozenset(),
                angle_tokens=frozenset(),
            )

            with patch.object(check_placeholders, "ROOT", temp_root):
                issues = check_placeholders.collect_issues(
                    note,
                    canonical={"TARGET_IP"},
                    replacements={},
                    literal_policy=literal_policy,
                )

            self.assertEqual(
                [(issue.token, issue.category) for issue in issues],
                [("NONCANONICAL_TARGET", "noncanonical-placeholder")],
            )


if __name__ == "__main__":
    unittest.main()

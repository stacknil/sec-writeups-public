#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = ("TryHackMe", "notes")
SKIP_PARTS = {"_meta"}
POLICY_PATH = ROOT / "docs" / "placeholder-policy.md"

CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
ANGLE_PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*>")
SEMANTIC_PLACEHOLDER_RE = re.compile(r"\b(?:[A-Z][A-Z0-9]*_[A-Z0-9_]*|LHOST|LPORT|RHOSTS|RPORT)\b")
GENERIC_PLACEHOLDER_SPAN_RE = re.compile(r"^(?:DOMAIN|HOST|USER|PASSWORD|HASHFILE|NAME)$")
LEGACY_USER_HOST_RE = re.compile(r"\b(?:USER|user)@(?:HOST|host)\b")
PLACEHOLDER_CONTEXT_RE = re.compile(r"\b(?:placeholder|placeholders|replace|generic|canonical)\b", re.I)
SECTION_RE = re.compile(r"^## (?P<title>.+)$", re.M)
CODE_TOKEN_RE = re.compile(r"`([^`\n]+)`")

LITERAL_PREFIXES = ("AWS_", "HKEY_")
LITERAL_SUFFIXES = (".DAT",)
LITERAL_EXACT = {
    "LD_PRELOAD",
    "HKCU",
    "HKLM",
    "SYSTEM",
    "SOFTWARE",
    "APPLICATIONNAME",
    "SHOWINTASKBAR",
    "WINDOWSTATE",
    "XMLHTTP",
}


@dataclass(frozen=True)
class Issue:
    path: str
    line: int
    token: str
    category: str
    message: str


@dataclass(frozen=True)
class LiteralPolicy:
    exact_tokens: frozenset[str]
    angle_tokens: frozenset[str]


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


def is_active_note_path(path: Path) -> bool:
    try:
        rel_path = path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return False

    return (
        rel_path.endswith(".md")
        and (rel_path.startswith("TryHackMe/") or rel_path.startswith("notes/"))
        and not rel_path.startswith("TryHackMe/_meta/")
    )


def extract_section(text: str, title: str) -> str:
    matches = list(SECTION_RE.finditer(text))
    for index, match in enumerate(matches):
        if match.group("title") != title:
            continue
        start = match.end()
        end = len(text)
        for later in matches[index + 1 :]:
            end = later.start()
            break
        return text[start:end]
    raise SystemExit(f"Missing section '## {title}' in {POLICY_PATH.as_posix()}")


def load_policy() -> tuple[set[str], dict[str, str], LiteralPolicy]:
    text = POLICY_PATH.read_text(encoding="utf-8")

    canonical_section = extract_section(text, "Canonical Placeholder Set")
    canonical = {token for token in CODE_TOKEN_RE.findall(canonical_section) if token}

    preferred_section = extract_section(text, "Preferred Migrations")
    replacements: dict[str, str] = {}
    for line in preferred_section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("| ---") or "Old style" in stripped:
            continue
        tokens = CODE_TOKEN_RE.findall(stripped)
        if len(tokens) >= 2:
            replacements[tokens[0]] = tokens[1]

    literal_section = extract_section(text, "Literal Identifiers That Should Stay Literal")
    literal_examples = {token for token in CODE_TOKEN_RE.findall(literal_section) if token}
    angle_tokens = frozenset(
        token for token in literal_examples if ANGLE_PLACEHOLDER_RE.fullmatch(token)
    )
    literal_policy = LiteralPolicy(
        exact_tokens=frozenset(literal_examples),
        angle_tokens=angle_tokens,
    )

    return canonical, replacements, literal_policy


def is_exempt_literal(token: str, literal_policy: LiteralPolicy) -> bool:
    if token in literal_policy.exact_tokens or token in LITERAL_EXACT:
        return True
    if any(token.startswith(prefix) for prefix in LITERAL_PREFIXES):
        return True
    if any(token.endswith(suffix) for suffix in LITERAL_SUFFIXES):
        return True
    return False


def mask_exempt_angle_literals(line: str, literal_policy: LiteralPolicy) -> str:
    masked = line
    for token in literal_policy.angle_tokens:
        if token in masked:
            masked = masked.replace(token, " " * len(token))
    return masked


def issue_for_token(
    rel_path: str,
    line: int,
    token: str,
    canonical: set[str],
    replacements: dict[str, str],
    literal_policy: LiteralPolicy,
    *,
    placeholder_context: bool = False,
) -> Issue | None:
    if token in canonical or is_exempt_literal(token, literal_policy):
        return None

    if token in replacements:
        if GENERIC_PLACEHOLDER_SPAN_RE.fullmatch(token) and not placeholder_context:
            return None
        replacement = replacements[token]
        return Issue(
            rel_path,
            line,
            token,
            "deprecated-placeholder",
            f"placeholder '{token}' is deprecated; use '{replacement}'",
        )

    if ANGLE_PLACEHOLDER_RE.fullmatch(token):
        return Issue(
            rel_path,
            line,
            token,
            "deprecated-angle-bracket",
            (
                f"angle-bracket placeholder '{token}' is deprecated; "
                "use a canonical uppercase placeholder or reserved example literal"
            ),
        )

    if GENERIC_PLACEHOLDER_SPAN_RE.fullmatch(token):
        return Issue(
            rel_path,
            line,
            token,
            "deprecated-generic",
            (
                f"generic placeholder '{token}' is deprecated; "
                "replace it with a semantic canonical placeholder"
            ),
        )

    if SEMANTIC_PLACEHOLDER_RE.fullmatch(token):
        return Issue(
            rel_path,
            line,
            token,
            "noncanonical-placeholder",
            (
                f"placeholder-like token '{token}' is not in the canonical placeholder set; "
                "replace it with a canonical placeholder or extend docs/placeholder-policy.md first"
            ),
        )

    return None


def collect_issues(
    path: Path,
    canonical: set[str],
    replacements: dict[str, str],
    literal_policy: LiteralPolicy,
) -> list[Issue]:
    rel_path = path.relative_to(ROOT).as_posix()
    issues: list[Issue] = []
    seen: set[tuple[int, str, str]] = set()

    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        placeholder_context = bool(PLACEHOLDER_CONTEXT_RE.search(line))
        for token in CODE_SPAN_RE.findall(line):
            issue = issue_for_token(
                rel_path,
                lineno,
                token,
                canonical,
                replacements,
                literal_policy,
                placeholder_context=placeholder_context,
            )
            if issue and (issue.line, issue.token, issue.category) not in seen:
                issues.append(issue)
                seen.add((issue.line, issue.token, issue.category))

        line_without_code = mask_exempt_angle_literals(CODE_SPAN_RE.sub(" ", line), literal_policy)
        angle_spans = [match.span() for match in ANGLE_PLACEHOLDER_RE.finditer(line_without_code)]

        for start, end in angle_spans:
            token = line_without_code[start:end]
            issue = issue_for_token(rel_path, lineno, token, canonical, replacements, literal_policy)
            if issue and (issue.line, issue.token, issue.category) not in seen:
                issues.append(issue)
                seen.add((issue.line, issue.token, issue.category))

        for match in LEGACY_USER_HOST_RE.finditer(line_without_code):
            token = match.group(0)
            issue = Issue(
                rel_path,
                lineno,
                token,
                "deprecated-generic-composite",
                (
                    f"generic host placeholder '{token}' is deprecated; "
                    "use USER_A@TARGET_HOST or user@example.com as appropriate"
                ),
            )
            if (issue.line, issue.token, issue.category) not in seen:
                issues.append(issue)
                seen.add((issue.line, issue.token, issue.category))

        for match in SEMANTIC_PLACEHOLDER_RE.finditer(line_without_code):
            if any(start <= match.start() and match.end() <= end for start, end in angle_spans):
                continue
            token = match.group(0)
            issue = issue_for_token(rel_path, lineno, token, canonical, replacements, literal_policy)
            if issue and (issue.line, issue.token, issue.category) not in seen:
                issues.append(issue)
                seen.add((issue.line, issue.token, issue.category))

    return issues


def build_report(files: list[Path], issues: list[Issue]) -> str:
    lines: list[str] = []
    if not files:
        return "No Markdown files found to check.\n"

    if not issues:
        return f"All placeholder checks passed for {len(files)} Markdown file(s).\n"

    counts_by_category: dict[str, int] = {}
    for issue in issues:
        counts_by_category[issue.category] = counts_by_category.get(issue.category, 0) + 1

    for issue in issues:
        lines.append(f"FAIL {issue.path}:{issue.line}: {issue.message}")

    lines.append("")
    lines.append(
        f"Found {len(issues)} issue(s) across {len({issue.path for issue in issues})} file(s)."
    )
    lines.append("Issue categories:")
    for category, count in sorted(counts_by_category.items()):
        lines.append(f"- {category}: {count}")
    lines.append("")
    lines.append(
        "Policy reference: docs/placeholder-policy.md"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check active-note Markdown files for canonical placeholder usage."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional file or directory paths relative to the repo root. Defaults to TryHackMe and notes.",
    )
    parser.add_argument(
        "--report",
        help="Optional path to write the full report to.",
    )
    args = parser.parse_args()

    files = [path for path in iter_markdown_files(args.targets) if is_active_note_path(path)]
    canonical, replacements, literal_policy = load_policy()

    issues: list[Issue] = []
    for path in files:
        issues.extend(collect_issues(path, canonical, replacements, literal_policy))

    report = build_report(files, issues)
    sys.stdout.write(report)

    if args.report:
        report_path = (ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")

    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())

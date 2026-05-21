# Reviewer brief

## Problem

Security notes are often hard to publish safely: they either leak too much, collapse into transcript dumps, or become too inconsistent to reuse as a real knowledge base.

## What it does

`sec-writeups-public` is a public, sanitized security note repository with:

- a large TryHackMe-centered note corpus
- topic-organized notes outside the training-platform tree
- taxonomy, placeholder, and publication governance
- local checks that keep the public corpus maintainable

## Reviewer Evidence

- Reproducible command: `python scripts/render_readme_snapshot.py --check`
- Deterministic outputs: rendered README snapshots, generated tag docs, placeholder audit output, taxonomy docs, and markdownlint debt reports.
- Tests / CI: local publication checks, placeholder checks, markdown checks, pre-commit hooks, and GitHub Actions maintenance workflows.
- Release evidence: public corpus snapshot, governance docs, sanitization checklist, publication workflow, and maintenance checkpoints.
- Non-goals: raw exploit logs, private evidence dumps, live target identifiers, weaponized exploit chains, or unsanitized challenge transcripts.

## Quick run

```bash
python scripts/render_tags_doc.py --check
python scripts/render_readme_snapshot.py --check
python scripts/check_placeholders.py notes/80-blue-team/soc-fundamentals.md
python scripts/check_markdown.py
python -m pre_commit run --files notes/80-blue-team/soc-fundamentals.md
```

## Sample output

The current public snapshot in the README reports:

- `111` active public notes
- `100` active TryHackMe notes
- `11` topic-organized notes under `notes/`

A representative public-safe note is `notes/80-blue-team/soc-fundamentals.md`, which uses summary-first structure, reusable concepts, and placeholders instead of live identifiers.

## What this proves

- security writing can be structured like an engineered artifact
- publication safety can be enforced with explicit governance
- public notes can stay reusable and maintainable instead of one-off dumps
- reviewer-facing documentation discipline extends beyond code repos

## Safety / boundaries

- authorized labs and training platforms only
- sanitized by default
- no raw private evidence dumps, live identifiers, or weaponized exploit chains
- this is a public knowledge base, not a private red-team notebook

## Limitations

- note quality and depth vary with topic maturity
- this repo is about reusable public artifacts, not raw working logs
- publication safety rules intentionally limit technical detail in some writeups

## Next milestone

Keep deepening blue-team and detection-oriented notes while improving reviewer-facing indexes for the strongest public writing paths.

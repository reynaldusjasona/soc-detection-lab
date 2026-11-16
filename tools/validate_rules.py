#!/usr/bin/env python3
"""Validate the Sigma rules in detections/.

Two layers:

1. Structural checks (always run, only needs PyYAML): required Sigma fields present,
   unique rule IDs, well-formed ATT&CK tags, and every name in `condition` refers to a
   defined selection block.
2. pySigma conversion (runs when pysigma + the Splunk backend are installed, i.e. in CI):
   parse each rule and convert it to SPL. A rule that does not compile fails the build.

Exit non-zero if any rule fails any check.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "detections"

REQUIRED = ["title", "id", "logsource", "detection"]
TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?|[a-z_]+)$")
# condition keywords that are not selection names
COND_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}


def structural_checks(rules: list[tuple[Path, dict]]) -> list[str]:
    errors: list[str] = []
    seen_ids: dict[str, str] = {}

    for path, doc in rules:
        name = path.name
        for field in REQUIRED:
            if field not in doc:
                errors.append(f"{name}: missing required field '{field}'")

        rid = doc.get("id")
        if rid:
            if rid in seen_ids:
                errors.append(f"{name}: duplicate id {rid} (also in {seen_ids[rid]})")
            else:
                seen_ids[rid] = name

        for tag in doc.get("tags", []):
            if not TAG_RE.match(str(tag).lower()):
                errors.append(f"{name}: malformed tag '{tag}'")

        detection = doc.get("detection", {})
        if isinstance(detection, dict):
            condition = detection.get("condition")
            selections = {k for k in detection if k != "condition"}
            if not condition:
                errors.append(f"{name}: detection has no condition")
            elif isinstance(condition, str):
                for token in re.split(r"[\s()]+", condition):
                    if not token or token in COND_KEYWORDS:
                        continue
                    base = token.rstrip("*").lstrip("*")
                    if base and not any(s == base or s.startswith(base.rstrip("*"))
                                        for s in selections):
                        if "*" not in token:
                            errors.append(
                                f"{name}: condition refers to '{token}' "
                                f"which is not a defined selection")
    return errors


def pysigma_checks(paths: list[Path]) -> list[str]:
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.splunk import SplunkBackend
    except ImportError:
        print("pysigma not installed, skipping SPL conversion "
              "(this runs in CI). Structural checks only.")
        return []

    errors: list[str] = []
    backend = SplunkBackend()
    for path in paths:
        try:
            collection = SigmaCollection.load_ruleset([path])
            queries = backend.convert(collection)
            if not queries or not queries[0].strip():
                errors.append(f"{path.name}: converted to an empty query")
            else:
                print(f"OK  {path.name} -> {queries[0]}")
        except Exception as exc:  # noqa: BLE001 - report any conversion failure
            errors.append(f"{path.name}: pySigma conversion failed: {exc}")
    return errors


def main() -> int:
    paths = sorted(RULES_DIR.glob("*.yml"))
    if not paths:
        print("No rules found in detections/.")
        return 1

    rules = []
    for path in paths:
        with path.open() as fh:
            doc = yaml.safe_load(fh)
        rules.append((path, doc))

    errors = structural_checks(rules)
    errors += pysigma_checks(paths)

    if errors:
        print(f"\nFAILED: {len(errors)} problem(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"\nAll {len(paths)} rule(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Language-neutral DTO schema validation (plan 50, External proof).

Replays the committed canonical-example corpus against the committed JSON
Schema 2020-12 bundle with a non-Rust validator (python-jsonschema):
every positive example must validate against its `$defs` entry; every
negative example marked `schemaExpressible` must be rejected. Reasons only
the Rust contract can see (decoded lengths, protocol pinning, identifier
grammar applied inside `validate()`) are skipped here and covered by
`crates/runtime/tests/dto_schema.rs`.

Also validates that every `identifiers` pattern compiles and anchors.
"""

import json
import re
import sys
from pathlib import Path

import jsonschema

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "crates" / "runtime" / "schema"
PRODUCT_DIR = Path(__file__).resolve().parent.parent / "schema"


def main() -> int:
    failures = []
    counts = []
    for name, schema_file, examples_file in [
        ("runtime", SCHEMA_DIR / "dto.schema.json", SCHEMA_DIR / "dto.examples.json"),
        (
            "product",
            PRODUCT_DIR / "product-policy.schema.json",
            PRODUCT_DIR / "product-policy.examples.json",
        ),
    ]:
        bundle = json.loads(schema_file.read_text(encoding="utf-8"))
        examples = json.loads(examples_file.read_text(encoding="utf-8"))
        check_bundle(name, bundle, examples, failures, counts)

    if failures:
        for f in failures:
            print(f"error: {f}", file=sys.stderr)
        return 1
    print("dto schemas OK — " + "; ".join(counts))
    return 0


def check_bundle(name, bundle, examples, failures, counts):

    def validator_for(def_name: str) -> jsonschema.Draft202012Validator:
        schema = dict(bundle["$defs"][def_name])
        return jsonschema.Draft202012Validator(schema)

    for ex in examples["positive"]:
        v = validator_for(ex["def"])
        errors = list(v.iter_errors(ex["value"]))
        if errors:
            failures.append(f"positive {ex['def']} failed: {errors[0].message}")

    for ex in examples["negative"]:
        if not ex.get("schemaExpressible", False):
            continue
        v = validator_for(ex["def"])
        errors = list(v.iter_errors(ex["value"]))
        if not errors:
            failures.append(
                f"negative {ex['def']} ({ex['reason']}) was NOT rejected by the schema"
            )

    idents = bundle.get("identifiers", {})
    for iname, ident in idents.items():
        pattern = ident.get("pattern", "")
        if not (pattern.startswith("^") and pattern.endswith("$")):
            failures.append(f"identifier {iname} pattern is not anchored: {pattern!r}")
            continue
        try:
            re.compile(pattern)
        except re.error as e:
            failures.append(f"identifier {iname} pattern does not compile: {e}")

    counts.append(
        f"{name}: {len(examples['positive'])} positives, "
        f"{len(examples['negative'])} negatives, "
        f"{len(idents)} identifier grammars"
    )


if __name__ == "__main__":
    sys.exit(main())

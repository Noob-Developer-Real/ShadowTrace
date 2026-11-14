"""Verify a ShadowTrace evidence bundle with the standard library."""

import argparse
import hmac
import json
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from uuid import UUID


def normalized(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"Unsupported evidence value: {type(value).__name__}")


def canonical(document):
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=normalized,
    ).encode("utf-8")


def seal(document):
    payload = canonical(document)
    return {"sha256": sha256(payload).hexdigest(), "evidence": json.loads(payload)}


def valid(bundle):
    if not isinstance(bundle, dict) or set(bundle) != {"sha256", "evidence"}:
        return False
    expected = bundle["sha256"]
    evidence = bundle["evidence"]
    return (
        isinstance(expected, str)
        and expected.isascii()
        and len(expected) == 64
        and isinstance(evidence, dict)
        and evidence.get("format") == "shadowtrace.evidence.v1"
        and hmac.compare_digest(expected, sha256(canonical(evidence)).hexdigest())
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as file:
            contents = file.read(2_000_001)
        verified = len(contents) <= 2_000_000 and valid(json.loads(contents))
    except (OSError, ValueError, TypeError, RecursionError):
        verified = False
    print("Evidence checksum matches." if verified else "Evidence checksum failed.")
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

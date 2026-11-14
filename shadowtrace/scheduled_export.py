"""Run one guarded CSV export occurrence from an existing source scheduler."""

import argparse
import asyncio
import csv
import os
import tempfile
from io import StringIO
from pathlib import Path

import httpx

from .enforce import ApprovalRequired, ReleaseDenied, release_protected
from .schema import Observed
from .transfer_intent import occurrence_id


def atomic_delivery(path, payload):
    """Write once without ever replacing another occurrence's output."""
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".st-export-", delete=False) as staged:
        staged_path = Path(staged.name)
        try:
            staged.write(payload)
            staged.flush()
            os.fsync(staged.fileno())
            os.link(staged_path, path)
        finally:
            staged_path.unlink(missing_ok=True)


def read_csv(path):
    with path.open("rb") as input_file:
        payload = input_file.read(10 * 1024 * 1024 + 1)
    if len(payload) > 10 * 1024 * 1024:
        raise ValueError("Stage a CSV of up to 10 MiB.")
    data = csv.reader(StringIO(payload.decode("utf-8-sig"), newline=""), strict=True)
    header = next(data, [])
    if not header or any(not field for field in header):
        raise ValueError("Use a CSV with a valid header.")
    count = 0
    for row in data:
        if len(row) != len(header):
            raise ValueError("Every CSV row must match the header.")
        count += 1
    if not 1 <= count <= 1_000_000:
        raise ValueError("Use a CSV containing 1 to 1,000,000 data rows.")
    return payload, count


async def run(args, credential):
    occurrence = Observed.model_validate({"occurred_at": args.occurrence}).occurred_at
    request_id = occurrence_id(args.schedule, occurrence)
    payload, count = read_csv(args.input)
    output = args.output_dir / f"{request_id}.csv"
    if output.exists():
        raise ReleaseDenied("operation_already_delivered")
    async with httpx.AsyncClient(base_url=args.origin, trust_env=False) as client:
        await release_protected(
            client,
            credential=credential,
            request_id=request_id,
            actor_id=args.actor,
            action="export",
            resource_type=args.resource,
            record_count=count,
            destination=args.destination,
            content=payload,
            release=lambda _, content: atomic_delivery(output, content),
            intent={
                "channel": "scheduled",
                "schedule_id": args.schedule,
                "scheduled": {"occurred_at": occurrence.isoformat()},
                "sensitive": args.sensitive,
            },
        )
    print(f"Delivered {count} records for occurrence {request_id}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--schedule", required=True)
    parser.add_argument("--occurrence", required=True, help="Nominal occurrence in RFC 3339")
    parser.add_argument("--actor", required=True, help="Stable source or service actor alias")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--resource", required=True, choices=["customer", "order", "invoice"])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--sensitive", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(run(args, os.environ["ST_PROTECTION_KEY"]))
    except ApprovalRequired as result:
        parser.exit(
            75,
            f"Awaiting approval for operation {result.request_id}. Retry the same staged occurrence.\n",
        )
    except ReleaseDenied as error:
        parser.exit(1, f"Scheduled export withheld ({error.reason}).\n")
    except (OSError, ValueError, csv.Error, KeyError):
        parser.exit(
            1,
            "Scheduled export could not finish. Check staging, configuration and delivery state.\n",
        )


if __name__ == "__main__":
    main()

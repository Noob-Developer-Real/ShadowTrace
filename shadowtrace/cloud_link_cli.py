"""Authorize a recipient-bound link for a CSV already staged in private versioned S3."""

import argparse
import asyncio
import os
import re
from pathlib import Path
from uuid import UUID

import httpx

from .enforce import ApprovalRequired, ReleaseDenied, release_protected
from .scheduled_export import read_csv
from .schema import SLUG


async def run(args, key):
    payload, count = read_csv(args.input)
    intent = {
        "channel": "cloud_link",
        "requester_id": str(args.requester),
        "recipient_id": str(args.recipient),
        "object_version": args.object_version,
        "link_minutes": args.minutes,
        "sensitive": args.sensitive,
    }
    async with httpx.AsyncClient(base_url=args.origin, trust_env=False) as client:
        path = f"/w/{args.workspace}/protection/links/{args.operation}"
        return await release_protected(
            client,
            credential=key,
            request_id=args.operation,
            actor_id=args.actor,
            action="share",
            resource_type=args.resource,
            record_count=count,
            destination=args.destination,
            content=payload,
            release=lambda *_: str(client.base_url.join(path)),
            intent=intent,
            expected_link_path=path,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--operation", required=True, type=UUID)
    parser.add_argument("--requester", required=True, type=UUID)
    parser.add_argument("--recipient", required=True, type=UUID)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--resource", required=True, choices=["customer", "order", "invoice"])
    parser.add_argument("--object-version", required=True)
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sensitive", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(SLUG, args.workspace):
        parser.error("Enter a valid workspace slug.")
    try:
        print(asyncio.run(run(args, os.environ["ST_PROTECTION_KEY"])))
    except ApprovalRequired as result:
        parser.exit(
            75,
            f"Awaiting approval for operation {result.request_id}. Retry with identical metadata.\n",
        )
    except ReleaseDenied as error:
        parser.exit(
            1,
            f"Cloud link withheld ({error.reason}). Check Managed transfers for the saved state.\n",
        )
    except (OSError, ValueError, KeyError):
        parser.exit(
            1, "Cloud link could not finish. Check the staged CSV and source configuration.\n"
        )


if __name__ == "__main__":
    main()

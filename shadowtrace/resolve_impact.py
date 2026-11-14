"""Run this connector inside the source environment with a private ID catalog."""

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from .fingerprints import record_fingerprint


def resolve_records(secret, workspace, token_set, fingerprints, record_ids):
    sought = set(fingerprints)
    matched = set()
    for raw_id in record_ids:
        if not raw_id:
            continue
        token = record_fingerprint(secret, workspace, token_set, "customer", raw_id)
        if token in sought:
            matched.add(raw_id)
    return sorted(matched)


def private_result(path, report):
    # Exclusive creation and restrictive permissions keep this local result private.
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as out:
        json.dump(report, out, ensure_ascii=False)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--job", type=UUID, required=True)
    parser.add_argument(
        "--catalog", type=Path, required=True, help="UTF-8 file, one canonical ID per line"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="New file in a private source directory"
    )
    args = parser.parse_args()
    origin = urlsplit(args.origin)
    if (
        origin.scheme != "https"
        and not (origin.scheme == "http" and origin.hostname in {"127.0.0.1", "localhost"})
    ) or (
        not origin.hostname
        or origin.username
        or origin.password
        or origin.query
        or origin.fragment
        or origin.path not in {"", "/"}
    ):
        parser.error("Use the service HTTPS origin or a loopback HTTP demo.")
    try:
        key = os.environ["ST_IMPACT_KEY"]
        secret = bytes.fromhex(os.environ["ST_RECORD_SECRET_HEX"])
        if len(secret) < 32 or not key:
            raise ValueError()
    except (KeyError, ValueError):
        parser.error(
            "Configure ST_IMPACT_KEY and a record secret of at least 32 bytes in ST_RECORD_SECRET_HEX."
        )
    route = f"/api/v1/impact-jobs/{args.job}"
    try:
        with httpx.Client(
            base_url=args.origin,
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
            verify=os.environ.get("ST_RESOLVER_CA") or True,
            trust_env=False,
        ) as client:
            if args.output.exists():
                # A previous run may have written the file before losing the completion response.
                if args.output.is_symlink() or args.output.stat().st_mode & 0o077:
                    raise ValueError()
                with args.output.open(encoding="utf-8") as existing:
                    report = json.load(existing)
                if (report.get("job_id"), report.get("origin"), report.get("workspace")) != (
                    str(args.job),
                    args.origin,
                    args.workspace,
                ) or not isinstance(report.get("ids"), list):
                    raise ValueError()
                count = len(report["ids"])
            else:
                reply = client.get(route)
                reply.raise_for_status()
                job = reply.json()
                with args.catalog.open(encoding="utf-8") as catalog:
                    matches = resolve_records(
                        secret,
                        args.workspace,
                        UUID(job["token_set"]),
                        job["fingerprints"],
                        (line.rstrip("\r\n") for line in catalog),
                    )
                private_result(
                    args.output,
                    {
                        "job_id": str(args.job),
                        "origin": args.origin,
                        "workspace": args.workspace,
                        "ids": matches,
                    },
                )
                count = len(matches)
            client.post(route + "/complete", json={"matched_count": count}).raise_for_status()
    except httpx.HTTPStatusError as error:
        parser.exit(
            1,
            f"ShadowTrace refused the lookup or completion (HTTP {error.response.status_code}). Check job status before using any local result.\n",
        )
    except (OSError, httpx.RequestError, ValueError, TypeError, KeyError):
        parser.exit(
            1, "Lookup could not finish. Check the private source files, network and job status.\n"
        )
    print(
        f"Reported {count} resolved records. The source-side results are in the private output file."
    )


if __name__ == "__main__":
    main()

import hmac
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Literal
from uuid import UUID, uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Request
from pydantic import AwareDatetime

from .config import LOOPBACK
from .console import parsed
from .db import connection, digest, one
from .enforce import ReleaseDenied, release_protected
from .fingerprints import record_fingerprint
from .protection import REASONS
from .receipt_proof import sign_receipt
from .resolve_impact import resolve_records
from .schema import Payload
from .web import Issue, rate, unavailable, verify_csrf, workspace

router = APIRouter()


class DemoRun(Payload):
    scenario: Literal["normal", "incident", "lineage"]
    run_id: UUID
    started_at: AwareDatetime


def events_for(scenario, run_id, started):
    if scenario == "normal":
        entries = [
            ("support-010", "view", "order", 8),
            ("support-024", "view", "customer", 18),
            ("support-014", "view", "invoice", 4),
            ("support-024", "export", "order", 15),
        ]
    else:
        actor = "support-" + run_id
        entries = [
            (actor, "view", "customer", 260),
            (actor, "view", "customer", 360),
            (actor, "export", "customer", 570),
        ]
    return [
        {
            "event_id": f"{run_id}-{scenario}-{i}",
            "actor_id": actor,
            "action": action,
            "resource_type": resource,
            "records_accessed": count,
            "occurred_at": (started - timedelta(seconds=(len(entries) - i) * 37 + 1)).isoformat(),
            "outcome": "success",
        }
        for i, (actor, action, resource, count) in enumerate(entries, 1)
    ]


async def seed_history(conn, tenant, key_id, actor, run):
    # Source history has historical receipt timestamps. Live incident events use the real API clock.
    anchor = run.started_at.astimezone(UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    fixtures = []
    for index, volume in enumerate((18, 22, 25, 29, 30, 32, 24, 27, 34, 36, 28, 31)):
        when = anchor - timedelta(days=2 + index // 4) + timedelta(minutes=20 * (index % 4))
        event_id = f"{run.run_id}-history-{index}"
        fixtures.append((tenant, event_id, actor, key_id, volume, when, when, digest(event_id)))
    async with conn.cursor() as cursor:
        await cursor.executemany(
            """
            INSERT INTO st.events(workspace_id,event_id,actor_id,key_id,records_accessed,occurred_at,
              received_at,fingerprint,action,resource_type,outcome)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'view','customer','success')
            ON CONFLICT(workspace_id,event_id) DO NOTHING
            """,
            fixtures,
        )


def demo_record_secret(config):
    return hmac.digest(config.secret.encode(), b"shadowtrace-demo-lineage", "sha256")


def demo_signer(config, slug):
    return Ed25519PrivateKey.from_private_bytes(
        hmac.digest(config.secret.encode(), f"demo-signer:{slug}".encode(), "sha256")
    )


@router.post("/api/v1/workspaces/{slug}/demo")
async def run_demo(request: Request, slug: str):
    config = request.app.state.config
    if not config.demo or not request.client or request.client.host not in LOOPBACK:
        raise unavailable()
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        key = getattr(request.app.state, "demo_keys", {}).get(slug)
        if not key:
            raise Issue(409, "DEMO_KEY", "The local demo has no source key for this workspace.")
        source = await one(
            conn,
            """
            SELECT id FROM st.keys WHERE workspace_id=%s AND digest=%s AND revoked_at IS NULL FOR SHARE
        """,
            (member["id"], digest(key)),
        )
        if not source:
            raise Issue(
                409,
                "DEMO_KEY",
                "The demo source was revoked. Restart the demo in a fresh state directory.",
            )
    await rate(request, "demo-run", 8, identity=str(member["id"]))
    run = await parsed(request, DemoRun, "Choose a valid demo scenario.")
    now = datetime.now(UTC)
    if not now - timedelta(hours=1) <= run.started_at <= now + timedelta(minutes=1):
        raise Issue(422, "DEMO_TIME", "This run expired. Start another demo run.")
    run_id = run.run_id.hex
    entries = events_for(run.scenario, run_id, run.started_at)
    incident = run.scenario in {"incident", "lineage"}
    if incident:
        for entry in entries:
            entry["actor_id"] = "support-" + run_id[:12]
    actor = entries[0]["actor_id"]
    if incident:
        async with connection(request) as conn:
            await workspace(request, conn, slug)
            await seed_history(conn, member["id"], source["id"], actor, run)

    receipt = None
    receipt_key = None
    if run.scenario == "lineage":
        receipt_key = getattr(request.app.state, "demo_receipt_keys", {}).get(slug)
        if not receipt_key:
            raise Issue(409, "DEMO_KEY", "The local destination connector has no receipt key.")
        # All fixtures use source-side pseudonyms unique to this workspace and demo run.
        secret = demo_record_secret(config)
        tokens = [
            record_fingerprint(secret, slug, run.run_id, "customer", str(index))
            for index in range(1, 821)
        ]
        for entry, selected in zip(
            entries, (tokens[:260], tokens[260:620], tokens[:520] + tokens[620:670]), strict=True
        ):
            entry["lineage"] = {"token_set": str(run.run_id), "fingerprints": selected}
        source_digest = digest(f"{run_id}:synthetic-export-file")
        entries[-1].update(artifact_sha256=source_digest, expected_destination="partner-import")
        receipt = {
            "receipt_id": f"{run_id}-destination",
            "export_id": entries[-1]["event_id"],
            "destination": "partner-import",
            "token_set": str(run.run_id),
            "fingerprints": tokens[:390] + tokens[620:640],
            "occurred_at": run.started_at.isoformat(),
            "artifact_sha256": source_digest,
        }
        altered = receipt | {
            "receipt_id": f"{run_id}-altered",
            "fingerprints": tokens[:90] + tokens[700:712],
            "occurred_at": (run.started_at + timedelta(milliseconds=1)).isoformat(),
            "artifact_sha256": digest(f"{run_id}:synthetic-altered-file"),
        }
        for report in (receipt, altered):
            report["signature"] = sign_receipt(demo_signer(config, slug), slug, report)

    accepted = replayed = 0
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=2) as client:
            for entry in entries:
                response = await client.post(
                    config.origin + "/api/v1/events",
                    json=entry,
                    headers={"Authorization": f"Bearer {key}"},
                )
                if response.status_code == 429:
                    raise Issue(
                        429, "DEMO_RATE", "The demo source is busy. Retry this run shortly."
                    )
                if response.status_code == 409:
                    raise Issue(
                        409, "DEMO_CONFLICT", "That run ID was already used. Start another run."
                    )
                if response.status_code not in {200, 201}:
                    raise Issue(
                        503, "DEMO_DELIVERY", "A demo event could not be delivered. Retry this run."
                    )
                accepted += response.status_code == 201
                replayed += response.status_code == 200
            for report in (receipt, altered) if receipt else ():
                result = await client.post(
                    config.origin + "/api/v1/receipts",
                    json=report,
                    headers={"Authorization": f"Bearer {receipt_key}"},
                )
                if result.status_code == 401:
                    raise Issue(
                        409,
                        "DEMO_KEY",
                        "The destination key is revoked. Start the demo with a fresh state directory.",
                    )
                if result.status_code == 409:
                    raise Issue(
                        409, "DEMO_CONFLICT", "That receipt ID was already used. Start another run."
                    )
                if result.status_code not in {200, 201}:
                    raise Issue(
                        503,
                        "DEMO_DELIVERY",
                        "The destination receipt could not be delivered. Retry this run.",
                    )
    except httpx.HTTPError:
        raise Issue(
            503, "DEMO_DELIVERY", "Demo delivery was interrupted. Retry this run."
        ) from None

    case_url = None
    if incident:
        async with connection(request) as conn:
            await workspace(request, conn, slug)
            case = await one(
                conn,
                """
                SELECT id FROM st.cases WHERE workspace_id=%s AND actor_id=%s
                ORDER BY opened_at DESC LIMIT 1
            """,
                (member["id"], actor),
            )
            if case:
                case_url = f"/w/{slug}/cases/{case['id']}"
    response = {"accepted": accepted, "replayed": replayed, "case": case_url}
    if receipt:
        response["trace"] = f"/w/{slug}/exports/id-{entries[-1]['event_id']}"
    return response


@router.post("/api/v1/workspaces/{slug}/demo-impact/{job_id}")
async def demo_impact(request: Request, slug: str, job_id: UUID):
    config = request.app.state.config
    if not config.demo or not request.client or request.client.host not in LOOPBACK:
        raise unavailable()
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        fixture = await one(
            conn,
            """
            SELECT export_id FROM st.impact_requests WHERE workspace_id=%s AND id=%s
              AND export_id ~ '^[0-9a-f]{32}-lineage-3$'
        """,
            (member["id"], job_id),
        )
        key = getattr(request.app.state, "demo_impact_keys", {}).get(slug)
        if not fixture or not key:
            raise unavailable()
    route = config.origin + f"/api/v1/impact-jobs/{job_id}"
    try:
        async with httpx.AsyncClient(
            trust_env=False, timeout=3, headers={"Authorization": f"Bearer {key}"}
        ) as client:
            response = await client.get(route)
            response.raise_for_status()
            job = response.json()
            # This synthetic catalog intentionally lacks some original IDs.
            matched = resolve_records(
                demo_record_secret(config),
                slug,
                UUID(job["token_set"]),
                job["fingerprints"],
                (str(index) for index in range(1, 551)),
            )
            result = await client.post(route + "/complete", json={"matched_count": len(matched)})
            result.raise_for_status()
    except httpx.HTTPError:
        raise Issue(
            409, "DEMO_RESOLVER", "The synthetic lookup is unavailable. Refresh and check approval."
        ) from None
    return {"message": "Synthetic lookup completed."}


@router.post("/api/v1/workspaces/{slug}/demo-protection")
async def demo_protection(request: Request, slug: str):
    config = request.app.state.config
    if not config.demo or not request.client or request.client.host not in LOOPBACK:
        raise unavailable()
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        key = getattr(request.app.state, "demo_protection_keys", {}).get(slug)
    if not key:
        raise unavailable()
    await rate(request, "demo-protection", 10, identity=str(member["id"]))
    outcomes = []
    async with httpx.AsyncClient(base_url=config.origin, trust_env=False, timeout=3) as client:
        for action, alias in (("export", "approved-partner"), ("share", "personal-drive")):
            count = 12
            artifact = b"record\n" + b"".join(
                f"synthetic-{i}\n".encode() for i in range(1, count + 1)
            )
            with BytesIO() as receiver:
                outcome = await demo_transfer(client, key, action, alias, count, artifact, receiver)
            outcomes.append(outcome)
    return {"outcomes": outcomes}


async def demo_transfer(client, key, action, alias, count, artifact, receiver):
    title = f"{action.title()} to {alias}"
    try:
        await release_protected(
            client,
            credential=key,
            request_id=uuid4(),
            actor_id="demo-support",
            action=action,
            resource_type="customer",
            record_count=count,
            destination=alias,
            content=artifact,
            release=lambda _, body: receiver.write(body),
        )
    except ReleaseDenied as error:
        detail = f"{REASONS.get(error.reason, 'Authorization unavailable')}. {receiver.tell()} bytes released."
    else:
        detail = (
            f"Authorized by policy. The synthetic destination received {receiver.tell()} bytes."
        )
    return {"title": title, "detail": detail}

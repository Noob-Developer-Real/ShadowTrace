import hmac
import json
import re
import time
from datetime import timedelta

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from psycopg import errors, sql
from pydantic import ValidationError

from .db import bind, connection, digest, one
from .investigation import VIEW_WINDOW
from .receipt_proof import verify_receipt
from .schema import DestinationReceipt, Event
from .web import Issue, rate, read_json, unavailable

router = APIRouter()


@router.post("/api/v1/events")
async def intake(request: Request):
    return await process_delivery(request, "events", Event, accept)


@router.post("/api/v1/receipts")
async def intake_receipt(request: Request):
    return await process_delivery(request, "receipts", DestinationReceipt, accept_receipt)


async def process_delivery(request, purpose, model, handler):
    key = await delivery_key(request, purpose)
    try:
        payload = model.model_validate(await read_json(request))
        return await handler(request, key, payload)
    except ValidationError as error:
        field = error.errors(include_input=False)[0]["loc"]
        codes = {
            "event_id": "INVALID_EVENT_ID",
            "actor_id": "INVALID_ACTOR_ID",
            "action": "INVALID_ACTION",
            "resource_type": "INVALID_RESOURCE",
            "records_accessed": "INVALID_COUNT",
            "occurred_at": "INVALID_TIMESTAMP",
            "outcome": "INVALID_OUTCOME",
            "lineage": "INVALID_MANIFEST",
            "fingerprints": "INVALID_MANIFEST",
            "token_set": "INVALID_MANIFEST",
            "receipt_id": "INVALID_RECEIPT",
            "destination": "INVALID_RECEIPT",
            "export_id": "INVALID_RECEIPT",
        }
        code = codes.get(field[0], "INVALID_EVENT") if field else "INVALID_COUNT"
        if error.errors(include_input=False)[0]["type"] == "extra_forbidden":
            code = "INVALID_EVENT"
        await report_refusal(request, key, "rejected")
        raise Issue(422, code, "Check the delivery fields and submit again.") from None
    except Issue as error:
        if error.status in {400, 403, 404, 409, 415, 422, 429}:
            await report_refusal(request, key, "throttled" if error.status == 429 else "rejected")
        raise


async def delivery_key(request, purpose):
    auth = request.headers.get("authorization", "")
    if not re.fullmatch(r"Bearer st_(?:demo|live)_[A-Za-z0-9_-]{43}", auth):
        await rate(request, "invalid-ingest", 90)
        raise Issue(401, "INVALID_KEY", "Provide a valid integration key.")

    key_digest = digest(auth.removeprefix("Bearer "))
    async with connection(request) as conn:
        await bind(conn, "st.key_digest", key_digest)
        key = await one(
            conn,
            "SELECT id,workspace_id,purpose,destination,signing_public_key,source_key_id FROM st.keys WHERE digest=%s AND revoked_at IS NULL",
            (key_digest,),
        )
    if not key:
        await rate(request, "invalid-ingest", 90)
        raise Issue(401, "INVALID_KEY", "Provide a valid integration key.")

    try:
        await rate(request, "ingest", 240, identity=str(key["id"]))
    except Issue:
        await report_refusal(request, key, "throttled")
        raise
    if key["purpose"] != purpose:
        await report_refusal(request, key, "rejected")
        raise Issue(403, "WRONG_KEY_PURPOSE", "Use a key authorized for this delivery type.")
    return key


async def report_refusal(request, key, counter):
    async with connection(request) as conn:
        await bind(conn, "st.tenant_id", key["workspace_id"])
        active = await one(
            conn,
            """
            SELECT id FROM st.keys WHERE workspace_id=%s AND id=%s AND revoked_at IS NULL FOR SHARE
        """,
            (key["workspace_id"], key["id"]),
        )
        if active:
            await record_delivery(conn, key["workspace_id"], key["id"], counter)


async def record_delivery(conn, workspace, key, counter):
    column = sql.Identifier(counter)
    await conn.execute(
        sql.SQL("""
            INSERT INTO st.ingest_health(workspace_id,key_id,day,{column})
            VALUES(%s,%s,(clock_timestamp() AT TIME ZONE 'UTC')::date,1)
            ON CONFLICT (workspace_id,key_id,day) DO UPDATE
              SET {column}=st.ingest_health.{column}+1
        """).format(column=column),
        (workspace, key),
    )


async def lock_key(conn, key):
    workspace = key["workspace_id"]
    await bind(conn, "st.tenant_id", workspace)
    active = await one(
        conn,
        """
        SELECT id FROM st.keys WHERE id=%s AND workspace_id=%s AND revoked_at IS NULL FOR SHARE
    """,
        (key["id"], workspace),
    )
    if not active:
        raise Issue(401, "INVALID_KEY", "Provide a valid integration key.")


def payload_fingerprint(payload):
    normalized = payload.model_dump(mode="json", exclude_none=True)
    return digest(json.dumps(normalized, sort_keys=True, separators=(",", ":")))


async def accept(request, key, event):
    fingerprint = payload_fingerprint(event)
    started = time.monotonic()
    workspace = key["workspace_id"]
    async with connection(request) as conn:
        await lock_key(conn, key)
        # The retention helper requires the authenticated key digest as well as tenant scope.
        await bind(
            conn, "st.key_digest", digest(request.headers["authorization"].removeprefix("Bearer "))
        )
        # Lock the external event ID before the actor stream. All deliveries take locks in this order.
        await conn.execute(
            "SELECT pg_advisory_xact_lock(1,hashtext(%s))", (f"{workspace}/{event.event_id}",)
        )
        prior = await one(
            conn,
            """
            SELECT fingerprint,received_at FROM st.events WHERE workspace_id=%s AND event_id=%s
        """,
            (workspace, event.event_id),
        )
        if prior:
            if not hmac.compare_digest(prior["fingerprint"], fingerprint):
                raise Issue(
                    409, "EVENT_ID_CONFLICT", "This event ID already has a different payload."
                )
            await record_delivery(conn, workspace, key["id"], "replayed")
            return receipt(event, prior["received_at"], True)

        await conn.execute(
            "SELECT pg_advisory_xact_lock(2,hashtext(%s))",
            (f"{workspace}/{event.actor_id}/{event.resource_type}",),
        )
        policy = await one(
            conn,
            """
            SELECT p.*,clock_timestamp() AS accepted,w.retention_days
            FROM st.policy p CROSS JOIN st.ingest_retention(p.workspace_id) w
            WHERE p.workspace_id=%s
        """,
            (workspace,),
        )
        if not policy:
            raise Issue(
                503, "RULES_UNAVAILABLE", "The workspace rules are temporarily unavailable."
            )
        now = policy["accepted"]
        if (
            not now - timedelta(days=min(7, policy["retention_days"]))
            <= event.occurred_at
            <= now + timedelta(minutes=5)
        ):
            raise Issue(
                422, "INVALID_TIMESTAMP", "Use an event time within the accepted delivery window."
            )

        await conn.execute(
            """
            INSERT INTO st.events(workspace_id,event_id,actor_id,key_id,action,resource_type,
                records_accessed,outcome,occurred_at,received_at,fingerprint)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
            (
                workspace,
                event.event_id,
                event.actor_id,
                key["id"],
                event.action,
                event.resource_type,
                event.records_accessed,
                event.outcome,
                event.occurred_at,
                now,
                fingerprint,
            ),
        )
        if event.lineage:
            await conn.execute(
                """
                INSERT INTO st.event_manifests(workspace_id,event_id,token_set,fingerprints,
                    artifact_sha256,expected_destination,receipt_due_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
            """,
                (
                    workspace,
                    event.event_id,
                    event.lineage.token_set,
                    event.lineage.fingerprints,
                    event.artifact_sha256,
                    event.expected_destination,
                    now + timedelta(minutes=event.receipt_due_minutes or 60)
                    if event.expected_destination
                    else None,
                ),
            )
        await detect(conn, workspace, event, policy)
        await record_delivery(conn, workspace, key["id"], "accepted")

    response = receipt(event, now, False)
    response.headers["Server-Timing"] = f"ingest;dur={(time.monotonic() - started) * 1000:.1f}"
    return response


def receipt(event, accepted, replayed):
    # Write-only clients receive an ingestion receipt and no case metadata or identifiers.
    return JSONResponse(
        {"event_id": event.event_id, "accepted_at": accepted.isoformat(), "replayed": replayed},
        status_code=200 if replayed else 201,
    )


async def detect(conn, workspace, event, policy):
    if event.outcome != "success":
        return
    now = policy["accepted"]
    window = now - VIEW_WINDOW
    per_actor = (workspace, event.actor_id, event.resource_type)
    if event.action == "view":
        total = await one(
            conn,
            """
            SELECT coalesce(sum(records_accessed),0) AS n FROM st.events
            WHERE workspace_id=%s AND actor_id=%s AND resource_type=%s
            AND action='view' AND outcome='success' AND received_at >= %s AND received_at <= %s
        """,
            (*per_actor, window, now),
        )
        observed, threshold, rule, severity = total["n"], policy["view_limit"], "view_burst", "high"
    else:
        observed, threshold, rule, severity = (
            event.records_accessed,
            policy["export_limit"],
            "large_export",
            "critical",
        )
    if observed < threshold:
        return

    case = await one(
        conn,
        """
        SELECT id FROM st.cases WHERE workspace_id=%s AND actor_id=%s AND resource_type=%s
         AND status IN ('open','in_review') AND latest_at >= %s
        ORDER BY latest_at DESC,id DESC LIMIT 1 FOR UPDATE
    """,
        (*per_actor, now - timedelta(minutes=10)),
    )
    if case:
        await conn.execute(
            """
            UPDATE st.cases SET severity=CASE WHEN severity='critical' THEN severity ELSE %s END,
              latest_at=%s, version=version+1 WHERE workspace_id=%s AND id=%s
        """,
            (severity, now, workspace, case["id"]),
        )
    else:
        case = await one(
            conn,
            """
            INSERT INTO st.cases(workspace_id,actor_id,resource_type,severity,opened_at,latest_at)
            VALUES (%s,%s,%s,%s,%s,%s) RETURNING id
        """,
            (*per_actor, severity, now, now),
        )

    await conn.execute(
        """
        INSERT INTO st.signals(workspace_id,case_id,rule,rule_version,threshold,observed,detected_at)
          VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (workspace_id,case_id,rule,rule_version) DO UPDATE
          SET observed=greatest(st.signals.observed,excluded.observed)
    """,
        (workspace, case["id"], rule, policy["version"], threshold, observed, now),
    )
    if rule == "view_burst":
        await conn.execute(
            """
            INSERT INTO st.evidence(workspace_id,case_id,event_id)
            SELECT workspace_id,%s,event_id FROM st.events
            WHERE workspace_id=%s AND actor_id=%s AND resource_type=%s
                AND action='view' AND outcome='success' AND received_at >= %s AND received_at <= %s
            ON CONFLICT DO NOTHING
        """,
            (case["id"], *per_actor, window, now),
        )
    else:
        await conn.execute(
            "INSERT INTO st.evidence VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
            (workspace, case["id"], event.event_id),
        )


async def accept_receipt(request, key, payload):
    workspace = key["workspace_id"]
    fingerprint = payload_fingerprint(payload)
    async with connection(request) as conn:
        await lock_key(conn, key)
        await conn.execute(
            "SELECT pg_advisory_xact_lock(4,hashtext(%s))", (f"{workspace}/{payload.receipt_id}",)
        )
        prior = await one(
            conn,
            """
            SELECT fingerprint,received_at,key_id FROM st.destination_receipts
            WHERE workspace_id=%s AND receipt_id=%s
        """,
            (workspace, payload.receipt_id),
        )
        if prior:
            if prior["key_id"] != key["id"] or not hmac.compare_digest(
                prior["fingerprint"], fingerprint
            ):
                raise Issue(409, "RECEIPT_CONFLICT", "This receipt ID is already in use.")
            await record_delivery(conn, workspace, key["id"], "replayed")
            return receipt_result(payload, prior["received_at"], True)
        if payload.signature:
            await conn.execute(
                "SELECT pg_advisory_xact_lock(5,hashtext(%s))",
                (f"{workspace}/{payload.export_id}",),
            )
        export = await one(
            conn,
            """
            SELECT e.occurred_at,e.records_accessed,m.token_set,m.fingerprints,
                   m.artifact_sha256,m.expected_destination,m.receipt_due_at,clock_timestamp() AS accepted
            FROM st.event_manifests m JOIN st.events e USING(workspace_id,event_id)
            WHERE m.workspace_id=%s AND m.event_id=%s AND e.action='export' AND e.outcome='success'
        """,
            (workspace, payload.export_id),
        )
        if not export:
            raise unavailable()
        if payload.token_set != export["token_set"]:
            raise Issue(
                422, "TOKEN_SET_MISMATCH", "The receipt and export must use the same token set."
            )
        now = export["accepted"]
        if (
            not max(export["occurred_at"], now - timedelta(days=7))
            <= payload.occurred_at
            <= now + timedelta(minutes=5)
        ):
            raise Issue(
                422,
                "INVALID_TIMESTAMP",
                "Use a receipt time after the export and within the delivery window.",
            )
        slug = None
        if payload.signature:
            await bind(conn, "st.key_digest", digest(request.headers["authorization"][7:]))
            slug = (await one(conn, "SELECT st.receipt_workspace_slug(%s) AS slug", (workspace,)))[
                "slug"
            ]
        manifest, comparison, findings = verify_receipt(key, slug, payload, export)
        first_expected = False
        if (
            manifest
            and payload.destination == export["expected_destination"]
            and comparison != "different"
        ):
            first_expected = not await one(
                conn,
                """
                SELECT 1 FROM st.destination_receipts WHERE workspace_id=%s AND export_id=%s AND destination=%s
                  AND signature IS NOT NULL AND file_comparison <> 'different' LIMIT 1
            """,
                (workspace, payload.export_id, payload.destination),
            )
        if findings or first_expected:
            # Lock before assigning the acceptance timestamp so reviews serialize with material changes.
            await conn.execute(
                """
                UPDATE st.cases c SET version=version+1
                WHERE c.workspace_id=%s AND EXISTS (
                  SELECT 1 FROM st.evidence x WHERE x.workspace_id=c.workspace_id AND x.case_id=c.id AND x.event_id=%s)
            """,
                (workspace, payload.export_id),
            )
            now = (await one(conn, "SELECT clock_timestamp() AS accepted"))["accepted"]
        try:
            await conn.execute(
                """
                INSERT INTO st.destination_receipts(workspace_id,receipt_id,export_id,key_id,destination,
                    fingerprints,occurred_at,received_at,fingerprint,artifact_sha256,signature,manifest_sha256,file_comparison,findings)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
                (
                    workspace,
                    payload.receipt_id,
                    payload.export_id,
                    key["id"],
                    payload.destination,
                    payload.fingerprints,
                    payload.occurred_at,
                    now,
                    fingerprint,
                    payload.artifact_sha256,
                    payload.signature,
                    manifest,
                    comparison,
                    findings,
                ),
            )
        except errors.ForeignKeyViolation:
            # Retention can remove the export after lookup; the foreign key closes the race.
            raise unavailable() from None
        await record_delivery(conn, workspace, key["id"], "accepted")
    return receipt_result(payload, now, False)


def receipt_result(payload, accepted, replayed):
    return JSONResponse(
        {
            "receipt_id": payload.receipt_id,
            "accepted_at": accepted.isoformat(),
            "replayed": replayed,
        },
        status_code=200 if replayed else 201,
    )

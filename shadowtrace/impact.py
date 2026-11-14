"""Approval workflow and a pull API for the source-side customer resolver."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from psycopg import errors
from pydantic import Field, ValidationError

from .db import connection, one, rows
from .ingest import delivery_key, lock_key, record_delivery
from .schema import Identifier, Payload
from .web import Issue, rate, read_json, unavailable, verify_csrf, workspace

router = APIRouter()
SCOPES = {"export": "Export manifest", "received": "Same-file receipt matches"}
REASONS = {
    "scoping": "Incident scoping",
    "notification": "Customer notification",
    "remediation": "Remediation",
}
PUBLIC_FIELDS = """
    id,case_id,requester_id,requester,approver,scope,reason,ticket,
    CASE WHEN expires_at <= clock_timestamp() AND state IN ('pending','approved')
      THEN 'expired' ELSE state END AS state,
    cardinality(fingerprints) AS requested_count,matched_count,expires_at
"""


class ImpactRequest(Payload):
    request_id: UUID
    scope: Literal["export", "received"]
    reason: Literal["scoping", "notification", "remediation"]
    ticket: Identifier


class ImpactResult(Payload):
    matched_count: Annotated[int, Field(strict=True, ge=0, le=1000)]


async def parse(request, model, message):
    try:
        return model.model_validate(await read_json(request))
    except ValidationError:
        raise Issue(422, "INVALID_IMPACT_INPUT", message) from None


async def audit(conn, workspace_id, actor, action, request_id):
    await conn.execute(
        "INSERT INTO st.audit(workspace_id,actor,operation,subject) VALUES(%s,%s,%s,%s)",
        (workspace_id, actor, action, str(request_id)),
    )


async def impact_history(conn, tenant, export_id):
    return await rows(
        conn,
        f"""
        SELECT {PUBLIC_FIELDS} FROM st.impact_requests WHERE workspace_id=%s AND export_id=%s
        ORDER BY (state IN ('pending','approved') AND expires_at>now()) DESC,created_at DESC,id LIMIT 20
        """,
        (tenant, export_id),
    )


@router.post("/api/v1/workspaces/{slug}/exports/id-{export_id}/impact")
async def request_impact(request: Request, slug: str, export_id: str):
    await rate(request, "impact-request", 30)
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        form = await parse(
            request, ImpactRequest, "Choose a scope and reason and enter a ticket ID."
        )
        tenant, principal = member["id"], identity["principal_id"]
        await conn.execute(
            "SELECT pg_advisory_xact_lock(7,hashtext(%s))", (f"{tenant}/{form.request_id}",)
        )
        await conn.execute(
            "SELECT pg_advisory_xact_lock(6,hashtext(%s))", (f"{tenant}/{export_id}",)
        )
        prior = await one(
            conn,
            """
            SELECT export_id,scope,ticket,reason,requester_id FROM st.impact_requests
            WHERE workspace_id=%s AND id=%s
        """,
            (tenant, form.request_id),
        )
        if prior:
            if prior == {
                "export_id": export_id,
                "scope": form.scope,
                "ticket": form.ticket,
                "reason": form.reason,
                "requester_id": principal,
            }:
                return {"message": "Lookup requested."}
            raise Issue(409, "REQUEST_CONFLICT", "Reload the trace before creating a new request.")
        target = await one(
            conn,
            """
            SELECT e.key_id,m.fingerprints,a.case_id
            FROM st.event_manifests m JOIN st.events e USING(workspace_id,event_id)
            JOIN LATERAL (
                SELECT x.case_id FROM st.evidence x JOIN st.cases c
                    ON c.workspace_id=x.workspace_id AND c.id=x.case_id
                WHERE x.workspace_id=e.workspace_id AND x.event_id=e.event_id
                ORDER BY c.opened_at DESC,c.id DESC LIMIT 1
            ) a ON true
            WHERE e.workspace_id=%s AND e.event_id=%s AND e.action='export'
              AND e.outcome='success' AND e.resource_type='customer'
        """,
            (tenant, export_id),
        )
        if not target:
            raise unavailable()
        if await one(
            conn,
            """
            SELECT 1 FROM st.impact_requests WHERE workspace_id=%s AND export_id=%s AND scope=%s
              AND requester_id=%s AND state IN ('pending','approved') AND expires_at>now() LIMIT 1
        """,
            (tenant, export_id, form.scope, principal),
        ):
            raise Issue(409, "LOOKUP_ACTIVE", "A lookup for this scope is already active.")
        tokens = target["fingerprints"]
        if form.scope == "received":
            matched = await rows(
                conn,
                """
                SELECT f AS token FROM unnest(%s::text[]) AS f WHERE EXISTS (
                    SELECT 1 FROM st.destination_receipts r WHERE r.workspace_id=%s AND r.export_id=%s
                      AND r.file_comparison='same' AND f=ANY(r.fingerprints)
                )
            """,
                (tokens, tenant, export_id),
            )
            tokens = sorted(row["token"] for row in matched)
        if not tokens:
            raise Issue(
                422, "NO_MATCHES", "Choose Export manifest or wait for a matching signed receipt."
            )
        try:
            await conn.execute(
                """
                INSERT INTO st.impact_requests(workspace_id,id,export_id,case_id,source_key_id,
                    requester_id,requester,scope,reason,ticket,fingerprints)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
                (
                    tenant,
                    form.request_id,
                    export_id,
                    target["case_id"],
                    target["key_id"],
                    principal,
                    member["principal_name"],
                    form.scope,
                    form.reason,
                    form.ticket,
                    tokens,
                ),
            )
        except errors.ForeignKeyViolation:
            raise unavailable() from None
        await audit(
            conn, tenant, member["principal_name"], "Impact lookup requested", form.request_id
        )
    return JSONResponse({"message": "Lookup requested."}, status_code=201)


@router.post("/api/v1/workspaces/{slug}/impact/{job_id}/{action}")
async def act_on_impact(
    request: Request, slug: str, job_id: UUID, action: Literal["approve", "cancel"]
):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=action == "approve")
        verify_csrf(request, identity)
        tenant, principal = member["id"], identity["principal_id"]
        job = await one(
            conn,
            """
            SELECT requester_id,approver_id,state,expires_at<=clock_timestamp() AS expired
            FROM st.impact_requests WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            (tenant, job_id),
        )
        if not job or (
            action == "cancel" and principal != job["requester_id"] and member["role"] != "admin"
        ):
            raise unavailable()
        if action == "approve" and principal == job["requester_id"]:
            raise Issue(
                403, "INDEPENDENT_APPROVAL", "Another workspace admin must approve this lookup."
            )
        state = "approved" if action == "approve" else "cancelled"
        message = "Lookup approved." if action == "approve" else "Lookup cancelled."
        if job["state"] == state:
            return {"message": message}
        if job["expired"] or job["state"] not in (
            {"pending"} if action == "approve" else {"pending", "approved"}
        ):
            raise Issue(409, "LOOKUP_CHANGED", "This lookup changed or expired. Refresh the trace.")
        if action == "approve":
            await conn.execute(
                """
                UPDATE st.impact_requests SET state='approved',approver_id=%s,approver=%s
                WHERE workspace_id=%s AND id=%s
            """,
                (principal, member["principal_name"], tenant, job_id),
            )
        else:
            await conn.execute(
                """
                UPDATE st.impact_requests SET state='cancelled' WHERE workspace_id=%s AND id=%s
            """,
                (tenant, job_id),
            )
        await audit(conn, tenant, member["principal_name"], f"Impact lookup {state}", job_id)
    return {"message": message}


@router.get("/api/v1/impact-jobs/{job_id}")
async def pull_impact(request: Request, job_id: UUID):
    key = await delivery_key(request, "impact")
    async with connection(request) as conn:
        await lock_key(conn, key)
        job = await one(
            conn,
            """
            SELECT m.token_set,i.export_id,i.scope,i.fingerprints,i.expires_at,k.label
            FROM st.impact_requests i JOIN st.event_manifests m
              ON m.workspace_id=i.workspace_id AND m.event_id=i.export_id
            JOIN st.keys k ON k.workspace_id=i.workspace_id AND k.id=%s
            WHERE i.workspace_id=%s AND i.source_key_id=%s AND i.id=%s
              AND i.state='approved' AND i.expires_at>clock_timestamp()
            FOR SHARE OF i
        """,
            (key["id"], key["workspace_id"], key["source_key_id"], job_id),
        )
        if not job:
            raise unavailable()
        await audit(
            conn, key["workspace_id"], job.pop("label"), "Impact snapshot delivered", job_id
        )
    return job | {"job_id": job_id}


@router.post("/api/v1/impact-jobs/{job_id}/complete")
async def complete_impact(request: Request, job_id: UUID):
    key = await delivery_key(request, "impact")
    result = await parse(request, ImpactResult, "Send a nonnegative matched record count.")
    async with connection(request) as conn:
        await lock_key(conn, key)
        job = await one(
            conn,
            """
            SELECT state,completed_by,matched_count,cardinality(fingerprints) AS requested_count,
              expires_at<=clock_timestamp() AS expired
            FROM st.impact_requests WHERE workspace_id=%s AND source_key_id=%s AND id=%s FOR UPDATE
        """,
            (key["workspace_id"], key["source_key_id"], job_id),
        )
        if not job or job["state"] not in {"approved", "completed"}:
            raise unavailable()
        if job["state"] == "completed":
            if job["completed_by"] == key["id"] and job["matched_count"] == result.matched_count:
                return {"replayed": True}
            raise Issue(409, "RESULT_CONFLICT", "This lookup already has a result.")
        if job["expired"]:
            raise unavailable()
        if result.matched_count > job["requested_count"]:
            raise Issue(
                422, "COUNT_EXCEEDS_SCOPE", "The count exceeds the requested fingerprint scope."
            )
        connector = await one(
            conn,
            "SELECT label FROM st.keys WHERE workspace_id=%s AND id=%s",
            (key["workspace_id"], key["id"]),
        )
        await conn.execute(
            """
            UPDATE st.impact_requests SET state='completed',matched_count=%s,completed_at=clock_timestamp(),completed_by=%s
            WHERE workspace_id=%s AND id=%s
        """,
            (result.matched_count, key["id"], key["workspace_id"], job_id),
        )
        await audit(
            conn, key["workspace_id"], connector["label"], "Impact lookup completed", job_id
        )
        await record_delivery(conn, key["workspace_id"], key["id"], "accepted")
    return {"replayed": False}

"""Workspace policy and server-to-server authorization for protected releases."""

from typing import Annotated, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import Field, ValidationError, field_validator, model_validator

from .console import filters, log_action, paginate, parsed
from .db import bind, connection, digest, one
from .ingest import delivery_key, lock_key, payload_fingerprint, record_delivery
from .managed_links import create_link, links_for_workspace
from .schema import Identifier, Payload
from .transfer_approvals import approval_state, approvals_for_workspace
from .transfer_intent import Transfer
from .web import Issue, rate, read_json, render, verify_csrf, workspace

router = APIRouter()
ACTIONS = ("export", "download", "share")
OUTCOMES = ("allowed", "blocked")
REASONS = {
    "allowed": "Within policy",
    "paused": "Protection policy paused",
    "destination": "Destination is not approved",
    "disabled": "Action disabled by workspace policy",
    "limit": "Record limit exceeded",
    "cumulative": "24-hour actor limit exceeded",
    "approval_denied": "Sensitive transfer denied",
}
DEFAULT = {
    "version": 0,
    "mode": "paused",
    "export_limit": 500,
    "download_limit": 100,
    "share_limit": 50,
    "destinations": [],
    "approval_threshold": 0,
    "cumulative_limit": 0,
}
Limit = Annotated[int, Field(strict=True, ge=0, le=1_000_000)]


class ProtectionPolicy(Payload):
    version: Annotated[int, Field(strict=True, ge=0, lt=2147483647)]
    mode: Literal["active", "paused"]
    export_limit: Limit
    download_limit: Limit
    share_limit: Limit
    approval_threshold: Limit | None = None
    cumulative_limit: Annotated[int, Field(strict=True, ge=0, le=10_000_000)] | None = None
    destinations: Annotated[list[Identifier], Field(max_length=20)]

    @field_validator("destinations")
    @classmethod
    def unique_aliases(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Remove duplicate destination aliases.")
        return sorted(value)

    @model_validator(mode="after")
    def active_needs_destination(self):
        if self.mode == "active" and not self.destinations:
            raise ValueError("Enter at least one destination to activate protection.")
        return self


async def read_policy(conn, tenant, lock=False):
    query = """
        SELECT version,mode,export_limit,download_limit,share_limit,destinations,approval_threshold,cumulative_limit
        FROM st.protection_policy WHERE workspace_id=%s
    """
    return await one(conn, query + (" FOR SHARE" if lock else ""), (tenant,)) or DEFAULT.copy()


def evaluate(policy, transfer):
    if policy["mode"] == "paused":
        return "paused"
    if transfer.destination not in policy["destinations"]:
        return "destination"
    limit = policy[f"{transfer.action}_limit"]
    if limit == 0:
        return "disabled"
    if transfer.record_count > limit:
        return "limit"
    return "allowed"


async def verify_parties(conn, request, tenant, transfer):
    parties = {transfer.requester_id, transfer.recipient_id} - {None}
    if parties:
        await bind(conn, "st.key_digest", digest(request.headers["authorization"][7:]))
    for party in parties:
        valid = await one(conn, "SELECT st.protection_member(%s,%s) AS member", (tenant, party))
        if not valid["member"]:
            raise Issue(422, "INVALID_PARTY", "Use a current member of this workspace.")


async def actor_budget(conn, tenant, transfer, policy):
    if not policy["cumulative_limit"]:
        return True
    used = await one(
        conn,
        """
        SELECT coalesce(sum(record_count),0) AS total
        FROM st.protection_decisions WHERE workspace_id=%s AND actor_id=%s AND outcome='allowed'
          AND decided_at > clock_timestamp()-interval '24 hours'
    """,
        (tenant, transfer.actor_id),
    )
    return used["total"] + transfer.record_count <= policy["cumulative_limit"]


@router.post("/api/v1/protection/authorize")
async def authorize(request: Request):
    key = await delivery_key(request, "protection")
    try:
        transfer = Transfer.model_validate(await read_json(request))
    except ValidationError:
        raise Issue(
            422, "INVALID_TRANSFER", "Check transfer metadata and channel fields."
        ) from None
    tenant = key["workspace_id"]
    async with connection(request) as conn:
        await lock_key(conn, key)
        policy = await read_policy(conn, tenant, lock=True)
        # Serialize the same operation across credential rotation and actor changes.
        await conn.execute(
            "SELECT pg_advisory_xact_lock(9,hashtext(%s))", (f"{tenant}/{transfer.request_id}",)
        )
        if await one(
            conn,
            """
            SELECT 1 FROM st.protection_decisions WHERE workspace_id=%s AND request_id=%s
        """,
            (tenant, transfer.request_id),
        ):
            await record_delivery(conn, tenant, key["id"], "replayed")
        else:
            return await authorize_new(conn, request, key, policy, transfer)
    raise Issue(409, "TRANSFER_ID_USED", "This operation already received a decision.")


async def authorize_new(conn, request, key, policy, transfer):
    tenant = key["workspace_id"]
    await verify_parties(conn, request, tenant, transfer)
    reason = evaluate(policy, transfer)
    intent = Jsonb(transfer.model_dump(mode="json", exclude_none=True))
    required = transfer.sensitive or (
        transfer.resource_type == "customer"
        and 0 < policy["approval_threshold"] <= transfer.record_count
    )
    approval, expiry = await approval_state(
        conn,
        tenant,
        key["id"],
        transfer,
        intent,
        payload_fingerprint(transfer),
        policy,
        required and reason == "allowed",
    )
    if reason == "allowed":
        if transfer.channel == "cloud_link" and request.app.state.share_storage is None:
            raise Issue(
                503, "STORAGE_UNAVAILABLE", "Configure private share storage before issuing links."
            )
        if approval == "pending":
            return JSONResponse(
                {
                    "request_id": str(transfer.request_id),
                    "outcome": "pending",
                    "expires_at": expiry.isoformat(),
                },
                status_code=202,
            )
        if approval == "denied":
            reason = "approval_denied"
        if reason == "allowed" and policy["cumulative_limit"]:
            await conn.execute(
                "SELECT pg_advisory_xact_lock(10,hashtext(%s))", (f"{tenant}/{transfer.actor_id}",)
            )
            if not await actor_budget(conn, tenant, transfer, policy):
                reason = "cumulative"
    outcome = "allowed" if reason == "allowed" else "blocked"
    written = await one(
        conn,
        """
        INSERT INTO st.protection_decisions(workspace_id,key_id,request_id,actor_id,action,
          resource_type,record_count,destination,content_sha256,outcome,reason,revision,intent)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING decided_at
    """,
        (
            tenant,
            key["id"],
            transfer.request_id,
            transfer.actor_id,
            transfer.action,
            transfer.resource_type,
            transfer.record_count,
            transfer.destination,
            transfer.content_sha256,
            outcome,
            reason,
            policy["version"],
            intent,
        ),
    )
    if approval == "approved":
        await conn.execute(
            """
            UPDATE st.transfer_approvals SET state='consumed' WHERE workspace_id=%s AND id=%s
        """,
            (tenant, transfer.request_id),
        )
    result = {
        "request_id": str(transfer.request_id),
        "content_sha256": transfer.content_sha256,
        "outcome": outcome,
        "reason": reason,
        "policy_version": policy["version"],
        "decided_at": written["decided_at"].isoformat(),
    }
    if outcome == "allowed" and transfer.channel == "cloud_link":
        await create_link(conn, tenant, transfer, written["decided_at"])
        slug = (await one(conn, "SELECT st.protection_slug(%s) AS slug", (tenant,)))["slug"]
        result["link_path"] = f"/w/{slug}/protection/links/{transfer.request_id}"
    await record_delivery(conn, tenant, key["id"], "accepted")
    return JSONResponse(result, status_code=201)


@router.get("/w/{slug}/protection")
async def protection_page(request: Request, slug: str):
    values, error = filters(request, {"outcome": OUTCOMES, "action": ACTIONS})
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        tenant = member["id"]
        policy = await read_policy(conn, tenant)
        totals = await one(
            conn,
            """
            SELECT count(*) FILTER (WHERE outcome='allowed') AS allowed,
                   count(*) FILTER (WHERE outcome='blocked') AS blocked
              FROM st.protection_decisions WHERE workspace_id=%s AND decided_at>=now()-interval '24 hours'
        """,
            (tenant,),
        )
        clauses, params = [sql.SQL("workspace_id=%s")], [tenant]
        for name, value in values.items():
            if value:
                clauses.append(sql.Identifier(name) + sql.SQL("=%s"))
                params.append(value)
        decisions, previous, following = await paginate(
            request,
            conn,
            member,
            query="""SELECT * FROM (
                SELECT d.workspace_id,d.decided_at,d.request_id,d.key_id,d.actor_id,d.action,
                       d.resource_type,d.record_count,d.destination,d.outcome,d.reason,d.revision,d.intent,k.label
                FROM st.protection_decisions d JOIN st.keys k ON k.workspace_id=d.workspace_id AND k.id=d.key_id
              ) decisions""",
            clauses=clauses,
            parameters=params,
            filter_values=values,
            fields=("decided_at", "request_id", "key_id"),
            group="protection",
        )
        approvals = await approvals_for_workspace(conn, tenant, policy["version"])
        links = await links_for_workspace(conn, tenant)
        recipients = await conn.execute("SELECT id,name FROM st.case_members() ORDER BY name,id")
        recipients = await recipients.fetchall()
    return render(
        request,
        "protection",
        title="Protection",
        member=member,
        identity=identity,
        policy=policy,
        actions=ACTIONS,
        outcomes=OUTCOMES,
        reasons=REASONS,
        totals=totals,
        decisions=decisions,
        approvals=approvals,
        links=links,
        recipients=recipients,
        member_names={str(person["id"]): person["name"] for person in recipients},
        values=values,
        problem=error,
        prev=previous,
        more=following,
        demo_protection=bool(getattr(request.app.state, "demo_protection_keys", {}).get(slug)),
        status=422 if error else 200,
    )


@router.post("/api/v1/workspaces/{slug}/protection/policy")
async def save_protection(request: Request, slug: str):
    await rate(request, "protection-policy", 30)
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        form = await parsed(
            request, ProtectionPolicy, "Check mode, limits and destination aliases."
        )
        tenant = member["id"]
        await conn.execute("SELECT pg_advisory_xact_lock(8,hashtext(%s))", (str(tenant),))
        current = await read_policy(conn, tenant)
        if current["version"] != form.version:
            raise Issue(
                409, "STALE_POLICY", "This policy changed. Reload to see the latest version."
            )
        revision = form.version + 1
        await conn.execute(
            """
            INSERT INTO st.protection_policy(workspace_id,version,mode,export_limit,download_limit,share_limit,
              destinations,approval_threshold,cumulative_limit)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (workspace_id) DO UPDATE SET version=excluded.version,mode=excluded.mode,
              export_limit=excluded.export_limit,download_limit=excluded.download_limit,
              share_limit=excluded.share_limit,destinations=excluded.destinations,
              approval_threshold=excluded.approval_threshold,cumulative_limit=excluded.cumulative_limit
        """,
            (
                tenant,
                revision,
                form.mode,
                form.export_limit,
                form.download_limit,
                form.share_limit,
                form.destinations,
                current["approval_threshold"]
                if form.approval_threshold is None
                else form.approval_threshold,
                current["cumulative_limit"]
                if form.cumulative_limit is None
                else form.cumulative_limit,
            ),
        )
        await log_action(
            conn, member, "Protection policy saved", f"Revision {revision} · {form.mode}"
        )
    return {"message": "Protection policy saved.", "version": revision}

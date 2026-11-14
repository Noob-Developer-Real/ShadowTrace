"""Approval state machine bound to the original transfer and policy revision."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request

from .console import log_action
from .db import connection, one, rows
from .web import Issue, rate, unavailable, verify_csrf, workspace

router = APIRouter()


async def approval_state(conn, tenant, key_id, transfer, intent, fingerprint, policy, required):
    existing = await one(
        conn,
        """
        SELECT key_id,fingerprint,revision,state,expires_at,expires_at<=clock_timestamp() AS expired
        FROM st.transfer_approvals WHERE workspace_id=%s AND id=%s FOR UPDATE
    """,
        (tenant, transfer.request_id),
    )
    if existing:
        if (
            existing["key_id"] != key_id
            or existing["fingerprint"] != fingerprint
            or existing["revision"] != policy["version"]
            or existing["expired"]
        ):
            raise Issue(
                409,
                "APPROVAL_CHANGED",
                "The transfer, credential or policy changed, or approval expired.",
            )
        return existing["state"], existing["expires_at"]
    if not required:
        return None, None
    if transfer.requester_id is None and transfer.channel != "scheduled":
        raise Issue(
            422, "REQUESTER_REQUIRED", "Identify the workspace member requesting this transfer."
        )
    saved = await one(
        conn,
        """
        INSERT INTO st.transfer_approvals(workspace_id,id,key_id,requester_id,intent,fingerprint,revision,expires_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,clock_timestamp()+interval '24 hours')
        RETURNING expires_at
    """,
        (
            tenant,
            transfer.request_id,
            key_id,
            transfer.requester_id,
            intent,
            fingerprint,
            policy["version"],
        ),
    )
    return "pending", saved["expires_at"]


async def approvals_for_workspace(conn, tenant, version):
    return await rows(
        conn,
        """
        SELECT a.id,a.requester_id,a.intent,a.expires_at,k.label AS source,
          (SELECT name FROM st.case_members() WHERE id=a.requester_id) AS requester,
          (SELECT name FROM st.case_members() WHERE id=a.reviewer_id) AS reviewer,
          CASE WHEN a.state IN ('pending','approved') AND a.expires_at<=clock_timestamp() THEN 'Expired'
               WHEN a.state IN ('pending','approved') AND a.revision<>%s THEN 'Policy changed'
               ELSE initcap(a.state) END AS status
        FROM st.transfer_approvals a JOIN st.keys k ON k.workspace_id=a.workspace_id AND k.id=a.key_id
        WHERE a.workspace_id=%s ORDER BY
          (a.state='pending' AND a.expires_at>clock_timestamp() AND a.revision=%s) DESC,
          a.created_at DESC,a.id DESC LIMIT 25
    """,
        (version, tenant, version),
    )


@router.post("/api/v1/workspaces/{slug}/protection/approvals/{transfer_id}/{action}")
async def review_approval(
    request: Request, slug: str, transfer_id: UUID, action: Literal["approve", "deny"]
):
    await rate(request, "transfer-review", 30)
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        tenant, principal = member["id"], identity["principal_id"]
        # Lock policy first, matching the authorization path.
        policy = await one(
            conn,
            "SELECT version,mode FROM st.protection_policy WHERE workspace_id=%s FOR SHARE",
            (tenant,),
        )
        transfer = await one(
            conn,
            """
            SELECT requester_id,reviewer_id,revision,state,expires_at<=clock_timestamp() AS expired
            FROM st.transfer_approvals WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            (tenant, transfer_id),
        )
        if not transfer:
            raise unavailable()
        if transfer["requester_id"] == principal:
            raise Issue(
                403,
                "INDEPENDENT_APPROVAL",
                "Another workspace administrator must review this transfer.",
            )
        state = "approved" if action == "approve" else "denied"
        message = "Transfer approved." if action == "approve" else "Transfer denied."
        if transfer["state"] == state and transfer["reviewer_id"] == principal:
            return {"message": message}
        if (
            transfer["state"] != "pending"
            or transfer["expired"]
            or not policy
            or (transfer["revision"] != policy["version"] or policy["mode"] != "active")
        ):
            raise Issue(
                409,
                "APPROVAL_CHANGED",
                "This request is no longer ready for review. Refresh to see its status.",
            )
        await conn.execute(
            """
            UPDATE st.transfer_approvals SET state=%s,reviewer_id=%s WHERE workspace_id=%s AND id=%s
        """,
            (state, principal, tenant, transfer_id),
        )
        await log_action(conn, member, f"Sensitive transfer {state}", str(transfer_id))
    return {"message": message}

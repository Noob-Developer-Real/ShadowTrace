"""Authenticated and revocable delivery of a private cloud object version."""

import hashlib
from datetime import timedelta
from uuid import UUID

import anyio
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Request
from fastapi.responses import Response

from .cloud_storage import MAX_BYTES
from .console import log_action
from .db import connection, one, rows
from .web import Issue, unavailable, verify_csrf, workspace

router = APIRouter()


async def create_link(conn, tenant, transfer, decided_at):
    await conn.execute(
        """
        INSERT INTO st.managed_links(workspace_id,id,recipient_id,object_version,expires_at)
        VALUES (%s,%s,%s,%s,%s)
    """,
        (
            tenant,
            transfer.request_id,
            transfer.recipient_id,
            transfer.object_version,
            decided_at + timedelta(minutes=transfer.link_minutes),
        ),
    )


async def links_for_workspace(conn, tenant):
    return await rows(
        conn,
        """
        SELECT l.id,l.expires_at,l.recipient_id,d.destination,d.actor_id,d.record_count,
          (SELECT name FROM st.case_members() WHERE id=l.recipient_id) AS recipient,
          CASE WHEN l.revoked_at IS NOT NULL THEN 'Revoked'
            WHEN l.expires_at<=clock_timestamp() THEN 'Expired'
            WHEN p.mode IS DISTINCT FROM 'active' OR NOT (d.destination=ANY(p.destinations))
              OR d.record_count>p.share_limit THEN 'Withheld by policy'
            ELSE 'Active' END AS status
        FROM st.managed_links l JOIN st.protection_decisions d
          ON d.workspace_id=l.workspace_id AND d.request_id=l.id
        LEFT JOIN st.protection_policy p ON p.workspace_id=l.workspace_id
        WHERE l.workspace_id=%s ORDER BY d.decided_at DESC,l.id DESC LIMIT 25
    """,
        (tenant,),
    )


async def available_link(conn, member, identity, link_id, lock=False):
    return await one(
        conn,
        """
        SELECT l.object_version,d.content_sha256
        FROM st.managed_links l JOIN st.protection_decisions d
          ON d.workspace_id=l.workspace_id AND d.request_id=l.id
        JOIN st.protection_policy p ON p.workspace_id=l.workspace_id
        WHERE l.workspace_id=%s AND l.id=%s AND l.recipient_id=%s
          AND l.revoked_at IS NULL AND l.expires_at>clock_timestamp()
          AND p.mode='active' AND d.destination=ANY(p.destinations) AND d.record_count<=p.share_limit
    """
        + (" FOR SHARE OF l,p" if lock else ""),
        (member["id"], link_id, identity["principal_id"]),
    )


@router.get("/w/{slug}/protection/links/{link_id}")
async def download_link(request: Request, slug: str, link_id: UUID):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        link = await available_link(conn, member, identity, link_id)
    if not link:
        raise unavailable()
    storage = request.app.state.share_storage
    if storage is None:
        raise Issue(503, "STORAGE_UNAVAILABLE", "Private share storage is unavailable.")
    try:
        with anyio.fail_after(8):
            data = await anyio.to_thread.run_sync(
                storage.read,
                member["id"],
                link_id,
                link["object_version"],
                limiter=request.app.state.share_limiter,
            )
    except (BotoCoreError, ClientError, OSError, ValueError, KeyError, TimeoutError):
        raise Issue(503, "STORAGE_UNAVAILABLE", "The shared file could not be retrieved.") from None
    if not 0 < len(data) <= MAX_BYTES or hashlib.sha256(data).hexdigest() != link["content_sha256"]:
        raise Issue(409, "CONTENT_MISMATCH", "The shared file could not be verified.")
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        if not await available_link(conn, member, identity, link_id, lock=True):
            raise unavailable()
        await log_action(conn, member, "Managed link download", str(link_id))
    return Response(
        data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="shadowtrace-transfer.bin"'},
    )


@router.post("/api/v1/workspaces/{slug}/protection/links/{link_id}/revoke")
async def revoke_link(request: Request, slug: str, link_id: UUID):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        link = await one(
            conn,
            """
            SELECT revoked_at FROM st.managed_links WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            (member["id"], link_id),
        )
        if not link:
            raise unavailable()
        if link["revoked_at"] is None:
            await conn.execute(
                """
                UPDATE st.managed_links SET revoked_at=clock_timestamp() WHERE workspace_id=%s AND id=%s
            """,
                (member["id"], link_id),
            )
            await log_action(conn, member, "Managed link revoked", str(link_id))
    return {"message": "Cloud link revoked."}

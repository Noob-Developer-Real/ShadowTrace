"""Loopback-only source fixtures for scheduled releases and managed links."""

from datetime import UTC, datetime
from io import BytesIO
from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Request

from .config import LOOPBACK
from .console import parsed
from .db import connection, one
from .enforce import ApprovalRequired, ReleaseDenied, release_protected
from .protection import REASONS
from .schema import Payload
from .transfer_intent import occurrence_id
from .web import rate, unavailable, verify_csrf, workspace

router = APIRouter()
DATA = b"record\n" + b"".join(f"synthetic-{i}\n".encode() for i in range(1, 13))


class ManagedDemo(Payload):
    operation: UUID
    variant: Literal["scheduled", "cloud"]
    recipient: UUID | None = None
    sensitive: bool = False
    nominal_day: str


@router.post("/api/v1/workspaces/{slug}/demo-managed")
async def run_managed(request: Request, slug: str):
    config = request.app.state.config
    if not config.demo or not request.client or request.client.host not in LOOPBACK:
        raise unavailable()
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        form = await parsed(request, ManagedDemo, "Choose a demo transfer and recipient.")
        key = getattr(request.app.state, "demo_protection_keys", {}).get(slug)
        if not key:
            raise unavailable()
        if form.variant == "cloud":
            recipient = await one(
                conn, "SELECT id FROM st.case_members() WHERE id=%s", (form.recipient,)
            )
            if not recipient:
                raise unavailable()
    await rate(request, "demo-managed", 15, identity=str(member["id"]))
    operation = form.operation
    actor = f"demo-{operation.hex[:16]}"
    if form.variant == "scheduled":
        try:
            when = datetime.strptime(form.nominal_day, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            raise unavailable() from None
        if abs((datetime.now(UTC) - when).total_seconds()) > 2 * 86400:
            raise unavailable()
        schedule = f"nightly-customers-{operation.hex[:8]}"
        operation = occurrence_id(schedule, when)
        intent = {
            "channel": "scheduled",
            "schedule_id": schedule,
            "scheduled": {"occurred_at": when.isoformat()},
            "sensitive": form.sensitive,
        }
        action = "export"
    else:
        action = "share"
        intent = {
            "channel": "cloud_link",
            "requester_id": str(identity["principal_id"]),
            "recipient_id": str(form.recipient),
            "object_version": "synthetic-v1",
            "link_minutes": 30,
            "sensitive": form.sensitive,
        }
        request.app.state.share_storage.put(member["id"], operation, "synthetic-v1", DATA)
    try:
        async with httpx.AsyncClient(base_url=config.origin, trust_env=False) as source:
            with BytesIO() as output:
                await release_protected(
                    source,
                    credential=key,
                    request_id=operation,
                    actor_id=actor,
                    action=action,
                    resource_type="customer",
                    record_count=12,
                    destination="approved-partner",
                    content=DATA,
                    intent=intent,
                    release=lambda _, payload: output.write(payload),
                )
                count = output.tell()
    except ApprovalRequired:
        return {
            "message": "Waiting for independent approval. Open the review queue, then retry this sample.",
            "status": "pending",
            "reference": str(operation),
        }
    except ReleaseDenied as error:
        label = REASONS.get(error.reason, "Transfer already checked or unavailable")
        return {
            "message": f"{label}. No new release.",
            "status": "withheld",
            "reference": str(operation),
        }
    return {
        "message": f"Scheduled export delivered {count} bytes."
        if action == "export"
        else "Recipient-bound cloud link created.",
        "status": "allowed",
        "reference": str(operation),
        "path": f"/w/{slug}/protection/links/{operation}" if action == "share" else None,
    }

"""Reference connector for releasing an immutable payload at a trusted source."""

import hashlib
import inspect
import time
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

import httpx


class ReleaseDenied(Exception):
    """The source must withhold the staged payload."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ApprovalRequired(ReleaseDenied):
    def __init__(self, request_id: UUID):
        super().__init__("approval_required")
        self.request_id = request_id


async def release_protected(
    client: httpx.AsyncClient,
    *,
    credential: str,
    request_id: UUID,
    actor_id: str,
    action: str,
    resource_type: str,
    record_count: int,
    destination: str,
    content: bytes,
    release: Callable[[str, bytes], object],
    intent: dict | None = None,
    expected_link_path: str | None = None,
):
    """Check immediately before release. Use a private TLS-verified client with a trusted base URL.

    The caller binds request_id to its durable operation and owns routing, user authorization,
    classification, canonical bytes and any delivery idempotency. Never pass a client-supplied URL.
    """
    if not isinstance(content, bytes):
        raise TypeError("Stage immutable bytes before requesting authorization.")
    origin = client.base_url
    local = origin.scheme == "http" and origin.host in {"localhost", "127.0.0.1", "::1"}
    if (
        not (origin.scheme == "https" or local)
        or origin.userinfo
        or origin.query
        or origin.fragment
        or origin.path != "/"
    ):
        raise ReleaseDenied("authorization_unavailable")
    content_hash = hashlib.sha256(content).hexdigest()
    started = time.monotonic()
    try:
        response = await client.post(
            "/api/v1/protection/authorize",
            json=(intent or {})
            | {
                "request_id": str(request_id),
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "record_count": record_count,
                "destination": destination,
                "content_sha256": content_hash,
            },
            headers={"Authorization": f"Bearer {credential}"},
            follow_redirects=False,
            timeout=3,
        )
        if response.status_code == 202:
            pending = response.json()
            if (
                isinstance(pending, dict)
                and pending.get("request_id") == str(request_id)
                and pending.get("outcome") == "pending"
            ):
                raise ApprovalRequired(request_id)
            raise ReleaseDenied("authorization_invalid")
        if response.status_code == 409:
            raise ReleaseDenied("operation_already_checked")
        if response.status_code != 201:
            raise ReleaseDenied("authorization_unavailable")
        decision = response.json()
        if not isinstance(decision, dict) or (
            decision.get("request_id") != str(request_id)
            or decision.get("content_sha256") != content_hash
            or time.monotonic() - started >= 5
        ):
            raise ReleaseDenied("authorization_invalid")
        decided_at = datetime.fromisoformat(decision["decided_at"])
        if abs((datetime.now(UTC) - decided_at).total_seconds()) >= 15:
            raise ReleaseDenied("authorization_stale")
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        raise ReleaseDenied("authorization_unavailable") from None
    if decision.get("outcome") != "allowed" or decision.get("reason") != "allowed":
        raise ReleaseDenied(
            decision.get("reason")
            if decision.get("reason")
            in ("paused", "destination", "disabled", "limit", "cumulative", "approval_denied")
            else "authorization_invalid"
        )
    if expected_link_path is not None and decision.get("link_path") != expected_link_path:
        raise ReleaseDenied("authorization_invalid")
    result = release(destination, content)
    if inspect.isawaitable(result):
        result = await result
    return result

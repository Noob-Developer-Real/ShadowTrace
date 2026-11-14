import asyncio
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import psycopg
import pytest

from shadowtrace.enforce import ReleaseDenied, release_protected
from shadowtrace.ops import purge

from .test_product import login
from .test_response import auth, create


def transfer(**fields):
    return {
        "request_id": str(uuid4()),
        "actor_id": "staff-42",
        "action": "export",
        "resource_type": "customer",
        "record_count": 12,
        "destination": "approved-partner",
        "content_sha256": "a" * 64,
    } | fields


def test_active_protection_and_workspace_boundaries(client, database):
    key = create(client, label="Release checks", purpose="protection")
    rotated = create(client, label="Replacement checks", purpose="protection")
    wrong = create(client, label="Audit only")
    endpoint = "/api/v1/protection/authorize"
    policy_endpoint = "/api/v1/workspaces/northwind/protection/policy"
    page = "/w/northwind/protection"
    assert client.post(endpoint, headers=auth(wrong), json=transfer()).status_code == 403

    def check(**fields):
        result = client.post(endpoint, headers=auth(key), json=transfer(**fields))
        assert result.status_code == 201, result.text
        return result.json()

    default = check()
    assert default["outcome"] == "blocked" and default["reason"] == "paused"
    admin = login(client, "northwind-admin")
    policy = {
        "version": 0,
        "mode": "active",
        "export_limit": 12,
        "download_limit": 8,
        "share_limit": 0,
        "destinations": ["approved-partner"],
    }
    assert (
        client.post(policy_endpoint, headers=admin, json=policy | {"destinations": []}).status_code
        == 422
    )
    assert (
        client.post(policy_endpoint, headers={"Origin": admin["Origin"]}, json=policy).status_code
        == 403
    )
    assert client.post(policy_endpoint, headers=admin, json=policy).json()["version"] == 1
    assert client.post(policy_endpoint, headers=admin, json=policy).status_code == 409
    assert check()["outcome"] == "allowed"
    assert check(record_count=13)["reason"] == "limit"
    assert check(action="download", record_count=8)["outcome"] == "allowed"
    assert check(action="download", record_count=9)["reason"] == "limit"
    assert check(action="share", record_count=8)["reason"] == "disabled"
    assert check(destination="personal-drive")["reason"] == "destination"
    entry = transfer()
    with ThreadPoolExecutor(max_workers=4) as workers:
        result = list(
            workers.map(
                lambda _: client.post(endpoint, headers=auth(key), json=entry).status_code, range(4)
            )
        )
    assert sorted(result) == [201, 409, 409, 409]
    assert client.post(endpoint, headers=auth(rotated), json=entry).status_code == 409
    assert (
        client.post(endpoint, headers=auth(key), json=transfer(raw_ids=["do-not-send"])).status_code
        == 422
    )
    assert (
        client.post(
            policy_endpoint, headers=admin, json=policy | {"version": 1, "mode": "paused"}
        ).status_code
        == 200
    )
    assert check()["reason"] == "paused"
    assert "Protection policy saved" in client.get("/w/northwind/settings/audit").text

    member = login(client, "northwind-analyst")
    assert client.post(policy_endpoint, headers=member, json=policy).status_code == 404
    history = client.get(page + "?outcome=blocked&action=download")
    assert history.status_code == 200
    assert "Record limit exceeded" in history.text and "personal-drive" not in history.text
    login(client, "harbor-analyst")
    assert client.get(page).status_code == 404
    assert entry["request_id"] not in client.get(page.replace("northwind", "harbor")).text

    with psycopg.connect(database[1]) as conn:
        assert conn.execute("SELECT count(*) FROM st.protection_decisions").fetchone() == (0,)
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.protection_decisions SET decided_at=now()-interval '31 days' WHERE request_id=%s",
            (entry["request_id"],),
        )
        purge(conn)
        assert conn.execute(
            "SELECT count(*) FROM st.protection_decisions WHERE request_id=%s",
            (entry["request_id"],),
        ).fetchone() == (0,)


def test_reference_connector_enforces_live_decisions(client):
    key = create(client, label="Reference connector", purpose="protection")
    admin = login(client, "northwind-admin")
    route = "/api/v1/workspaces/northwind/protection/policy"
    url = "/w/northwind/protection"
    page = client.get(url).text
    version = int(re.search(r'data-version="(\d+)"', page)[1])
    assert (
        client.post(
            route,
            headers=admin,
            json={
                "version": version,
                "mode": "active",
                "export_limit": 12,
                "download_limit": 8,
                "share_limit": 4,
                "destinations": ["approved-partner"],
            },
        ).status_code
        == 200
    )
    calls = []
    data = b"source-staged artifact"
    request_id = uuid4()

    async def release(destination, content):
        calls.append((destination, content))
        return len(content)

    async def attempt(transport, **override):
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8787", trust_env=False
        ) as connection:
            parameters = {
                "credential": key["key"],
                "request_id": request_id,
                "actor_id": "staff-42",
                "action": "export",
                "resource_type": "customer",
                "record_count": 12,
                "destination": "approved-partner",
                "content": data,
                "release": release,
            } | override
            return await release_protected(connection, **parameters)

    def forward(request):
        response = client.post(request.url.path, headers=request.headers, content=request.content)
        return httpx.Response(response.status_code, content=response.content)

    def fail(request):
        raise httpx.ConnectError("fixture timeout", request=request)

    def unbound(request):
        return httpx.Response(
            201,
            json={"request_id": str(request_id), "content_sha256": "f" * 64, "outcome": "allowed"},
        )

    def stale(request):
        return httpx.Response(
            201,
            json={
                "request_id": str(request_id),
                "content_sha256": hashlib.sha256(data).hexdigest(),
                "outcome": "allowed",
                "reason": "allowed",
                "decided_at": (datetime.now(UTC) - timedelta(seconds=60)).isoformat(),
            },
        )

    assert asyncio.run(attempt(httpx.MockTransport(forward))) == len(data)
    with pytest.raises(ReleaseDenied, match="operation_already_checked"):
        asyncio.run(attempt(httpx.MockTransport(forward)))
    with pytest.raises(ReleaseDenied, match="destination"):
        asyncio.run(
            attempt(httpx.MockTransport(forward), request_id=uuid4(), destination="personal-drive")
        )
    with pytest.raises(ReleaseDenied, match="authorization_unavailable"):
        asyncio.run(attempt(httpx.MockTransport(fail), request_id=uuid4()))
    with pytest.raises(ReleaseDenied, match="authorization_invalid"):
        asyncio.run(attempt(httpx.MockTransport(unbound)))
    with pytest.raises(ReleaseDenied, match="authorization_stale"):
        asyncio.run(attempt(httpx.MockTransport(stale)))
    assert calls == [("approved-partner", data)]

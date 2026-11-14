import secrets
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from shadowtrace.config import Settings
from shadowtrace.integrity import valid
from shadowtrace.main import create_app
from shadowtrace.ops import remove

from .conftest import ISSUER, PROD
from .conftest import database as shared_database
from .test_product import case_for, create_key, event, login, send

# These tests remove memberships and assert exact counts, so each owns its fixture data.
database = pytest.fixture(scope="function")(shared_database.__wrapped__)


def test_ownership_disposition_and_evidence(client, database):
    token = create_key(client)
    entry = event("export", 700)
    assert send(client, token["key"], entry).status_code == 201
    [(case_id, _, initial)] = case_for(database, entry["actor_id"])
    with psycopg.connect(database[0]) as conn:
        users = dict(conn.execute("SELECT subject,id FROM st.principals WHERE issuer='demo'"))
    member = login(client, "northwind-analyst")
    route = f"/api/v1/workspaces/northwind/cases/{case_id}"
    assert (
        client.post(
            route + "/owner",
            headers=member,
            json={
                "version": initial,
                "assignee_id": str(users["harbor-analyst"]),
            },
        ).status_code
        == 422
    )
    owner_data = {"version": initial, "assignee_id": str(users["northwind-analyst"])}
    owner = client.post(route + "/owner", headers=member, json=owner_data)
    assert owner.json()["version"] == initial + 1
    assert (
        client.post(route + "/owner", headers=member, json=owner_data).json()["version"]
        == initial + 1
    )
    assert (
        client.post(
            route + "/owner", headers=member, json=owner_data | {"assignee_id": None}
        ).status_code
        == 409
    )
    assert entry["actor_id"] in client.get("/w/northwind/cases?owner=me").text
    decision = {
        "version": initial + 1,
        "mutation_id": str(uuid4()),
        "status": "resolved",
        "note": "Reviewed export.",
        "disposition": "approved",
    }
    assert client.post(route + "/reviews", headers=member, json=decision).status_code == 201
    assert client.post(route + "/reviews", headers=member, json=decision).json()["replayed"]
    assert (
        client.post(
            route + "/reviews", headers=member, json=decision | {"disposition": "other"}
        ).status_code
        == 409
    )

    download = client.post(route + "/evidence", headers=member, json={})
    assert download.status_code == 200
    assert download.headers["content-disposition"].endswith('.json"')
    bundle = download.json()
    assert valid(bundle)
    assert bundle["evidence"]["case"]["assignee"] == "Northwind Analyst"
    assert bundle["evidence"]["reviews"][0]["disposition"] == "approved"
    bundle["evidence"]["events"][0]["records_accessed"] = 50
    assert not valid(bundle)

    with psycopg.connect(database[0]) as conn:
        remove(conn, "northwind", "demo", "northwind-analyst")
        assert conn.execute(
            "SELECT assignee_id FROM st.cases WHERE id=%s", (case_id,)
        ).fetchone() == (None,)
    harbor = login(client, "harbor-analyst")
    assert client.post(route + "/evidence", headers=harbor, json={}).status_code == 404
    assert client.get(f"/w/harbor/actors/id-{entry['actor_id']}").status_code == 404


def test_replay_and_delivery_health(client, database):
    token = create_key(client)
    actor = "replay-" + uuid4().hex[:8]
    first, last = event(count=260, actor=actor), event(count=360, actor=actor)
    for data in (first, last, event("export", 570, actor)):
        assert send(client, token["key"], data).status_code == 201
    assert send(client, token["key"], first).status_code == 200
    assert send(client, token["key"], first | {"actor_id": "conflict"}).status_code == 409
    assert send(client, token["key"], first | {"records_accessed": 0}).status_code == 422
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT accepted,replayed,rejected,throttled FROM st.ingest_health WHERE key_id=%s",
            (token["id"],),
        ).fetchone() == (3, 1, 2, 0)
        version = conn.execute(
            "SELECT version FROM st.policy p JOIN st.workspaces w ON w.id=p.workspace_id WHERE w.slug='northwind'"
        ).fetchone()[0]
    headers = login(client, "northwind-admin")
    response = client.post(
        "/api/v1/workspaces/northwind/rules/replay",
        headers=headers,
        json={
            "version": version,
            "view_limit": 1000,
            "export_limit": 1000,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["evaluated"] == 3
    assert data["counts"]["view"]["removed"] == 1 and data["counts"]["export"]["removed"] == 1
    assert {item["observed"] for item in data["changes"]} == {570, 620}
    assert "Integration health" in client.get("/w/northwind/settings/integration").text
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT version FROM st.policy p JOIN st.workspaces w ON w.id=p.workspace_id WHERE w.slug='northwind'"
        ).fetchone() == (version,)
        assert len(case_for(database, actor)) == 1
    analyst = login(client, "harbor-analyst")
    assert (
        client.post(
            "/api/v1/workspaces/northwind/rules/replay", headers=analyst, json={}
        ).status_code
        == 404
    )
    assert "Integration health" not in client.get("/w/harbor/settings/integration").text


def test_baseline_and_demo_replay_are_scoped(client, database, monkeypatch):
    token = create_key(client)
    client.app.state.demo_keys = {"northwind": token["key"]}
    to_api = httpx.AsyncClient

    def mock_internal(**options):
        assert options.get("trust_env") is False
        return to_api(transport=httpx.ASGITransport(app=client.app, client=("127.0.0.1", 43211)))

    from shadowtrace import demo_flow

    monkeypatch.setattr(demo_flow.httpx, "AsyncClient", mock_internal)
    north = login(client, "northwind-analyst")
    run_id = str(uuid4())
    payload = {
        "run_id": run_id,
        "scenario": "incident",
        "started_at": datetime.now(UTC).isoformat(),
    }
    route = "/api/v1/workspaces/northwind/demo"
    result = client.post(route, headers=north, json=payload)
    assert result.status_code == 200, result.text
    case_url = result.json()["case"]
    assert result.json()["accepted"] == 3 and case_url.startswith("/w/northwind/cases/")
    assert "12 windows across 3 UTC days" in client.get(case_url).text
    assert "18.2×" in client.get(case_url).text
    actor_url = f"/w/northwind/actors/id-support-{UUID(run_id).hex[:12]}"
    assert client.get(actor_url).status_code == 200
    repeat = client.post(route, headers=north, json=payload).json()
    assert repeat == {"accepted": 0, "replayed": 3, "case": case_url}
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT count(*) FROM st.events WHERE actor_id=%s",
            ("support-" + UUID(run_id).hex[:12],),
        ).fetchone() == (15,)
    harbor = login(client, "harbor-analyst")
    assert client.post(route, headers=harbor, json=payload).status_code == 404
    assert client.get(actor_url.replace("northwind", "harbor")).status_code == 404


def test_production_excludes_demo_route(database):
    config = Settings(
        "production", PROD, database[1], secrets.token_urlsafe(48), ISSUER, "id", "secret"
    )
    with TestClient(create_app(config), base_url=PROD) as client:
        assert client.post("/api/v1/workspaces/northwind/demo", json={}).status_code == 404


def test_supported_actor_ids_survive_links(client):
    key = create_key(client)["key"]
    entry = event(actor="..", count=20)
    assert send(client, key, entry).status_code == 201
    login(client, "northwind-analyst")
    assert "/w/northwind/actors/id-.." in client.get("/w/northwind/activity").text
    assert client.get("/w/northwind/actors/id-..").status_code == 200
    assert client.get("/w/northwind/actors/id-missing").status_code == 404

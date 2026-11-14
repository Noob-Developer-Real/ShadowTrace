import base64
import hashlib
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, parse_qsl, urlsplit
from uuid import uuid4

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from shadowtrace.config import Settings
from shadowtrace.main import create_app
from shadowtrace.ops import migrate, purge, remove

from .conftest import ISSUER, ORIGIN, PROD


def login(http, name):
    response = http.post(
        "/auth/demo", json={"identity": name}, headers={"Origin": ORIGIN}, follow_redirects=False
    )
    assert response.status_code == 303
    page = http.get(response.headers["location"])
    assert page.status_code == 200
    return {
        "Origin": ORIGIN,
        "X-CSRF-Token": re.search(r'name="csrf-token" content="([^"]+)"', page.text)[1],
    }


def create_key(http):
    headers = login(http, "northwind-admin")
    response = http.post(
        "/api/v1/workspaces/northwind/keys",
        headers=headers,
        json={"label": f"test-{uuid4().hex[:12]}"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def event(action="view", count=260, actor=None):
    return {
        "event_id": str(uuid4()),
        "actor_id": actor or f"actor-{uuid4().hex[:8]}",
        "action": action,
        "resource_type": "customer",
        "records_accessed": count,
        "occurred_at": datetime.now(UTC).isoformat(),
        "outcome": "success",
    }


def send(http, key, entry):
    return http.post("/api/v1/events", headers={"Authorization": f"Bearer {key}"}, json=entry)


def case_for(database, actor):
    with psycopg.connect(database[0]) as conn:
        return conn.execute(
            "SELECT id,severity,version FROM st.cases WHERE actor_id=%s", (actor,)
        ).fetchall()


def test_normal_traffic_creates_no_case(client, database):
    key = create_key(client)["key"]
    normal = event(count=20)
    assert send(client, key, normal).status_code == 201
    assert case_for(database, normal["actor_id"]) == []


def test_concurrent_correlation_and_immutable_receipt(client, database):
    key = create_key(client)["key"]
    actor = event()["actor_id"]
    first, second, export = (
        event(actor=actor),
        event(count=360, actor=actor),
        event("export", 570, actor),
    )
    with ThreadPoolExecutor(max_workers=5) as workers:
        results = list(
            workers.map(
                lambda entry: send(client, key, entry), [first, second, export, first, first]
            )
        )
    assert sorted(r.status_code for r in results) == [200, 200, 201, 201, 201]
    replay = send(client, key, first)
    assert replay.json()["replayed"] is True
    assert set(replay.json()) == {"event_id", "accepted_at", "replayed"}
    conflict = send(client, key, {**first, "records_accessed": 261})
    assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "EVENT_ID_CONFLICT"
    [(case_id, severity, _)] = case_for(database, actor)
    assert severity == "critical"
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT rule,observed FROM st.signals WHERE case_id=%s ORDER BY rule", (case_id,)
        ).fetchall() == [("large_export", 570), ("view_burst", 620)]
        assert conn.execute(
            "SELECT count(*) FROM st.evidence WHERE case_id=%s", (case_id,)
        ).fetchone() == (3,)


def test_invalid_ingest_rejected_without_data(client, database):
    key = create_key(client)["key"]
    valid = event()
    for change in (
        {"tenant_id": "harbor"},
        {"records_accessed": True},
        {"outcome": "failure"},
        {"resource_type": "raw"},
        {"occurred_at": (datetime.now(UTC) - timedelta(days=8)).isoformat()},
    ):
        assert send(client, key, valid | change).status_code == 422
    assert send(client, "bad", valid).status_code == 401
    assert (
        client.post(
            "/api/v1/events", content=b"x" * 90000, headers={"Authorization": f"Bearer {key}"}
        ).status_code
        == 413
    )
    invalid = client.post(
        "/api/v1/events",
        content='{"event_id":"a","event_id":"b"}',
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    assert invalid.status_code == 400
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT count(*) FROM st.events WHERE event_id=%s", (valid["event_id"],)
        ).fetchone() == (0,)


def test_key_permissions_revocation_and_csrf(client):
    token = create_key(client)
    key = token["key"]
    viewer = login(client, "northwind-analyst")
    route = "/api/v1/workspaces/northwind/keys"
    assert client.post(route, headers=viewer, json={"label": "Prohibited"}).status_code == 404
    admin = login(client, "northwind-admin")
    assert (
        client.post(
            route,
            headers=admin | {"Origin": "https://foreign.example"},
            json={"label": "Prohibited"},
        ).status_code
        == 403
    )
    assert (
        client.post(route, headers={"Origin": ORIGIN}, json={"label": "Prohibited"}).status_code
        == 403
    )
    assert key not in client.get("/w/northwind/settings/integration").text
    for _ in range(2):
        assert client.post(f"{route}/{token['id']}/revoke", headers=admin).status_code == 200
    assert send(client, key, event()).status_code == 401


def test_case_review_replay_stale_and_cross_tenant(client, database):
    key = create_key(client)["key"]
    entry = event("export", 600)
    assert send(client, key, entry).status_code == 201
    [(case_id, _, version)] = case_for(database, entry["actor_id"])
    path = f"/w/northwind/cases/{case_id}"
    route = f"/api/v1/workspaces/northwind/cases/{case_id}/reviews"
    north = login(client, "northwind-analyst")
    data = {
        "version": version,
        "mutation_id": str(uuid4()),
        "status": "resolved",
        "note": "Approved ticket.",
    }
    assert client.post(route, headers=north, json=data | {"note": ""}).status_code == 422
    assert client.post(route, headers=north, json=data).status_code == 201
    assert client.post(route, headers=north, json=data).json()["replayed"] is True
    assert client.post(route, headers=north, json=data | {"note": "changed"}).status_code == 409
    stale = client.post(route, headers=north, json=data | {"mutation_id": str(uuid4())})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "STALE_CASE"
    assert client.get(path).text.count("Approved ticket.") == 1
    harbor = login(client, "harbor-analyst")
    assert client.get(path).status_code == 404
    assert client.get(f"/w/harbor/cases/{case_id}").status_code == 404
    assert client.post(route, headers=harbor, json=data).status_code == 404
    assert (
        client.post(route.replace("northwind", "harbor"), headers=harbor, json=data).status_code
        == 404
    )


def test_rules_and_audit_are_scoped(client):
    viewer = login(client, "northwind-analyst")
    route = "/api/v1/workspaces/northwind/rules"
    assert client.get("/w/northwind/settings/audit").status_code == 404
    assert client.post(route, headers=viewer, json={}).status_code == 404
    admin = login(client, "northwind-admin")
    version = int(
        re.search(r'data-revision="(\d+)"', client.get("/w/northwind/settings/rules").text)[1]
    )
    data = {"version": version, "view_limit": 500, "export_limit": 500}
    assert client.post(route, headers=admin, json=data | {"view_limit": 0}).status_code == 422
    assert client.post(route, headers=admin, json=data).json()["version"] == version + 1
    assert client.post(route, headers=admin, json=data).status_code == 409
    assert "Detection rules updated" in client.get("/w/northwind/settings/audit").text


def test_database_isolation_applies_without_explicit_where_clause(client, database):
    key = create_key(client)["key"]
    entry = event("export", 600)
    assert send(client, key, entry).status_code == 201
    with psycopg.connect(database[0]) as db:
        ids = dict(db.execute("SELECT slug,id FROM st.workspaces").fetchall())
    with psycopg.connect(database[1], autocommit=True) as conn:
        assert conn.execute("SELECT count(*) FROM st.events").fetchone() == (0,)
        with conn.transaction():
            conn.execute("SELECT set_config('st.tenant_id',%s,true)", (str(ids["northwind"]),))
            assert conn.execute("SELECT DISTINCT workspace_id FROM st.events").fetchall() == [
                (ids["northwind"],)
            ]
            with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
                conn.execute(
                    """
                    INSERT INTO st.cases(workspace_id,actor_id,resource_type,severity,opened_at,latest_at)
                    VALUES (%s,'foreign','customer','critical',now(),now())
                """,
                    (ids["harbor"],),
                )
        assert conn.execute("SELECT count(*) FROM st.cases").fetchone() == (0,)


def test_expired_and_revoked_memberships(client, database):
    login(client, "northwind-analyst")
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.sessions SET last_seen=now()-interval '35 minutes' WHERE principal_id=(SELECT id FROM st.principals WHERE subject='northwind-analyst')"
        )
    denied = client.get("/w/northwind", follow_redirects=False)
    assert denied.status_code == 303 and denied.headers["location"].startswith("/sign-in")
    login(client, "harbor-analyst")
    with psycopg.connect(database[0]) as conn:
        remove(conn, "harbor", "demo", "harbor-analyst")
    assert client.get("/w/harbor").status_code == 404


def test_pagination_and_tenant_bound_cursor(client):
    key = create_key(client)["key"]
    for _ in range(30):
        assert send(client, key, event(count=3)).status_code == 201
    first = client.get("/w/northwind/activity").text
    assert first.count("<tr>") == 26
    cursor = re.search(r'href="(\?cursor=[^"]+)">Next', first)[1]
    following = client.get("/w/northwind/activity" + cursor)
    assert following.status_code == 200 and ">Previous<" in following.text
    assert client.get("/w/northwind/activity" + cursor + "&action=export").status_code == 400


def test_retention_and_repeatable_migrations(client, database):
    key = create_key(client)["key"]
    entry = event("export", 600)
    assert send(client, key, entry).status_code == 201
    with psycopg.connect(database[0]) as conn:
        migrate(conn)
        conn.execute(
            "UPDATE st.events SET received_at=now()-interval '31 days' WHERE event_id=%s",
            (entry["event_id"],),
        )
        conn.execute(
            "UPDATE st.cases SET latest_at=now()-interval '31 days' WHERE actor_id=%s",
            (entry["actor_id"],),
        )
        purge(conn)
        assert conn.execute(
            "SELECT count(*) FROM st.events WHERE event_id=%s", (entry["event_id"],)
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM st.cases WHERE actor_id=%s", (entry["actor_id"],)
        ).fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM st.events").fetchone()[0] > 0


def test_production_guards_and_oidc_signed_callback(database):
    config = Settings(
        "production",
        PROD,
        database[1],
        secrets.token_urlsafe(48),
        ISSUER,
        "trace-client",
        "test-client-secret",
    )
    with pytest.raises(ValueError):
        Settings(
            "production",
            "http://trace.example.test",
            database[1],
            config.secret,
            ISSUER,
            "client",
            "secret",
        ).validate()
    app = create_app(config)
    signing = RSAKey.generate_key(2048, private=True, parameters={"kid": "test-signing"})
    state = {}
    token_requests = []

    def provider(request):
        path = request.url.path
        if path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [signing.as_dict(private=False)]})
        assert path == "/token"
        form = dict(parse_qsl(request.content.decode()))
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest())
            .decode()
            .rstrip("=")
        )
        assert challenge == state["code_challenge"]
        token_requests.append(form["code"])
        claims = {
            "iss": ISSUER,
            "sub": "licensed-user",
            "aud": "trace-client",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "nonce": state["nonce"] if form["code"] == "valid" else "wrong",
        }
        token = jwt.encode({"alg": "RS256", "kid": "test-signing"}, claims, signing)
        return httpx.Response(
            200,
            json={
                "token_type": "Bearer",
                "access_token": "fixture-access-token",
                "id_token": token,
            },
        )

    app.state.oauth.client_kwargs["transport"] = httpx.MockTransport(provider)
    with TestClient(app, base_url=PROD) as http:
        assert http.post("/auth/demo", json={"identity": "northwind-admin"}).status_code == 404
        assert http.get("/w/northwind", follow_redirects=False).status_code == 303
        assert http.get(PROD.replace("https:", "http:") + "/sign-in").status_code == 400

        def begin():
            response = http.get("/auth/sso", follow_redirects=False)
            assert response.status_code == 302
            state.update(
                {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}
            )
            cookie = response.cookies.get("__Host-st_oidc")
            stored = base64.b64decode(cookie.split(".")[0]).decode()
            assert "code_verifier" not in stored and state["nonce"] not in stored
            return cookie

        begin()
        bad = http.get(
            "/auth/callback",
            params={"state": state["state"], "code": "bad"},
            follow_redirects=False,
        )
        assert bad.headers["location"].startswith("/sign-in?error=interrupted")
        copied = begin()
        good = http.get(
            "/auth/callback",
            params={"state": state["state"], "code": "valid"},
            follow_redirects=False,
        )
        assert good.headers["location"] == "/w/northwind"
        session_cookie = next(
            v for v in good.headers.get_list("set-cookie") if v.startswith("__Host-st_session")
        )
        assert "Secure" in session_cookie and "HttpOnly" in session_cookie
        page = http.get("/w/northwind")
        assert page.status_code == 200 and "SSO Analyst" in page.text
        http.cookies.set("__Host-st_oidc", copied, domain="trace.example.test", path="/")
        replay = http.get(
            "/auth/callback",
            params={"state": state["state"], "code": "valid"},
            follow_redirects=False,
        )
        assert replay.headers["location"].startswith("/sign-in?error=interrupted")
        assert token_requests == ["bad", "valid"]

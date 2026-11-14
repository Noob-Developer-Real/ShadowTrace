import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg

from shadowtrace.db import digest
from shadowtrace.fingerprints import record_fingerprint
from shadowtrace.integrity import valid
from shadowtrace.ops import purge
from shadowtrace.schema import Event

from .test_product import case_for, create_key, event, login, send


def receipt_key(client, label="Receiving integration"):
    headers = login(client, "northwind-admin")
    response = client.post(
        "/api/v1/workspaces/northwind/keys",
        headers=headers,
        json={"label": label, "purpose": "receipts"},
    )
    assert response.status_code == 201, response.text
    return response.json()["key"]


def submit(client, key, body):
    return client.post("/api/v1/receipts", headers={"Authorization": f"Bearer {key}"}, json=body)


def test_record_overlap_receipts_and_coverage(client, database):
    source = create_key(client)["key"]
    destination = receipt_key(client)
    other = receipt_key(client, label="Secondary connector")
    epoch = uuid4()
    secret = b"s" * 32
    ids = [
        record_fingerprint(secret, "northwind", epoch, "customer", f"private-id-{index}")
        for index in range(7)
    ]
    now = datetime.now(UTC)
    actor = "lineage-" + uuid4().hex[:10]

    def tagged(action, indexes, seconds, *, actor_id=actor, token_set=epoch, count=None):
        payload = event(action, count or len(indexes), actor_id)
        payload["occurred_at"] = (now + timedelta(seconds=seconds)).isoformat()
        payload["lineage"] = {
            "token_set": str(token_set),
            "fingerprints": [ids[i] for i in indexes],
        }
        return payload

    for payload in (
        tagged("view", (0, 1), -35),
        tagged("view", (1, 2), -25),
        tagged("view", (3,), -15, actor_id="different-actor"),
        tagged("view", (3,), -15, token_set=uuid4()),
        tagged("view", (3,), -5),
    ):
        response = send(client, source, payload)
        assert response.status_code == 201, response.text
    export = tagged("export", (0, 1, 2, 3, 4), -10, count=570)
    assert send(client, source, export).status_code == 201
    assert send(client, source, export).json()["replayed"]
    assert send(client, source, export | {"lineage": None}).status_code == 409
    assert send(client, source, tagged("view", (0, 0), -4)).status_code == 422
    assert send(client, source, tagged("view", (0, 1), -4, count=1)).status_code == 422

    base = {
        "receipt_id": str(uuid4()),
        "export_id": export["event_id"],
        "destination": "destination-a",
        "token_set": str(epoch),
        "fingerprints": [ids[i] for i in (0, 3, 5)],
        "occurred_at": now.isoformat(),
    }
    assert submit(client, source, base).json()["error"]["code"] == "WRONG_KEY_PURPOSE"
    assert send(client, destination, export).json()["error"]["code"] == "WRONG_KEY_PURPOSE"
    assert submit(client, destination, base | {"token_set": str(uuid4())}).status_code == 422
    assert submit(client, destination, base | {"export_id": "missing"}).status_code == 404
    before_export = (now - timedelta(seconds=15)).isoformat()
    assert submit(client, destination, base | {"occurred_at": before_export}).status_code == 422
    accepted = submit(client, destination, base)
    assert accepted.status_code == 201, accepted.text
    assert set(accepted.json()) == {"receipt_id", "accepted_at", "replayed"}
    duplicate = submit(client, destination, base | {"fingerprints": base["fingerprints"][::-1]})
    assert duplicate.status_code == 200 and duplicate.json()["replayed"]
    assert submit(client, other, base).status_code == 409
    assert submit(client, destination, base | {"destination": "altered"}).status_code == 409
    followup = base | {
        "receipt_id": str(uuid4()),
        "destination": "destination-b",
        "fingerprints": [ids[i] for i in (0, 2)],
    }
    assert submit(client, other, followup).status_code == 201

    analyst = login(client, "northwind-analyst")
    [(case_id, _, _)] = case_for(database, actor)
    path = f"/w/northwind/exports/id-{export['event_id']}"
    screen = client.get(path)
    assert screen.status_code == 200
    assert "Count-only export" not in screen.text and "1 outside export manifest" in screen.text
    downloaded = client.post(
        f"/api/v1/workspaces/northwind/cases/{case_id}/evidence", headers=analyst, json={}
    )
    assert downloaded.status_code == 200, downloaded.text
    assert valid(downloaded.json())
    [trace] = downloaded.json()["evidence"]["record_lineage"]
    assert not any(mark in downloaded.text or mark in screen.text for mark in ids)
    assert (
        trace["manifest_count"],
        trace["viewed"],
        trace["received"],
        trace["all_stages"],
        trace["unobserved"],
        trace["untagged"],
        trace["matching_views"],
        trace["reported_receipts"],
    ) == (5, 3, 3, 2, 2, 565, 2, 2)

    harbor = "st_demo_" + secrets.token_urlsafe(32)
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            """
            INSERT INTO st.keys(workspace_id,label,prefix,digest,purpose)
            SELECT id,'Harbor receiver',%s,%s,'receipts' FROM st.workspaces WHERE slug='harbor'
            """,
            (harbor[:15], digest(harbor)),
        )
    login(client, "harbor-analyst")
    assert submit(client, harbor, base | {"receipt_id": str(uuid4())}).status_code == 404
    assert client.get(path).status_code == 404
    assert client.get(path.replace("/northwind/", "/harbor/")).status_code == 404

    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.events SET received_at=now()-interval '31 days' WHERE event_id=%s",
            (export["event_id"],),
        )
        purge(conn)
        assert conn.execute(
            "SELECT count(*) FROM st.destination_receipts WHERE export_id=%s", (export["event_id"],)
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM st.event_manifests WHERE event_id=%s", (export["event_id"],)
        ).fetchone() == (0,)


def test_record_pseudonyms_are_scoped_and_legacy_replay_survives(client, database):
    secret = b"s" * 32
    epoch = uuid4()
    token = record_fingerprint(secret, "northwind", epoch, "customer", "48")
    assert token == record_fingerprint(secret, "northwind", epoch, "customer", "48")
    assert (
        len(
            {
                token,
                record_fingerprint(secret, "harbor", epoch, "customer", "48"),
                record_fingerprint(secret, "northwind", epoch, "order", "48"),
                record_fingerprint(secret, "northwind", uuid4(), "customer", "48"),
                record_fingerprint(b"k" * 32, "northwind", epoch, "customer", "48"),
            }
        )
        == 5
    )

    # Compare to the 1.1 serialization contract, including normalized UTC.
    key = create_key(client)["key"]
    before = event("export", 10)
    accepted = send(client, key, before)
    assert accepted.status_code == 201
    normalized = Event.model_validate(before).model_dump(
        mode="json",
        include={
            "event_id",
            "actor_id",
            "action",
            "resource_type",
            "records_accessed",
            "occurred_at",
            "outcome",
        },
    )
    expected = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT fingerprint FROM st.events WHERE event_id=%s", (before["event_id"],)
        ).fetchone() == (expected,)
    assert send(client, key, before).json()["replayed"]
    assert client.get(f"/w/northwind/exports/id-{before['event_id']}").status_code == 200
    assert "Count-only export" in client.get(f"/w/northwind/exports/id-{before['event_id']}").text

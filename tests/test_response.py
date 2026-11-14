from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shadowtrace.fingerprints import record_fingerprint
from shadowtrace.integrity import valid
from shadowtrace.receipt_proof import sign_receipt
from shadowtrace.resolve_impact import resolve_records

from .test_lineage import submit
from .test_product import case_for, event, login, send


def create(client, **body):
    admin = login(client, "northwind-admin")
    result = client.post("/api/v1/workspaces/northwind/keys", headers=admin, json=body)
    assert result.status_code == 201, result.text
    return result.json()


def auth(key):
    return {"Authorization": f"Bearer {key['key']}"}


def setup_export(client):
    source = create(client, label=f"Source {uuid4()}")
    signer = Ed25519PrivateKey.generate()
    destination = create(
        client,
        label=f"Signed {uuid4()}",
        purpose="receipts",
        destination="receiving",
        signing_public_key=signer.public_key().public_bytes_raw().hex(),
    )
    when = datetime.now(UTC)
    token_set = uuid4()
    fingerprints = [
        record_fingerprint(b"s" * 32, "northwind", token_set, "customer", ident)
        for ident in ("local-alpha", "local-beta", "local-gamma")
    ]
    export = event("export", 530) | {
        "artifact_sha256": "a" * 64,
        "lineage": {"token_set": str(token_set), "fingerprints": fingerprints},
        "expected_destination": "receiving",
        "receipt_due_minutes": 1,
        "occurred_at": (when - timedelta(seconds=1)).isoformat(),
    }
    assert send(client, source["key"], export).status_code == 201
    receipt = {
        "receipt_id": str(uuid4()),
        "export_id": export["event_id"],
        "destination": "receiving",
        "occurred_at": when.isoformat(),
        "token_set": str(token_set),
        "fingerprints": fingerprints[:2],
        "artifact_sha256": "a" * 64,
    }
    return source, destination, signer, export, receipt


def proof(signer, receipt, tenant="northwind"):
    return receipt | {"signature": sign_receipt(signer, tenant, receipt)}


def test_signed_receipt_followup_and_fresh_review(client, database):
    _source, destination, signer, export, receipt = setup_export(client)
    assert (
        submit(
            client, destination["key"], {k: v for k, v in receipt.items() if k != "artifact_sha256"}
        ).json()["error"]["code"]
        == "SIGNING_KEY_REQUIRED"
    )
    assert (
        submit(client, destination["key"], proof(signer, receipt, "harbor")).json()["error"]["code"]
        == "INVALID_SIGNATURE"
    )
    signed = proof(signer, receipt)
    forged = signed | {"fingerprints": receipt["fingerprints"][:1]}
    assert submit(client, destination["key"], forged).status_code == 422
    assert (
        submit(
            client, destination["key"], proof(signer, receipt | {"destination": "unexpected"})
        ).status_code
        == 422
    )
    [(case, _, version)] = case_for(database, export["actor_id"])
    member = login(client, "northwind-analyst")
    queue = "/w/northwind/cases/follow-up"
    path = f"/w/northwind/exports/id-{export['event_id']}"
    review = f"/api/v1/workspaces/northwind/cases/{case}/reviews"

    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.event_manifests SET receipt_due_at=now()-interval '1 second' WHERE event_id=%s",
            (export["event_id"],),
        )
    assert "Receipt overdue" in client.get(queue).text
    close = {
        "version": version,
        "mutation_id": str(uuid4()),
        "status": "resolved",
        "note": "Deadline reviewed.",
        "disposition": "other",
    }
    assert client.post(review, headers=member, json=close).status_code == 201
    assert export["event_id"] not in client.get(queue).text
    assert export["event_id"] in client.get(queue + "?state=reviewed").text

    response = submit(client, destination["key"], signed)
    assert response.status_code == 201, response.text
    assert submit(
        client,
        destination["key"],
        signed | {"fingerprints": list(reversed(receipt["fingerprints"]))},
    ).json()["replayed"]
    followups = client.get(queue)
    assert followups.status_code == 200 and export["event_id"] in followups.text
    assert "Receipt arrived late" in followups.text and "Review case" in followups.text
    stale = close | {
        "version": version + 1,
        "mutation_id": str(uuid4()),
        "note": "This view is stale.",
    }
    assert client.post(review, headers=member, json=stale).json()["error"]["code"] == "STALE_CASE"

    mismatch = receipt | {"receipt_id": str(uuid4()), "artifact_sha256": "b" * 64}
    alternate = create(
        client,
        label=f"Alternate {uuid4()}",
        purpose="receipts",
        destination="other",
        signing_public_key=signer.public_key().public_bytes_raw().hex(),
    )
    assert (
        submit(
            client, alternate["key"], proof(signer, mismatch | {"destination": "other"})
        ).status_code
        == 201
    )
    member = login(client, "northwind-analyst")
    assert export["event_id"] in client.get(queue + "?reason=unexpected").text
    assert export["event_id"] in client.get(queue + "?reason=different").text
    page = client.get(path)
    assert "Same file" in page.text and "Different file" in page.text
    bundle = client.post(review.replace("/reviews", "/evidence"), headers=member, json={}).json()
    assert valid(bundle)
    assert {
        report["file_comparison"] for report in bundle["evidence"]["record_lineage"][0]["receipts"]
    } == {"same", "different"}
    assert "local-alpha" not in page.text

    store = "/api/v1/workspaces/northwind/follow-up/filters"
    assert (
        client.post(
            store, headers=member, json={"reason": "unexpected", "state": "all", "owner": "me"}
        ).status_code
        == 200
    )
    saved = client.get(queue).text
    assert 'value="unexpected" selected' in saved and 'value="me" checked' in saved
    login(client, "northwind-admin")
    assert 'value="unexpected" selected' not in client.get(queue).text
    login(client, "harbor-analyst")
    assert client.get(path).status_code == 404
    assert client.get(queue).status_code == 404


def test_impact_guardrails_and_local_resolution(client, database):
    source, destination, signer, export, receipt = setup_export(client)
    unrelated = create(client, label=f"Other {uuid4()}")
    impact = create(
        client, label=f"Resolver {uuid4()}", purpose="impact", source_key_id=source["id"]
    )
    wrong = create(
        client, label=f"Wrong resolver {uuid4()}", purpose="impact", source_key_id=unrelated["id"]
    )
    assert submit(client, destination["key"], proof(signer, receipt)).status_code == 201
    member = login(client, "northwind-analyst")
    trace = f"/w/northwind/exports/id-{export['event_id']}"
    path = f"/api/v1/workspaces/northwind/exports/id-{export['event_id']}/impact"
    job = str(uuid4())
    form = {"request_id": job, "scope": "received", "reason": "notification", "ticket": "INC-0042"}
    result = client.post(path, headers=member, json=form)
    assert result.status_code == 201, result.text
    assert client.post(path, headers=member, json=form).status_code == 200
    assert client.post(path, headers=member, json=form | {"ticket": "INC-0043"}).status_code == 409
    connector = f"/api/v1/impact-jobs/{job}"
    actions = f"/api/v1/workspaces/northwind/impact/{job}"
    assert client.get(connector, headers=auth(impact)).status_code == 404
    assert client.post(actions + "/approve", headers=member, json={}).status_code == 404
    admin = login(client, "northwind-admin")
    assert client.post(actions + "/approve", headers=admin, json={}).status_code == 200
    assert client.get(connector, headers=auth(wrong)).status_code == 404
    assert client.get(connector, headers=auth(source)).status_code == 403
    pulled = client.get(connector, headers=auth(impact))
    assert pulled.status_code == 200, pulled.text
    snapshot = pulled.json()
    assert set(snapshot["fingerprints"]) == set(receipt["fingerprints"])
    local = resolve_records(
        b"s" * 32,
        "northwind",
        UUID(snapshot["token_set"]),
        snapshot["fingerprints"],
        ["local-alpha", "irrelevant", "local-alpha", "local-gamma"],
    )
    assert local == ["local-alpha"]
    complete = connector + "/complete"
    assert client.post(complete, headers=auth(impact), json={"matched_count": 3}).status_code == 422
    assert (
        client.post(
            complete, headers=auth(impact), json={"matched_count": 1, "raw_ids": local}
        ).status_code
        == 422
    )
    assert client.post(complete, headers=auth(impact), json={"matched_count": 1}).json() == {
        "replayed": False
    }
    assert client.post(complete, headers=auth(impact), json={"matched_count": 1}).json() == {
        "replayed": True
    }
    assert client.post(complete, headers=auth(impact), json={"matched_count": 0}).status_code == 409
    assert client.get(connector, headers=auth(impact)).status_code == 404
    page = client.get(trace).text
    assert "1 resolved at source" in page and "INC-0042" in page
    assert "local-alpha" not in page and snapshot["fingerprints"][0] not in page

    own = str(uuid4())
    assert (
        client.post(
            path, headers=admin, json=form | {"request_id": own, "scope": "export"}
        ).status_code
        == 201
    )
    self_approve = f"/api/v1/workspaces/northwind/impact/{own}/approve"
    assert (
        client.post(self_approve, headers=admin, json={}).json()["error"]["code"]
        == "INDEPENDENT_APPROVAL"
    )
    assert (
        client.post(self_approve.replace("/approve", "/cancel"), headers=admin, json={}).status_code
        == 200
    )
    expired = str(uuid4())
    member = login(client, "northwind-analyst")
    assert (
        client.post(
            path, headers=member, json=form | {"request_id": expired, "scope": "export"}
        ).status_code
        == 201
    )
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.impact_requests SET expires_at=now()-interval '1 second' WHERE id=%s",
            (expired,),
        )
    admin = login(client, "northwind-admin")
    assert (
        client.post(self_approve.replace(own, expired), headers=admin, json={}).status_code == 409
    )
    audit = client.get("/w/northwind/settings/audit").text
    assert all(
        action in audit
        for action in (
            "Impact lookup requested",
            "Impact lookup approved",
            "Impact snapshot delivered",
            "Impact lookup completed",
        )
    )


def test_below_threshold_export_can_enter_case_workflow(client, database):
    source = create(client, label=f"Manual source {uuid4()}")
    export = event("export", 1) | {
        "expected_destination": "receiving",
        "lineage": {"token_set": str(uuid4()), "fingerprints": ["a" * 64]},
    }
    assert send(client, source["key"], export).status_code == 201
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.event_manifests SET receipt_due_at=now()-interval '1 second' WHERE event_id=%s",
            (export["event_id"],),
        )
    member = login(client, "northwind-analyst")
    queue = client.get("/w/northwind/cases/follow-up?reason=overdue")
    assert export["event_id"] in queue.text
    route = f"/api/v1/workspaces/northwind/exports/id-{export['event_id']}/case"
    opened = client.post(route, headers=member, json={})
    assert opened.status_code == 201
    location = opened.json()["location"]
    assert client.post(route, headers=member, json={}).json()["location"] == location
    assert "An analyst opened this case" in client.get(location).text
    assert len(case_for(database, export["actor_id"])) == 1

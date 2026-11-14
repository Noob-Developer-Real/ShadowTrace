import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import uuid4

import boto3
import psycopg
from botocore.response import StreamingBody
from botocore.stub import Stubber

from shadowtrace.cloud_storage import S3Storage, object_key
from shadowtrace.scheduled_export import atomic_delivery, read_csv
from shadowtrace.transfer_intent import occurrence_id

from .test_product import login
from .test_protection import transfer
from .test_response import auth, create

BASE = "/api/v1/workspaces/northwind/protection"
AUTHORIZE = "/api/v1/protection/authorize"


def policy(client, **updates):
    admin = login(client, "northwind-admin")
    page = client.get("/w/northwind/protection").text
    version = int(re.search(r'data-version="(\d+)"', page)[1])
    result = client.post(
        BASE + "/policy",
        headers=admin,
        json={
            "version": version,
            "mode": "active",
            "export_limit": 100,
            "download_limit": 100,
            "share_limit": 100,
            "destinations": ["approved-partner"],
            "approval_threshold": 0,
            "cumulative_limit": 0,
        }
        | updates,
    )
    assert result.status_code == 200, result.text
    return admin


def ids(database):
    with psycopg.connect(database[0]) as conn:
        people = dict(conn.execute("SELECT subject,id FROM st.principals"))
        tenant = conn.execute("SELECT id FROM st.workspaces WHERE slug='northwind'").fetchone()[0]
    return people, tenant


def test_schedule_and_independent_approval(client, database, tmp_path):
    source = create(client, label="Schedule fixture", purpose="protection")
    admin = policy(client, approval_threshold=12)
    instant = datetime.now(UTC).replace(microsecond=0)
    identifier = occurrence_id("nightly-customers", instant)
    assert occurrence_id("nightly-customers", instant.astimezone(UTC)) == identifier
    assert occurrence_id("nightly-customers", instant + timedelta(days=1)) != identifier
    body = transfer(
        request_id=str(identifier),
        channel="scheduled",
        schedule_id="nightly-customers",
        scheduled={"occurred_at": instant.isoformat()},
    )
    assert (
        client.post(
            AUTHORIZE, headers=auth(source), json=body | {"request_id": str(uuid4())}
        ).status_code
        == 422
    )
    result = client.post(AUTHORIZE, headers=auth(source), json=body)
    assert result.status_code == 202, result.text
    assert client.post(AUTHORIZE, headers=auth(source), json=body).json()["outcome"] == "pending"
    assert (
        client.post(
            AUTHORIZE, headers=auth(source), json=body | {"content_sha256": "f" * 64}
        ).status_code
        == 409
    )
    review = f"{BASE}/approvals/{identifier}"
    assert client.post(review + "/approve", headers=admin, json={}).status_code == 200
    assert client.post(AUTHORIZE, headers=auth(source), json=body).json()["outcome"] == "allowed"
    assert client.post(AUTHORIZE, headers=auth(source), json=body).status_code == 409
    assert "nightly-customers" in client.get("/w/northwind/protection").text

    _, tenant = ids(database)
    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT state FROM st.transfer_approvals WHERE workspace_id=%s AND id=%s",
            (tenant, identifier),
        ).fetchone() == ("consumed",)

    staged = tmp_path / "source.csv"
    staged.write_bytes(b'customer,name\n1,"one\ncontinued"\n2,two\n')
    payload, count = read_csv(staged)
    assert count == 2
    output = tmp_path / f"{identifier}.csv"
    atomic_delivery(output, payload)
    assert output.read_bytes() == payload
    assert output.stat().st_mode & 0o777 == 0o600


def test_approval_bounds_and_denial(client, database):
    source = create(client, label="Approval fixture", purpose="protection")
    admin = policy(client, approval_threshold=1)
    people, _ = ids(database)
    no_identity = transfer()
    assert (
        client.post(AUTHORIZE, headers=auth(source), json=no_identity).json()["error"]["code"]
        == "REQUESTER_REQUIRED"
    )
    foreign = transfer(requester_id=str(people["harbor-analyst"]))
    assert (
        client.post(AUTHORIZE, headers=auth(source), json=foreign).json()["error"]["code"]
        == "INVALID_PARTY"
    )
    own = transfer(requester_id=str(people["northwind-admin"]))
    assert client.post(AUTHORIZE, headers=auth(source), json=own).status_code == 202
    review = f"{BASE}/approvals/{own['request_id']}/approve"
    assert (
        client.post(review, headers=admin, json={}).json()["error"]["code"]
        == "INDEPENDENT_APPROVAL"
    )
    analyst = login(client, "northwind-analyst")
    assert client.post(review, headers=analyst, json={}).status_code == 404
    admin = login(client, "northwind-admin")
    other = transfer(requester_id=str(people["northwind-analyst"]))
    assert client.post(AUTHORIZE, headers=auth(source), json=other).status_code == 202
    denied = f"{BASE}/approvals/{other['request_id']}/deny"
    assert client.post(denied, headers=admin, json={}).status_code == 200
    assert (
        client.post(AUTHORIZE, headers=auth(source), json=other).json()["reason"]
        == "approval_denied"
    )
    expired = transfer(requester_id=str(people["northwind-analyst"]))
    assert client.post(AUTHORIZE, headers=auth(source), json=expired).status_code == 202
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.transfer_approvals SET expires_at=now()-interval '1 second' WHERE id=%s",
            (expired["request_id"],),
        )
    assert (
        client.post(
            f"{BASE}/approvals/{expired['request_id']}/approve", headers=admin, json={}
        ).status_code
        == 409
    )
    assert client.post(AUTHORIZE, headers=auth(source), json=expired).status_code == 409
    policy(client, approval_threshold=0)
    assert client.post(AUTHORIZE, headers=auth(source), json=own).status_code == 409


def test_rolling_budget_serializes_multiple_credentials(client, database):
    source = create(client, label="Budget source one", purpose="protection")
    alternate = create(client, label="Budget source two", purpose="protection")
    policy(client, cumulative_limit=20, destinations=["approved-partner", "internal-vault"])
    actor = "budget-actor"
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [
            pool.submit(
                client.post,
                AUTHORIZE,
                headers=auth(key),
                json=transfer(
                    actor_id=actor, record_count=12, action=action, destination=destination
                ),
            )
            for key, action, destination in [
                (source, "export", "approved-partner"),
                (alternate, "download", "internal-vault"),
            ]
        ]
    assert sorted(task.result().json()["reason"] for task in tasks) == ["allowed", "cumulative"]
    assert (
        client.post(
            AUTHORIZE,
            headers=auth(alternate),
            json=transfer(
                actor_id=actor,
                record_count=8,
                action="share",
            ),
        ).json()["outcome"]
        == "allowed"
    )
    assert (
        client.post(
            AUTHORIZE, headers=auth(source), json=transfer(actor_id=actor, record_count=1)
        ).json()["reason"]
        == "cumulative"
    )
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.protection_decisions SET decided_at=now()-interval '25 hours' WHERE actor_id=%s",
            (actor,),
        )
    assert (
        client.post(
            AUTHORIZE, headers=auth(source), json=transfer(actor_id=actor, record_count=12)
        ).json()["outcome"]
        == "allowed"
    )


def test_managed_link_recipient_pinning_expiry_and_revocation(client, database):
    source = create(client, label="Cloud link source", purpose="protection")
    admin = policy(client)
    people, tenant = ids(database)
    data = b"private synthetic content"

    def issue(**changes):
        body = (
            transfer(
                channel="cloud_link",
                action="share",
                requester_id=str(people["northwind-admin"]),
                recipient_id=str(people["northwind-analyst"]),
                object_version="v1",
                link_minutes=5,
                content_sha256=hashlib.sha256(data).hexdigest(),
            )
            | changes
        )
        op = body["request_id"]
        client.app.state.share_storage.put(tenant, op, "v1", data)
        client.app.state.share_storage.put(tenant, op, "v2", b"unapproved substitution")
        response = client.post(AUTHORIZE, headers=auth(source), json=body)
        return op, response

    _, foreign = issue(recipient_id=str(people["harbor-analyst"]))
    assert foreign.status_code == 422
    _, unversioned = issue(object_version="null")
    assert unversioned.status_code == 422
    identifier, response = issue()
    assert response.status_code == 201, response.text
    path = response.json()["link_path"]
    assert client.get(path).status_code == 404
    login(client, "harbor-analyst")
    assert client.get(path).status_code == 404
    login(client, "northwind-analyst")
    download = client.get(path)
    assert download.content == data and "attachment" in download.headers["Content-Disposition"]
    assert download.headers["Cache-Control"] == "no-store"
    client.app.state.share_storage.put(tenant, identifier, "v1", b"same-version corruption")
    assert client.get(path).status_code == 409
    client.app.state.share_storage.put(tenant, identifier, "v1", data)
    admin = login(client, "northwind-admin")
    revoke = f"{BASE}/links/{identifier}/revoke"
    assert client.post(revoke, headers=admin, json={}).status_code == 200
    assert client.post(revoke, headers=admin, json={}).status_code == 200
    login(client, "northwind-analyst")
    assert client.get(path).status_code == 404
    expired, response = issue()
    with psycopg.connect(database[0]) as conn:
        conn.execute(
            "UPDATE st.managed_links SET expires_at=now()-interval '1 second' WHERE id=%s",
            (expired,),
        )
    assert client.get(response.json()["link_path"]).status_code == 404


def test_s3_adapter_requests_exact_private_object_version():
    client = boto3.client(
        "s3", region_name="us-east-1", aws_access_key_id="fixture", aws_secret_access_key="fixture"
    )
    tenant, operation = uuid4(), uuid4()
    data = b"stubbed S3 object"
    with Stubber(client) as stub:
        stub.add_response(
            "get_object",
            {"Body": StreamingBody(BytesIO(data), len(data)), "ContentLength": len(data)},
            {
                "Bucket": "fixture-bucket",
                "Key": object_key(tenant, operation),
                "VersionId": "known-version",
            },
        )
        assert S3Storage("fixture-bucket", client).read(tenant, operation, "known-version") == data
        stub.assert_no_pending_responses()

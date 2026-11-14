from datetime import timedelta
from uuid import uuid4

from fastapi import APIRouter, Request

from .db import connection, one, rows
from .impact import REASONS, SCOPES, impact_history
from .receipt_proof import PROOF_LABELS
from .web import render, unavailable, workspace

router = APIRouter()
VIEW_LIMIT = 500
RECEIPT_LIMIT = 50
LOOKBACK_DAYS = 7


async def export_trace(conn, tenant, export_id):
    export = await one(
        conn,
        """
        SELECT e.event_id,e.actor_id,e.resource_type,e.records_accessed,e.occurred_at,e.received_at,
            k.label,m.token_set,m.fingerprints,m.artifact_sha256,m.expected_destination,m.receipt_due_at
        FROM st.events e JOIN st.keys k ON k.workspace_id=e.workspace_id AND k.id=e.key_id
        LEFT JOIN st.event_manifests m ON m.workspace_id=e.workspace_id AND m.event_id=e.event_id
        WHERE e.workspace_id=%s AND e.event_id=%s AND e.action='export' AND e.outcome='success'
    """,
        (tenant, export_id),
    )
    if not export:
        raise unavailable()
    tokens = set(export.pop("fingerprints") or ())
    token_set = export.pop("token_set")
    export["token_set"] = token_set
    view_rows = []
    receipt_rows = []
    if tokens:
        view_rows = await rows(
            conn,
            """
            SELECT e.event_id,e.occurred_at,k.label,
              ARRAY(SELECT unnest(m.fingerprints) INTERSECT SELECT unnest(%s::text[])) AS matches
            FROM st.events e JOIN st.event_manifests m USING(workspace_id,event_id)
            JOIN st.keys k ON k.workspace_id=e.workspace_id AND k.id=e.key_id
            WHERE e.workspace_id=%s AND e.actor_id=%s AND e.resource_type=%s
              AND e.action='view' AND e.outcome='success' AND m.token_set=%s
              AND e.occurred_at >= %s AND e.occurred_at < %s
              AND e.received_at >= %s
            ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT %s
        """,
            (
                list(tokens),
                tenant,
                export["actor_id"],
                export["resource_type"],
                token_set,
                export["occurred_at"] - timedelta(days=LOOKBACK_DAYS),
                export["occurred_at"],
                export["occurred_at"] - timedelta(days=LOOKBACK_DAYS + 1),
                VIEW_LIMIT + 1,
            ),
        )
        receipt_rows = await rows(
            conn,
            """
            SELECT r.receipt_id,r.destination,r.occurred_at,r.received_at,k.label,
              r.artifact_sha256,r.file_comparison,r.manifest_sha256,r.signature,r.findings,k.signing_public_key,
              cardinality(r.fingerprints) AS submitted,
              ARRAY(SELECT unnest(r.fingerprints) INTERSECT SELECT unnest(%s::text[])) AS matches
            FROM st.destination_receipts r JOIN st.keys k ON k.workspace_id=r.workspace_id AND k.id=r.key_id
            WHERE r.workspace_id=%s AND r.export_id=%s ORDER BY r.occurred_at DESC,r.receipt_id DESC LIMIT %s
        """,
            (list(tokens), tenant, export_id, RECEIPT_LIMIT + 1),
        )
    viewed = set()
    received = set()
    same_file = set()
    signed_reports = 0
    views = []
    receipts = []
    for item in view_rows[:VIEW_LIMIT]:
        matches = item.pop("matches")
        if matches:
            viewed.update(matches)
            views.append(item | {"matched": len(matches)})
    for item in receipt_rows[:RECEIPT_LIMIT]:
        matches = item.pop("matches")
        received.update(matches)
        if item["signature"]:
            signed_reports += 1
        if item["file_comparison"] == "same":
            same_file.update(matches)
        item["proof_label"] = PROOF_LABELS[item["file_comparison"]]
        receipts.append(
            item | {"matched": len(matches), "outside_manifest": item["submitted"] - len(matches)}
        )
    return {
        "export": export,
        "lookback_days": LOOKBACK_DAYS,
        "manifest_count": len(tokens),
        "viewed": len(viewed),
        "received": len(received),
        "same_file_matches": len(same_file),
        "signed_reports": signed_reports,
        "all_stages": len(viewed & received),
        "unobserved": len(tokens - received),
        "untagged": export["records_accessed"] - len(tokens),
        "views": views[:10],
        "receipts": receipts[:10],
        "matching_views": len(views),
        "reported_receipts": len(receipts),
        "views_capped": len(view_rows) > VIEW_LIMIT,
        "receipts_capped": len(receipt_rows) > RECEIPT_LIMIT,
    }


@router.get("/w/{slug}/exports/id-{export_id}")
async def record_lineage(request: Request, slug: str, export_id: str):
    async with connection(request) as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        member, identity = await workspace(request, conn, slug)
        trace = await export_trace(conn, member["id"], export_id)
        cases = await rows(
            conn,
            """
            SELECT c.id,c.severity,c.actor_id,c.status FROM st.evidence a JOIN st.cases c
               ON c.workspace_id=a.workspace_id AND c.id=a.case_id
            WHERE a.workspace_id=%s AND a.event_id=%s ORDER BY c.opened_at DESC,c.id DESC LIMIT 5
        """,
            (member["id"], export_id),
        )
        impact_enabled = trace["export"]["resource_type"] == "customer" and bool(
            cases and trace["manifest_count"]
        )
        impact = await impact_history(conn, member["id"], export_id) if impact_enabled else []
    return render(
        request,
        "lineage",
        title="Record lineage",
        member=member,
        identity=identity,
        trace=trace,
        cases=cases,
        impact_enabled=impact_enabled,
        impact=impact,
        impact_scopes=SCOPES,
        impact_reasons=REASONS,
        impact_request_id=uuid4(),
        demo_resolver=bool(getattr(request.app.state, "demo_impact_keys", {}).get(slug)),
    )

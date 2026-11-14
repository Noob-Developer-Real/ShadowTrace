"""Current export exceptions and the latest case review of each export."""

from typing import Literal

from pydantic import ValidationError

from .db import one
from .schema import Payload
from .web import Issue, read_json

REASONS = {
    "overdue": "Receipt overdue",
    "late": "Receipt arrived late",
    "unexpected": "Unexpected destination",
    "different": "Different file",
    "extra": "Records outside full manifest",
}

# Only monitored exports and signed exceptions enter the queue. A qualifying receipt
# must come from the expected alias and cannot contradict the source's file digest.
QUERY = """
WITH candidates AS (
    SELECT workspace_id,event_id FROM st.event_manifests
     WHERE workspace_id=st.tenant() AND receipt_due_at IS NOT NULL
    UNION
    SELECT workspace_id,export_id FROM st.destination_receipts
     WHERE workspace_id=st.tenant() AND cardinality(findings)>0
)
SELECT * FROM (
  SELECT m.workspace_id,m.event_id,e.actor_id,e.resource_type,e.records_accessed,
    m.expected_destination,m.receipt_due_at,c.case_id,c.status,c.assignee_id,c.assignee,
    notices.reasons,notices.changed_at,
    coalesce(c.status IN ('resolved','dismissed') AND c.closed_at >= notices.changed_at,false) AS reviewed
  FROM candidates q
  JOIN st.event_manifests m USING(workspace_id,event_id)
  JOIN st.events e USING(workspace_id,event_id)
  LEFT JOIN LATERAL (
    SELECT min(r.received_at) FILTER (WHERE r.signature IS NOT NULL
        AND r.destination=m.expected_destination AND r.file_comparison<>'different') AS first_expected,
      max(r.received_at) FILTER (WHERE cardinality(r.findings)>0) AS last_exception,
      bool_or('unexpected'=ANY(r.findings)) AS unexpected,
      bool_or('different'=ANY(r.findings)) AS different,
      bool_or('extra'=ANY(r.findings)) AS extra
    FROM st.destination_receipts r WHERE r.workspace_id=m.workspace_id AND r.export_id=m.event_id
  ) p ON true
  JOIN LATERAL (
    SELECT array_remove(ARRAY[
        CASE WHEN m.receipt_due_at<=now() AND p.first_expected IS NULL THEN 'overdue' END,
        CASE WHEN p.first_expected>m.receipt_due_at THEN 'late' END,
        CASE WHEN p.unexpected THEN 'unexpected' END,
        CASE WHEN p.different THEN 'different' END,
        CASE WHEN p.extra THEN 'extra' END],NULL) AS reasons,
      greatest(p.last_exception,
        CASE WHEN p.first_expected>m.receipt_due_at THEN p.first_expected END,
        CASE WHEN m.receipt_due_at<=now() AND p.first_expected IS NULL THEN m.receipt_due_at END
      ) AS changed_at
  ) notices ON notices.changed_at IS NOT NULL
  LEFT JOIN LATERAL (
    SELECT c.id AS case_id,c.status,c.assignee_id,
        (SELECT name FROM st.case_members() WHERE id=c.assignee_id) AS assignee,
        v.created_at AS closed_at
    FROM st.evidence l JOIN st.cases c ON c.workspace_id=l.workspace_id AND c.id=l.case_id
    LEFT JOIN LATERAL (
        SELECT created_at FROM st.reviews v
        WHERE v.workspace_id=c.workspace_id AND v.case_id=c.id AND v.status IN ('resolved','dismissed')
        ORDER BY v.created_at DESC LIMIT 1
    ) v ON true
    WHERE l.workspace_id=m.workspace_id AND l.event_id=m.event_id
    ORDER BY c.opened_at DESC,c.id DESC LIMIT 1
  ) c ON true
) queue
"""


class FollowupFilters(Payload):
    reason: Literal["", "overdue", "late", "unexpected", "different", "extra"] = ""
    state: Literal["needs", "reviewed", "all"] = "needs"
    owner: Literal["", "me"] = ""


async def save_filters(request, conn, tenant, principal):
    try:
        filters = FollowupFilters.model_validate(await read_json(request))
    except ValidationError:
        raise Issue(422, "INVALID_FILTER", "Choose available follow-up filters.") from None
    await conn.execute(
        """
        INSERT INTO st.followup_filters(workspace_id,principal_id,reason,state,owner)
        VALUES(%s,%s,%s,%s,%s)
        ON CONFLICT (workspace_id,principal_id) DO UPDATE
          SET reason=excluded.reason,state=excluded.state,owner=excluded.owner
    """,
        (tenant, principal, filters.reason, filters.state, filters.owner),
    )


async def load_filters(conn, tenant, principal):
    return await one(
        conn,
        """
        SELECT reason,state,owner FROM st.followup_filters WHERE workspace_id=%s AND principal_id=%s
    """,
        (tenant, principal),
    )

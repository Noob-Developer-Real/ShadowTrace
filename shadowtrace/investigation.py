from collections import defaultdict, deque
from datetime import timedelta

from .db import one, rows

BASELINE_DAYS = 14
REPLAY_LIMIT = 5000
REPLAY_HOURS = 24
VIEW_WINDOW = timedelta(minutes=5)
DISPOSITIONS = {
    "approved": "Approved activity",
    "policy_violation": "Policy violation",
    "false_positive": "False positive",
    "other": "Other",
}


async def baselines(conn, tenant, actor, cutoff):
    data = await rows(
        conn,
        """
        WITH bounds AS (
          SELECT date_bin(interval '5 minutes',%s::timestamptz,'2000-01-01T00:00:00Z') AS ends
        ), buckets AS (
          SELECT resource_type,sum(records_accessed) AS volume,
             date_bin(interval '5 minutes',received_at,'2000-01-01T00:00:00Z') AS bucket
          FROM st.events CROSS JOIN bounds
          WHERE workspace_id=%s AND actor_id=%s AND action='view' AND outcome='success'
            AND received_at >= ends-make_interval(days=>%s) AND received_at < ends
          GROUP BY resource_type,bucket
        )
        SELECT resource_type,count(*) AS samples,count(DISTINCT (bucket AT TIME ZONE 'UTC')::date) AS days,
          percentile_disc(0.5) WITHIN GROUP(ORDER BY volume) AS typical,
          percentile_disc(0.9) WITHIN GROUP(ORDER BY volume) AS upper
        FROM buckets GROUP BY resource_type
        """,
        (cutoff, tenant, actor, BASELINE_DAYS),
    )
    for item in data:
        item["ready"] = item["samples"] >= 8 and item["days"] >= 3
    return {item["resource_type"]: item for item in data}


async def replay(conn, tenant, current, proposed):
    ends = (await one(conn, "SELECT now() AS ends"))["ends"]
    requested_start = ends - timedelta(hours=REPLAY_HOURS)
    entries = await rows(
        conn,
        """
        SELECT event_id, actor_id, resource_type, action, received_at, records_accessed
        FROM st.events WHERE workspace_id=%s AND outcome='success'
          AND received_at >= %s AND received_at <= %s
        ORDER BY received_at DESC,event_id DESC LIMIT %s
        """,
        (tenant, requested_start - VIEW_WINDOW, ends, REPLAY_LIMIT + 1),
    )
    truncated = len(entries) > REPLAY_LIMIT
    entries = entries[:REPLAY_LIMIT]
    starts = (
        max(requested_start, entries[-1]["received_at"] + VIEW_WINDOW)
        if truncated
        else requested_start
    )
    counts = {
        rule: {"current": 0, "proposed": 0, "added": 0, "removed": 0} for rule in ("view", "export")
    }
    evaluated = 0
    stream = defaultdict(deque)
    totals = defaultdict(int)
    changed = deque(maxlen=8)
    for entry in reversed(entries):
        when = entry["received_at"]
        action = entry["action"]
        observed = entry["records_accessed"]
        if action == "view":
            key = (entry["actor_id"], entry["resource_type"])
            bucket = stream[key]
            while bucket and bucket[0][0] < when - VIEW_WINDOW:
                totals[key] -= bucket.popleft()[1]
            bucket.append((when, observed))
            totals[key] += observed
            observed = totals[key]
        if when < starts:
            continue
        evaluated += 1
        before = observed >= current[f"{action}_limit"]
        after = observed >= proposed[f"{action}_limit"]
        counts[action]["current"] += before
        counts[action]["proposed"] += after
        if before != after:
            difference = "added" if after else "removed"
            counts[action][difference] += 1
            changed.append(
                {
                    "actor": entry["actor_id"],
                    "resource": entry["resource_type"],
                    "action": action,
                    "observed": observed,
                    "change": difference,
                    "event_id": entry["event_id"],
                    "received_at": when.isoformat(),
                }
            )
    return {
        "starts": min(starts, ends).isoformat(),
        "ends": ends.isoformat(),
        "truncated": truncated,
        "evaluated": evaluated,
        "counts": counts,
        "changes": list(reversed(changed)),
    }


def evidence_bundle(case, signals, evidence, reviews, captured, *, traces, traces_omitted):
    from .integrity import seal

    # A newly versioned wire format gives auditors a predictable export contract.
    document = {
        "format": "shadowtrace.evidence.v1",
        "workspace": case["workspace"],
        "captured_at": captured.isoformat(),
        "case": {
            key: value for key, value in case.items() if key not in {"workspace", "assignee_id"}
        },
        "signals": signals[:100],
        "events": evidence[:100],
        "record_lineage": traces,
        "reviews": [
            {key: value for key, value in review.items() if key != "mutation_id"}
            for review in reviews[:50]
        ],
        "omitted": {
            "record_lineage": traces_omitted or len(evidence) > 100,
            "signals": len(signals) > 100,
            "events": len(evidence) > 100,
            "reviews": len(reviews) > 50,
        },
    }
    return seal(document)

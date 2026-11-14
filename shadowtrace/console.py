import json
import re
import secrets
import uuid
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from psycopg import errors, sql
from pydantic import ValidationError

from . import followup
from .db import connection, digest, one, rows
from .impact import impact_history
from .investigation import DISPOSITIONS, VIEW_WINDOW, baselines, evidence_bundle, replay
from .lineage import export_trace
from .schema import IDENT, Assignment, KeyName, Policy, Review, StatusList
from .web import (
    Issue,
    encode_cursor,
    load_cursor,
    memberships,
    rate,
    read_json,
    redirect,
    render,
    session,
    unavailable,
    verify_csrf,
    workspace,
)

router = APIRouter()
SIZE = 25
CASE_COLUMNS = "id,actor_id,resource_type,severity,status,opened_at,latest_at,version,evidence_expired,assignee_id"
EXAMPLE = json.dumps(
    {
        "event_id": "orders-00042",
        "actor_id": "support-014",
        "action": "view",
        "resource_type": "customer",
        "records_accessed": 24,
        "occurred_at": "<current UTC timestamp>",
        "outcome": "success",
    },
    indent=2,
)


@router.get("/workspaces")
async def choices(request: Request):
    async with connection(request) as conn:
        identity = await session(request, conn)
        principal = await one(conn, "SELECT name FROM st.principals WHERE id=st.principal()")
        items = await memberships(conn)
    return render(
        request,
        "workspaces",
        title="Workspaces",
        identity=identity,
        principal=principal,
        items=items,
    )


@router.get("/w/{slug}")
async def overview(request: Request, slug: str):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        stats = await one(
            conn,
            """
            SELECT count(*) FILTER(WHERE status IN ('open','in_review')) AS active,
                count(*) FILTER(WHERE status IN ('open','in_review') AND severity='critical') AS critical
            FROM st.cases WHERE workspace_id=%s
        """,
            (member["id"],),
        )
        summary = await one(
            conn,
            """
            SELECT count(*) AS events, count(DISTINCT actor_id) AS actors, max(received_at) AS fresh
            FROM st.events WHERE workspace_id=%s AND received_at > now()-interval '24 hours'
        """,
            (member["id"],),
        )
        histogram = await rows(
            conn,
            """
            WITH counts AS (
              SELECT date_trunc('hour',received_at,'UTC') AS hour,count(*) AS amount
              FROM st.events WHERE workspace_id=%s AND received_at > now()-interval '24 hours'
              GROUP BY 1
            )
            SELECT series.hour,coalesce(counts.amount,0) AS amount
            FROM generate_series(date_trunc('hour',now(),'UTC')-interval '24 hours',
                                 date_trunc('hour',now(),'UTC'),interval '1 hour') AS series(hour)
            LEFT JOIN counts USING(hour) ORDER BY hour
        """,
            (member["id"],),
        )
        cases = await rows(
            conn,
            f"""
            SELECT {CASE_COLUMNS} FROM st.cases WHERE workspace_id=%s ORDER BY latest_at DESC,id DESC LIMIT 5
        """,
            (member["id"],),
        )
    peak = max((item["amount"] for item in histogram), default=1) or 1
    for item in histogram:
        item["height"] = round(100 * item["amount"] / peak)
    return render(
        request,
        "overview",
        title="Overview",
        member=member,
        identity=identity,
        stats=stats,
        summary=summary,
        histogram=histogram,
        cases=cases,
        peak=peak,
        demo_controls=bool(getattr(request.app.state, "demo_keys", {}).get(slug)),
        demo_lineage=bool(getattr(request.app.state, "demo_receipt_keys", {}).get(slug)),
        demo_protection=bool(getattr(request.app.state, "demo_protection_keys", {}).get(slug)),
    )


def filters(request, options):
    values = {key: request.query_params.get(key, "") for key in options}
    for key, allowed in options.items():
        value = values[key]
        if value and (not re.fullmatch(IDENT, value) if allowed is None else value not in allowed):
            message = (
                "Enter a valid actor ID." if allowed is None else f"Choose an available {key}."
            )
            values[key] = ""
            return values, message
    return values, ""


async def paginate(
    request, conn, member, *, query, clauses, parameters, filter_values, fields, group
):
    scope = digest(json.dumps([str(member["id"]), group, filter_values], sort_keys=True))
    cursor = load_cursor(request, scope, request.query_params.get("cursor"))
    previous = cursor and cursor["direction"] == "previous"
    key_sql = sql.SQL(",").join(sql.SQL(field) for field in fields)
    if cursor:
        boundary = [int(value) if isinstance(value, int) else value for value in cursor["key"]]
        operator = sql.SQL(" > " if previous else " < ")
        placeholders = sql.SQL(",").join(sql.Placeholder() for _ in fields)
        clauses.append(sql.SQL("({}){}({})").format(key_sql, operator, placeholders))
        parameters.extend(boundary)
    order = sql.SQL(",").join(
        sql.SQL(field + (" ASC" if previous else " DESC")) for field in fields
    )
    statement = sql.SQL("{} WHERE {} ORDER BY {} LIMIT {}").format(
        sql.SQL(query),
        sql.SQL(" AND ").join(clauses),
        order,
        sql.Literal(SIZE + 1),
    )
    data = await rows(conn, statement, parameters)
    more = len(data) > SIZE
    data = data[:SIZE]
    if previous:
        data.reverse()

    def link(direction, row):
        boundary = [row[name] for name in fields]
        key = [
            value.isoformat()
            if isinstance(value, datetime)
            else str(value)
            if isinstance(value, uuid.UUID)
            else value
            for value in boundary
        ]
        return "?" + urlencode(
            {
                **{k: v for k, v in filter_values.items() if v},
                "cursor": encode_cursor(request, scope, direction, key),
            }
        )

    earlier = link("previous", data[0]) if data and (more if previous else cursor) else ""
    later = link("next", data[-1]) if data and (cursor if previous else more) else ""
    if cursor and not data:
        earlier = "?" + urlencode({k: v for k, v in filter_values.items() if v})
    return data, earlier, later


@router.get("/w/{slug}/cases")
async def case_list(request: Request, slug: str):
    values, error = filters(
        request,
        {
            "status": StatusList,
            "severity": ("high", "critical"),
            "actor": None,
            "owner": ("me",),
        },
    )
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        clauses, params = [sql.SQL("workspace_id=%s")], [member["id"]]
        for key, column in {
            "status": "status",
            "severity": "severity",
            "actor": "actor_id",
        }.items():
            if values[key]:
                clauses.append(sql.Identifier(column) + sql.SQL("=%s"))
                params.append(values[key])
        if values["owner"]:
            clauses.append(sql.SQL("assignee_id=%s"))
            params.append(identity["principal_id"])
        data, previous, following = await paginate(
            request,
            conn,
            member,
            query=f"""SELECT {CASE_COLUMNS},
                (SELECT name FROM st.case_members() WHERE id=assignee_id) AS assignee
                FROM st.cases""",
            clauses=clauses,
            parameters=params,
            filter_values=values,
            fields=("latest_at", "id"),
            group="cases",
        )
    return render(
        request,
        "cases",
        status=422 if error else 200,
        title="Cases",
        member=member,
        identity=identity,
        cases=data,
        values=values,
        problem=error,
        prev=previous,
        more=following,
    )


@router.get("/w/{slug}/cases/follow-up")
async def followup_queue(request: Request, slug: str):
    options = {"reason": followup.REASONS, "state": ("needs", "reviewed", "all"), "owner": ("me",)}
    values, error = filters(request, options)
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        if not request.url.query:
            saved = await followup.load_filters(conn, member["id"], identity["principal_id"])
            if saved:
                values = saved
        values["state"] = values["state"] or "needs"
        clauses, parameters = [sql.SQL("workspace_id=%s")], [member["id"]]
        if values["state"] != "all":
            clauses.append(sql.SQL("reviewed=%s"))
            parameters.append(values["state"] == "reviewed")
        if values["reason"]:
            clauses.append(sql.SQL("%s=ANY(reasons)"))
            parameters.append(values["reason"])
        if values["owner"]:
            clauses.append(sql.SQL("assignee_id=%s"))
            parameters.append(identity["principal_id"])
        data, previous, following = await paginate(
            request,
            conn,
            member,
            query=followup.QUERY,
            clauses=clauses,
            parameters=parameters,
            filter_values=values,
            fields=("changed_at", "event_id"),
            group="follow-up",
        )
    return render(
        request,
        "followup",
        title="Follow-up",
        member=member,
        identity=identity,
        followups=data,
        values=values,
        reason_names=followup.REASONS,
        problem=error,
        prev=previous,
        more=following,
        status=422 if error else 200,
    )


@router.post("/api/v1/workspaces/{slug}/exports/id-{export_id}/case")
async def open_export_case(request: Request, slug: str, export_id: str):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        tenant = member["id"]
        await conn.execute(
            "SELECT pg_advisory_xact_lock(5,hashtext(%s))", (f"{tenant}/{export_id}",)
        )
        event = await one(
            conn,
            """
            SELECT e.actor_id,e.resource_type FROM st.events e JOIN st.event_manifests m USING(workspace_id,event_id)
            WHERE e.workspace_id=%s AND e.event_id=%s AND e.action='export' AND e.outcome='success'
        """,
            (tenant, export_id),
        )
        if not event:
            raise unavailable()
        case = await one(
            conn,
            """
            SELECT c.id FROM st.evidence a JOIN st.cases c ON c.workspace_id=a.workspace_id AND c.id=a.case_id
            WHERE a.workspace_id=%s AND a.event_id=%s ORDER BY c.opened_at DESC,c.id DESC LIMIT 1
        """,
            (tenant, export_id),
        )
        if case:
            return {"message": "Case already exists.", "location": f"/w/{slug}/cases/{case['id']}"}
        case = await one(
            conn,
            """
            INSERT INTO st.cases(workspace_id,actor_id,resource_type,severity,opened_at,latest_at)
              VALUES(%s,%s,%s,'high',now(),now()) RETURNING id
        """,
            (tenant, event["actor_id"], event["resource_type"]),
        )
        try:
            await conn.execute(
                "INSERT INTO st.evidence VALUES(%s,%s,%s)", (tenant, case["id"], export_id)
            )
        except errors.ForeignKeyViolation:
            raise unavailable() from None
        await log_action(conn, member, "Export case opened", str(case["id"]))
    return JSONResponse(
        {"message": "Case opened.", "location": f"/w/{slug}/cases/{case['id']}"},
        status_code=201,
    )


@router.post("/api/v1/workspaces/{slug}/follow-up/filters")
async def store_followup(request: Request, slug: str):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        await followup.save_filters(request, conn, member["id"], identity["principal_id"])
    return {"message": "Follow-up filters saved.", "location": f"/w/{slug}/cases/follow-up"}


def safe_back(value, slug):
    route = f"/w/{slug}/cases"
    allowed = {route, route + "/follow-up"}
    if (
        value.split("?", 1)[0] in allowed
        and len(value) < 1600
        and not re.search(r"[\x00-\x20#]", value)
    ):
        return value
    return route


def valid_case_id(case_id):
    try:
        return uuid.UUID(case_id)
    except ValueError:
        raise unavailable() from None


async def case_snapshot(conn, tenant, case_id):
    params = (tenant, case_id)
    case = await one(
        conn,
        f"""SELECT {CASE_COLUMNS},
          (SELECT name FROM st.case_members() WHERE id=assignee_id) AS assignee
          FROM st.cases WHERE workspace_id=%s AND id=%s""",
        params,
    )
    if not case:
        raise unavailable()
    signals = await rows(
        conn,
        """
        SELECT rule,rule_version,threshold,observed,detected_at
        FROM st.signals WHERE workspace_id=%s AND case_id=%s ORDER BY detected_at,rule LIMIT 101
    """,
        params,
    )
    evidence = await rows(
        conn,
        """
        SELECT e.event_id,e.action,e.resource_type,e.records_accessed,e.occurred_at,e.received_at,k.label,
           coalesce(cardinality(m.fingerprints),0) AS manifest_count
        FROM st.evidence a JOIN st.events e USING(workspace_id,event_id)
        JOIN st.keys k ON k.workspace_id=e.workspace_id AND k.id=e.key_id
        LEFT JOIN st.event_manifests m ON m.workspace_id=e.workspace_id AND m.event_id=e.event_id
        WHERE a.workspace_id=%s AND a.case_id=%s ORDER BY e.received_at,e.event_id LIMIT 101
    """,
        params,
    )
    reviews = await rows(
        conn,
        """
        SELECT status,note,author,created_at,mutation_id,disposition FROM st.reviews
        WHERE workspace_id=%s AND case_id=%s ORDER BY created_at DESC,mutation_id LIMIT 51
    """,
        params,
    )
    return case, signals, evidence, reviews


@router.get("/w/{slug}/cases/{case_id}")
async def case_detail(request: Request, slug: str, case_id: str, back: str = ""):
    case_uuid = valid_case_id(case_id)
    async with connection(request) as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        member, identity = await workspace(request, conn, slug)
        tenant = member["id"]
        case, signals, evidence, reviews = await case_snapshot(conn, tenant, case_uuid)
        history = await baselines(conn, tenant, case["actor_id"], case["opened_at"] - VIEW_WINDOW)
        members = await rows(conn, "SELECT * FROM st.case_members() ORDER BY name,id")
        exports = [item for item in evidence if item["action"] == "export"]
        primary = next((item for item in reversed(exports) if item["manifest_count"]), None)
        trace = await export_trace(conn, tenant, primary["event_id"]) if primary else None
    baseline = history.get(case["resource_type"])
    view_signals = [signal["observed"] for signal in signals if signal["rule"] == "view_burst"]
    ratio = (
        max(view_signals) / baseline["upper"]
        if baseline and baseline["ready"] and view_signals
        else None
    )
    return render(
        request,
        "case",
        title="Case details",
        member=member,
        identity=identity,
        case=case,
        signals=signals,
        evidence=evidence,
        reviews=reviews,
        members=members,
        ratio=ratio,
        baseline=baseline,
        dispositions=DISPOSITIONS,
        trace=trace,
        back=safe_back(back, slug),
        mutation_id=uuid.uuid4(),
    )


@router.get("/w/{slug}/actors/id-{actor_id}")
async def actor_profile(request: Request, slug: str, actor_id: str):
    if not re.fullmatch(IDENT, actor_id):
        raise unavailable()
    async with connection(request) as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        member, identity = await workspace(request, conn, slug)
        params = (member["id"], actor_id)
        stats = await one(
            conn,
            """
            SELECT count(*) AS events, max(received_at) AS latest,
              count(*) FILTER(WHERE action='export' AND outcome='success') AS exports,
              now() AS cutoff FROM st.events
            WHERE workspace_id=%s AND actor_id=%s AND received_at >= now()-interval '14 days'
        """,
            params,
        )
        cases = await rows(
            conn,
            f"""
            SELECT {CASE_COLUMNS} FROM st.cases WHERE workspace_id=%s AND actor_id=%s
            ORDER BY latest_at DESC,id DESC LIMIT 5
        """,
            params,
        )
        if not stats["events"] and not cases:
            seen = await one(
                conn,
                "SELECT 1 FROM st.events WHERE workspace_id=%s AND actor_id=%s LIMIT 1",
                params,
            )
            if not seen:
                raise unavailable()
        history = await baselines(conn, *params, stats["cutoff"])
        events = await rows(
            conn,
            """
            SELECT received_at,resource_type,action,records_accessed,outcome
            FROM st.events WHERE workspace_id=%s AND actor_id=%s
            ORDER BY received_at DESC,event_id DESC LIMIT 8
        """,
            params,
        )
    return render(
        request,
        "actor",
        title="Actor profile",
        member=member,
        identity=identity,
        actor=actor_id,
        stats=stats,
        history=history,
        cases=cases,
        events=events,
    )


@router.post("/api/v1/workspaces/{slug}/cases/{case_id}/evidence")
async def download_evidence(request: Request, slug: str, case_id: str):
    case_uuid = valid_case_id(case_id)
    await rate(request, "evidence", 20)
    async with connection(request) as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        case, signals, evidence, reviews = await case_snapshot(conn, member["id"], case_uuid)
        captured = (await one(conn, "SELECT now() AS captured"))["captured"]
        exports = [
            item for item in evidence[:100] if item["action"] == "export" and item["manifest_count"]
        ]
        traces = [await export_trace(conn, member["id"], item["event_id"]) for item in exports[-3:]]
        for trace in traces:
            trace["impact_history"] = [
                {field: value for field, value in job.items() if field != "requester_id"}
                for job in await impact_history(conn, member["id"], trace["export"]["event_id"])
            ]
        bundle = evidence_bundle(
            case | {"workspace": slug},
            signals,
            evidence,
            reviews,
            captured,
            traces=traces,
            traces_omitted=len(exports) > len(traces),
        )
        await log_action(conn, member, "Case evidence downloaded", str(case_uuid))
    return JSONResponse(
        bundle,
        headers={
            "Content-Disposition": f'attachment; filename="shadowtrace-{case_uuid}.json"',
        },
    )


@router.get("/w/{slug}/activity")
async def activity(request: Request, slug: str):
    values, error = filters(request, {"actor": None, "action": ("view", "export")})
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        clauses, params = [sql.SQL("e.workspace_id=%s")], [member["id"]]
        for key, column in {"actor": "actor_id", "action": "action"}.items():
            if values[key]:
                clauses.append(sql.SQL("e.") + sql.Identifier(column) + sql.SQL("=%s"))
                params.append(values[key])
        data, previous, following = await paginate(
            request,
            conn,
            member,
            query="""
                SELECT e.event_id,e.actor_id,e.action,e.resource_type,e.records_accessed,
                    e.outcome,e.occurred_at,e.received_at,k.label
                FROM st.events e JOIN st.keys k ON k.workspace_id=e.workspace_id AND k.id=e.key_id
            """,
            clauses=clauses,
            parameters=params,
            filter_values=values,
            fields=("received_at", "event_id"),
            group="events",
        )
    return render(
        request,
        "activity",
        status=422 if error else 200,
        title="Activity",
        member=member,
        identity=identity,
        events=data,
        values=values,
        problem=error,
        prev=previous,
        more=following,
    )


@router.get("/w/{slug}/settings")
async def settings_redirect(request: Request, slug: str):
    async with connection(request) as conn:
        await workspace(request, conn, slug)
    return redirect(f"/w/{slug}/settings/integration")


@router.get("/w/{slug}/settings/{section}")
async def settings(request: Request, slug: str, section: str):
    if section not in {"integration", "rules", "audit"}:
        raise unavailable()
    context = {}
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=section == "audit")
        if section == "integration":
            keys = []
            if member["role"] == "admin":
                keys = await rows(
                    conn,
                    """
                    SELECT k.id,k.label,k.prefix,k.created_at,k.revoked_at,k.purpose,k.destination,
                           k.signing_public_key,
                           (SELECT src.label FROM st.keys src WHERE src.workspace_id=k.workspace_id
                               AND src.id=k.source_key_id) AS source_label,
                           coalesce(h.accepted,0) AS accepted,coalesce(h.replayed,0) AS replayed,
                           coalesce(h.rejected,0) AS rejected,coalesce(h.throttled,0) AS throttled,
                           activity.received_at AS last_event,
                           activity.received_at < now()-interval '24 hours' AS quiet
                    FROM st.keys k
                    LEFT JOIN st.ingest_health h ON h.workspace_id=k.workspace_id AND h.key_id=k.id
                        AND h.day=(now() AT TIME ZONE 'UTC')::date
                    LEFT JOIN LATERAL (
                        SELECT received_at FROM (
                            (SELECT e.received_at FROM st.events e WHERE k.purpose='events'
                               AND e.workspace_id=k.workspace_id AND e.key_id=k.id ORDER BY e.received_at DESC LIMIT 1)
                            UNION ALL
                            (SELECT r.received_at FROM st.destination_receipts r WHERE k.purpose='receipts'
                               AND r.workspace_id=k.workspace_id AND r.key_id=k.id ORDER BY r.received_at DESC LIMIT 1)
                            UNION ALL
                            (SELECT i.completed_at FROM st.impact_requests i WHERE k.purpose='impact'
                               AND i.workspace_id=k.workspace_id AND i.completed_by=k.id ORDER BY i.completed_at DESC LIMIT 1)
                            UNION ALL
                            (SELECT p.decided_at FROM st.protection_decisions p WHERE k.purpose='protection'
                               AND p.workspace_id=k.workspace_id AND p.key_id=k.id ORDER BY p.decided_at DESC LIMIT 1)
                        ) delivery ORDER BY received_at DESC LIMIT 1
                    ) activity ON true
                    WHERE k.workspace_id=%s
                    ORDER BY k.revoked_at IS NOT NULL, k.created_at DESC LIMIT 100
                """,
                    (member["id"],),
                )
            context = {"keys": keys, "example": EXAMPLE}
        elif section == "rules":
            context = {
                "policy": await one(
                    conn, "SELECT * FROM st.policy WHERE workspace_id=%s", (member["id"],)
                )
            }
        else:
            data, previous, following = await paginate(
                request,
                conn,
                member,
                query="SELECT id,actor,operation,subject,created_at FROM st.audit",
                clauses=[sql.SQL("workspace_id=%s")],
                parameters=[member["id"]],
                filter_values={},
                fields=("id",),
                group="audit",
            )
            context = {"audit": data, "prev": previous, "more": following}
    return render(
        request,
        "settings",
        title="Settings",
        member=member,
        identity=identity,
        section=section,
        **context,
    )


async def parsed(request, model, default):
    try:
        return model.model_validate(await read_json(request))
    except ValidationError as error:
        message = default
        first = error.errors(include_input=False)[0]
        if first["type"] == "value_error":
            message = first["msg"].removeprefix("Value error, ")
        raise Issue(422, "INVALID_INPUT", message) from None


async def log_action(conn, member, operation, subject):
    await conn.execute(
        """
        INSERT INTO st.audit(workspace_id,actor,operation,subject) VALUES(%s,%s,%s,%s)
    """,
        (member["id"], member["principal_name"], operation, subject),
    )


@router.post("/api/v1/workspaces/{slug}/cases/{case_id}/reviews")
async def save_review(request: Request, slug: str, case_id: str):
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise unavailable() from None
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        form = await parsed(
            request, Review, "Choose a status and enter a note of 1,000 characters or fewer."
        )
        params = (member["id"], case_uuid)
        case = await one(
            conn,
            """
            SELECT version FROM st.cases WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            params,
        )
        if not case:
            raise unavailable()
        existing = await one(
            conn,
            """
            SELECT author_id,status,note,case_version,disposition FROM st.reviews
            WHERE workspace_id=%s AND case_id=%s AND mutation_id=%s
        """,
            (*params, form.mutation_id),
        )
        if existing:
            if (
                existing["author_id"],
                existing["status"],
                existing["note"],
                existing["case_version"],
                existing["disposition"],
            ) != (
                identity["principal_id"],
                form.status,
                form.note,
                form.version + 1,
                form.disposition,
            ):
                raise Issue(
                    409,
                    "REQUEST_CONFLICT",
                    "This action ID has already been used. Reload this case.",
                )
            return {"message": "Review saved.", "replayed": True}
        if case["version"] != form.version:
            raise Issue(409, "STALE_CASE", "This case changed. Reload before saving.")
        updated = form.version + 1
        await conn.execute(
            """
            UPDATE st.cases SET status=%s,version=%s WHERE workspace_id=%s AND id=%s
        """,
            (form.status, updated, *params),
        )
        await conn.execute(
            """
            INSERT INTO st.reviews(workspace_id,case_id,mutation_id,author_id,author,status,note,case_version,disposition,created_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,clock_timestamp())
        """,
            (
                *params,
                form.mutation_id,
                identity["principal_id"],
                member["principal_name"],
                form.status,
                form.note,
                updated,
                form.disposition,
            ),
        )
        await log_action(conn, member, "Case reviewed", str(case_uuid))
    return JSONResponse({"message": "Review saved.", "replayed": False}, status_code=201)


@router.post("/api/v1/workspaces/{slug}/keys")
async def create_key(request: Request, slug: str):
    token = ("st_demo_" if request.app.state.config.demo else "st_live_") + secrets.token_urlsafe(
        32
    )
    try:
        async with connection(request) as conn:
            member, identity = await workspace(request, conn, slug, admin=True)
            verify_csrf(request, identity)
            form = await parsed(request, KeyName, "Enter a key name of 1–60 characters.")
            # Serialize admin creation to keep the per-workspace limit valid under concurrency.
            await conn.execute("SELECT pg_advisory_xact_lock(3,hashtext(%s))", (str(member["id"]),))
            active = await one(
                conn,
                "SELECT count(*) AS n FROM st.keys WHERE workspace_id=%s AND revoked_at IS NULL",
                (member["id"],),
            )
            if active["n"] >= 50:
                raise Issue(409, "KEY_LIMIT", "Revoke an active key before creating another.")
            if form.source_key_id and not await one(
                conn,
                """
                SELECT id FROM st.keys WHERE workspace_id=%s AND id=%s AND purpose='events'
                  AND revoked_at IS NULL FOR SHARE
            """,
                (member["id"], form.source_key_id),
            ):
                raise Issue(422, "INVALID_SOURCE", "Choose an active audit event source.")
            key = await one(
                conn,
                """
                INSERT INTO st.keys(workspace_id,label,prefix,digest,purpose,destination,signing_public_key,source_key_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
            """,
                (
                    member["id"],
                    form.label,
                    token[:15],
                    digest(token),
                    form.purpose,
                    form.destination,
                    form.signing_public_key,
                    form.source_key_id,
                ),
            )
            await log_action(conn, member, "Integration key created", str(key["id"]))
    except errors.UniqueViolation:
        raise Issue(409, "DUPLICATE_KEY", "An active key already uses this name.") from None
    return JSONResponse({"key": token, "id": str(key["id"])}, status_code=201)


@router.post("/api/v1/workspaces/{slug}/keys/{key_id}/revoke")
async def revoke_key(request: Request, slug: str, key_id: uuid.UUID):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        key = await one(
            conn,
            """
            SELECT revoked_at FROM st.keys WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            (member["id"], key_id),
        )
        if not key:
            raise unavailable()
        if not key["revoked_at"]:
            await conn.execute(
                "UPDATE st.keys SET revoked_at=now() WHERE workspace_id=%s AND id=%s",
                (member["id"], key_id),
            )
            await log_action(conn, member, "Integration key revoked", str(key_id))
    return {"message": "Key revoked."}


@router.post("/api/v1/workspaces/{slug}/rules")
async def save_rules(request: Request, slug: str):
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        form = await parsed(request, Policy, "Enter whole numbers from 1 to 100,000.")
        updated = await one(
            conn,
            """
            UPDATE st.policy SET view_limit=%s, export_limit=%s, version=version+1
            WHERE workspace_id=%s AND version=%s RETURNING version
        """,
            (form.view_limit, form.export_limit, member["id"], form.version),
        )
        if not updated:
            raise Issue(409, "STALE_RULES", "Rules changed. Reload before saving.")
        await log_action(conn, member, "Detection rules updated", str(updated["version"]))
    return {"message": "Rules saved.", "version": updated["version"]}


@router.post("/api/v1/workspaces/{slug}/cases/{case_id}/owner")
async def assign_owner(request: Request, slug: str, case_id: str):
    case_uuid = valid_case_id(case_id)
    async with connection(request) as conn:
        member, identity = await workspace(request, conn, slug)
        verify_csrf(request, identity)
        form = await parsed(request, Assignment, "Choose an active workspace member.")
        params = (member["id"], case_uuid)
        case = await one(
            conn,
            """
            SELECT assignee_id,version FROM st.cases WHERE workspace_id=%s AND id=%s FOR UPDATE
        """,
            params,
        )
        if not case:
            raise unavailable()
        if form.assignee_id == case["assignee_id"]:
            return {"message": "Case owner saved.", "version": case["version"]}
        if form.version != case["version"]:
            raise Issue(409, "STALE_CASE", "This case changed. Reload before assigning it.")
        if form.assignee_id and not await one(
            conn, "SELECT id FROM st.case_members() WHERE id=%s", (form.assignee_id,)
        ):
            raise Issue(422, "INVALID_OWNER", "Choose an active member of this workspace.")
        try:
            await conn.execute(
                """
                UPDATE st.cases SET assignee_id=%s,version=version+1 WHERE workspace_id=%s AND id=%s
            """,
                (form.assignee_id, *params),
            )
        except errors.ForeignKeyViolation:
            raise Issue(
                422, "INVALID_OWNER", "Choose an active member of this workspace."
            ) from None
        await log_action(conn, member, "Case owner changed", str(case_uuid))
    return {"message": "Case owner saved.", "version": case["version"] + 1}


@router.post("/api/v1/workspaces/{slug}/rules/replay")
async def preview_rules(request: Request, slug: str):
    await rate(request, "rule-replay", 15)
    async with connection(request) as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        member, identity = await workspace(request, conn, slug, admin=True)
        verify_csrf(request, identity)
        form = await parsed(request, Policy, "Enter whole numbers from 1 to 100,000.")
        current = await one(conn, "SELECT * FROM st.policy WHERE workspace_id=%s", (member["id"],))
        if not current or form.version != current["version"]:
            raise Issue(409, "STALE_RULES", "Rules changed. Reload before previewing.")
        return await replay(conn, member["id"], current, form.model_dump())

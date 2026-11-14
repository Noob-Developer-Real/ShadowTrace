import hmac
import json
import re
import time
from datetime import UTC
from pathlib import Path

from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadData, URLSafeTimedSerializer

from .db import bind, connection, digest, one, rows

ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=ROOT / "templates")
STATUS = {
    "open": "Open",
    "in_review": "In review",
    "resolved": "Resolved",
    "dismissed": "Dismissed",
}


def fmt(value, style="full"):
    if not value:
        return "—"
    return value.astimezone(UTC).strftime(
        {
            "full": "%d %b %Y, %H:%M:%S UTC",
            "short": "%d %b, %H:%M UTC",
            "time": "%H:%M:%S UTC",
        }[style]
    )


templates.env.filters.update(dt=fmt, number=lambda v: f"{v:,}")
templates.env.globals.update(status_names=STATUS)


class Issue(Exception):
    def __init__(self, status, code, message, headers=None):
        super().__init__(code)
        self.status, self.code, self.message, self.headers = status, code, message, headers


def unavailable():
    return Issue(404, "UNAVAILABLE", "This page is unavailable.")


def render(request, name, *, status=200, **context):
    return templates.TemplateResponse(
        request=request,
        name=name + ".html",
        status_code=status,
        context={"demo": request.app.state.config.demo, **context},
    )


def redirect(path):
    return RedirectResponse(path, status_code=303)


def private_api(request):
    return request.url.path.startswith("/api/")


def issue_response(request, error):
    if private_api(request):
        return JSONResponse(
            {
                "error": {"code": error.code, "message": error.message},
                "request_id": getattr(request.state, "request_id", None),
            },
            status_code=error.status,
            headers=error.headers,
        )
    if error.status == 401:
        from urllib.parse import urlencode

        return redirect("/sign-in?" + urlencode({"next": request.url.path}))
    title = "This page is unavailable." if error.status == 404 else error.message
    response = render(request, "error", status=error.status, title=title, problem=error.status)
    if error.headers:
        response.headers.update(error.headers)
    return response


async def rate(request, scope, maximum, identity=None):
    address = request.client.host if request.client else "unknown"
    timer = int(time.time())
    async with connection(request) as conn:
        result = await one(
            conn,
            """
            INSERT INTO st.rate_limits(scope,bucket) VALUES (%s,%s)
            ON CONFLICT (scope,bucket) DO UPDATE SET uses=st.rate_limits.uses+1
              WHERE st.rate_limits.uses < %s
            RETURNING uses
        """,
            (digest(f"{scope}/{identity or address}"), timer // 60, maximum),
        )
    if not result:
        raise Issue(
            429,
            "RATE_LIMITED",
            "Too many requests. Wait and try again.",
            {"Retry-After": str(60 - timer % 60)},
        )


async def read_json(request):
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
        != "application/json"
    ):
        raise Issue(415, "JSON_REQUIRED", "Send an application/json request.")
    try:
        raw = await request.body()

        def unique_keys(items):
            values = dict(items)
            if len(items) != len(values):
                raise ValueError("Duplicate JSON fields")
            return values

        return json.loads(raw, object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as error:
        raise Issue(400, "INVALID_JSON", "Send a valid JSON object.") from error


def enforce_origin(request):
    if request.headers.get("origin") != request.app.state.config.origin:
        raise Issue(
            403, "ORIGIN_DENIED", "This request could not be verified. Reload and try again."
        )


async def session(request, conn):
    token = request.cookies.get(request.app.state.config.session_cookie, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise Issue(401, "SIGN_IN_REQUIRED", "Sign in to continue.")
    token_hash = digest(token)
    await bind(conn, "st.session_digest", token_hash)
    record = await one(
        conn,
        """
        SELECT principal_id,csrf,last_seen FROM st.sessions WHERE digest=%s
          AND expires_at > now() AND last_seen > now() - interval '30 minutes'
    """,
        (token_hash,),
    )
    if not record:
        raise Issue(401, "SIGN_IN_REQUIRED", "Your session expired. Sign in to continue.")
    if request.method != "GET" or (time.time() - record["last_seen"].timestamp()) > 60:
        await conn.execute(
            """
            UPDATE st.sessions SET last_seen=now() WHERE digest=%s AND expires_at > now()
              AND last_seen < now() - interval '1 minute'
        """,
            (token_hash,),
        )
    record["digest"] = token_hash
    await bind(conn, "st.principal_id", record["principal_id"])
    return record


def verify_csrf(request, identity, presented=None):
    enforce_origin(request)
    token = request.headers.get("x-csrf-token", "") if presented is None else presented
    if not isinstance(token, str) or not hmac.compare_digest(
        token.encode(), identity["csrf"].encode()
    ):
        raise Issue(403, "CSRF_DENIED", "This request could not be verified. Reload and try again.")


async def workspace(request, conn, slug, admin=False):
    identity = await session(request, conn)
    member = await one(
        conn,
        """
        SELECT w.id,w.slug,w.name,w.retention_days,m.role,p.name AS principal_name
        FROM st.memberships m JOIN st.workspaces w ON w.id=m.workspace_id
        JOIN st.principals p ON p.id=m.principal_id
        WHERE m.principal_id=%s AND w.slug=%s
    """,
        (identity["principal_id"], slug),
    )
    if not member or (admin and member["role"] != "admin"):
        raise unavailable()
    await bind(conn, "st.tenant_id", member["id"])
    return member, identity


async def memberships(conn):
    return await rows(
        conn,
        """
        SELECT w.slug,w.name,m.role FROM st.workspaces w JOIN st.memberships m ON m.workspace_id=w.id
        WHERE m.principal_id=st.principal() ORDER BY w.name,w.slug
    """,
    )


def safe_next(value):
    if re.fullmatch(
        r"/(?:workspaces|w/[a-z0-9][a-z0-9-]{1,47}(?:/[A-Za-z0-9_-]{1,64}|/id-[A-Za-z0-9._-]{1,80}){0,3})",
        value or "",
    ):
        return value
    return ""


def cursor_codec(request):
    return URLSafeTimedSerializer(
        request.app.state.config.secret, salt="shadowtrace/list-cursor-v1"
    )


def load_cursor(request, scope, token):
    if not token:
        return None
    try:
        data = cursor_codec(request).loads(token, max_age=86400)
        if data["scope"] != scope or data["direction"] not in {"next", "previous"}:
            raise ValueError
        return data
    except (BadData, KeyError, TypeError, ValueError):
        raise Issue(
            400, "INVALID_CURSOR", "This page link expired. Restart at the first page."
        ) from None


def encode_cursor(request, scope, direction, key):
    return cursor_codec(request).dumps({"scope": scope, "direction": direction, "key": key})

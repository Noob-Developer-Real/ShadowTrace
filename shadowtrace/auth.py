import logging
import secrets
from urllib.parse import urlencode

import httpx
from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request
from joserfc.errors import JoseError

from .config import LOOPBACK
from .db import bind, connection, digest, one
from .web import (
    Issue,
    enforce_origin,
    memberships,
    rate,
    read_json,
    redirect,
    render,
    safe_next,
    session,
    unavailable,
    verify_csrf,
)

router = APIRouter()
logger = logging.getLogger("shadowtrace")
DEMO = {"northwind-analyst", "northwind-admin", "harbor-analyst"}


class LoginState:
    """Store the PKCE verifier and nonce on the server, with a browser-bound state marker."""

    def __init__(self, app):
        self.app = app

    async def get(self, key):
        async with self.app.state.pool.connection() as conn:
            state = await one(
                conn,
                """
                DELETE FROM st.oidc_state WHERE cache_key=%s AND expires_at > now()
                RETURNING payload
            """,
                (key,),
            )
        return state["payload"] if state else None

    async def set(self, key, value, _ttl):
        async with self.app.state.pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO st.oidc_state(cache_key,payload,expires_at)
                VALUES(%s,%s,now()+interval '10 minutes')
            """,
                (key, value),
            )

    async def delete(self, key):
        async with self.app.state.pool.connection() as conn:
            await conn.execute("DELETE FROM st.oidc_state WHERE cache_key=%s", (key,))


def oauth_client(config, app):
    if config.demo:
        return None
    oauth = OAuth(cache=LoginState(app))
    return oauth.register(
        "work",
        server_metadata_url=config.issuer + "/.well-known/openid-configuration",
        client_id=config.client_id,
        client_secret=config.client_secret,
        client_kwargs={
            "scope": "openid",
            "code_challenge_method": "S256",
            "timeout": httpx.Timeout(8),
            "follow_redirects": False,
        },
    )


async def verify_metadata(client, config):
    from urllib.parse import urlsplit

    metadata = await client.load_server_metadata()
    if metadata.get("issuer") != config.issuer:
        raise ValueError("OIDC issuer")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint = urlsplit(metadata.get(name, ""))
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username
            or endpoint.fragment
        ):
            raise ValueError("OIDC endpoint")


@router.get("/")
async def root(request: Request):
    config = request.app.state.config
    return redirect("/workspaces" if request.cookies.get(config.session_cookie) else "/sign-in")


@router.get("/sign-in")
async def sign_in(request: Request, next: str = "", error: str = ""):
    return render(
        request,
        "signin",
        title="Sign in",
        intended=safe_next(next),
        interrupted=error == "interrupted",
    )


@router.get("/auth/sso")
async def start_sso(request: Request, next: str = ""):
    config = request.app.state.config
    if config.demo:
        raise unavailable()
    await rate(request, "auth-start", 30)
    request.session.clear()
    request.session["next"] = safe_next(next)
    client = request.app.state.oauth
    try:
        await verify_metadata(client, config)
        return await client.authorize_redirect(request, config.origin + "/auth/callback")
    except (httpx.HTTPError, OAuthError, ValueError, KeyError) as error:
        logger.warning("sso-start-failed error_type=%s", type(error).__name__)
        request.session.clear()
        return redirect("/sign-in?error=interrupted")


@router.get("/auth/callback")
async def callback(request: Request):
    config = request.app.state.config
    if config.demo:
        raise unavailable()
    await rate(request, "auth-callback", 45)
    intended = safe_next(request.session.pop("next", ""))
    client = request.app.state.oauth
    try:
        await verify_metadata(client, config)
        token = await client.authorize_access_token(request, leeway=60)
        info = token.get("userinfo")
        subject = info.get("sub", "") if info else ""
        if (
            not info
            or info.get("iss") != config.issuer
            or not isinstance(subject, str)
            or not 1 <= len(subject) <= 255
        ):
            raise ValueError("OIDC identity")
    except (httpx.HTTPError, OAuthError, JoseError, ValueError, KeyError, TypeError) as error:
        logger.warning("sso-callback-failed error_type=%s", type(error).__name__)
        return redirect("/sign-in?" + urlencode({"error": "interrupted", "next": intended}))
    finally:
        request.session.clear()
    return await issue_session(request, config.issuer, subject, intended)


@router.post("/auth/demo")
async def demo_login(request: Request):
    config = request.app.state.config
    if not config.demo or not request.client or request.client.host not in LOOPBACK:
        raise unavailable()
    enforce_origin(request)
    await rate(request, "auth-demo", 45)
    args = await read_json(request)
    if (
        not isinstance(args, dict)
        or not isinstance(args.get("identity"), str)
        or args["identity"] not in DEMO
    ):
        raise Issue(400, "INVALID_IDENTITY", "Choose a demo identity.")
    intended = safe_next(args.get("next")) if isinstance(args.get("next"), str) else ""
    return await issue_session(request, "demo", args["identity"], intended)


async def issue_session(request, issuer, subject, intended):
    config = request.app.state.config
    token = secrets.token_urlsafe(32)
    token_hash = digest(token)
    async with connection(request) as conn:
        principal = await one(conn, "SELECT id FROM st.identity(%s,%s)", (issuer, subject))
        if not principal:
            return render(
                request,
                "error",
                status=403,
                title="No workspace access.",
                problem=403,
                help_text="Ask your workspace administrator for access.",
            )
        old_token = request.cookies.get(config.session_cookie, "")
        if old_token and len(old_token) == 43:
            await bind(conn, "st.session_digest", digest(old_token))
            await conn.execute("DELETE FROM st.sessions WHERE digest=%s", (digest(old_token),))
        await bind(conn, "st.session_digest", token_hash)
        await conn.execute(
            """
            INSERT INTO st.sessions(digest,principal_id,csrf,expires_at)
            VALUES(%s,%s,%s,now()+interval '8 hours')
        """,
            (token_hash, principal["id"], secrets.token_urlsafe(32)),
        )
        await bind(conn, "st.principal_id", principal["id"])
        choices = await memberships(conn)
    allowed = {item["slug"] for item in choices}
    parts = intended.split("/")
    if intended == "/workspaces" or len(parts) > 2 and parts[2] in allowed:
        destination = intended
    elif len(choices) == 1:
        destination = "/w/" + choices[0]["slug"]
    else:
        destination = "/workspaces"
    response = redirect(destination)
    response.set_cookie(
        config.session_cookie,
        token,
        httponly=True,
        secure=not config.demo,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/auth/logout")
async def logout(request: Request):
    async with connection(request) as conn:
        identity = await session(request, conn)
        verify_csrf(request, identity)
        await conn.execute("DELETE FROM st.sessions WHERE digest=%s", (identity["digest"],))
    response = redirect("/sign-in")
    response.delete_cookie(
        request.app.state.config.session_cookie,
        secure=not request.app.state.config.demo,
        httponly=True,
        samesite="lax",
    )
    return response

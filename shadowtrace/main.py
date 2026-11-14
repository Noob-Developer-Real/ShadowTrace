import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

import anyio
import psycopg
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import PoolTimeout, TooManyRequests
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import (
    auth,
    console,
    demo_flow,
    demo_managed,
    impact,
    ingest,
    lineage,
    managed_links,
    protection,
    transfer_approvals,
)
from .cloud_storage import DemoStorage, storage_from_env
from .config import Settings
from .db import connection, pool, verify_runtime, verify_schema
from .web import ROOT, Issue, issue_response, unavailable

logger = logging.getLogger("shadowtrace")
BODY_LIMIT = 16 * 1024
LINEAGE_BODY_LIMIT = 80 * 1024
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def create_app(settings=None):
    config = settings or Settings.from_env()
    config.validate()

    @asynccontextmanager
    async def lifespan(app):
        app.state.share_storage = DemoStorage() if config.demo else storage_from_env()
        app.state.share_limiter = anyio.CapacityLimiter(4)
        app.state.pool = pool(config.database)
        await app.state.pool.open(wait=True, timeout=10)
        try:
            async with app.state.pool.connection() as conn:
                await verify_runtime(conn)
            yield
        finally:
            await app.state.pool.close()

    app = FastAPI(
        lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None, title="ShadowTrace"
    )
    app.state.config = config
    app.state.oauth = auth.oauth_client(config, app)
    if not config.demo:
        app.add_middleware(
            SessionMiddleware,
            secret_key=config.secret,
            session_cookie="__Host-st_oidc",
            https_only=True,
            same_site="lax",
            max_age=600,
        )

    @app.middleware("http")
    async def protect(request, call_next):
        started = time.monotonic()
        request.state.request_id = uuid.uuid4().hex
        try:
            expected_host = config.origin.split("://", 1)[1].lower()
            if request.headers.get("host", "").lower() != expected_host:
                raise Issue(400, "INVALID_HOST", "This host is unavailable.")
            if not config.demo and request.url.scheme != "https":
                raise Issue(400, "HTTPS_REQUIRED", "ShadowTrace requires HTTPS.")
            if request.method in MUTATING:
                limit = (
                    LINEAGE_BODY_LIMIT
                    if request.url.path in {"/api/v1/events", "/api/v1/receipts"}
                    else BODY_LIMIT
                )
                size = request.headers.get("content-length")
                if size and (
                    not size.isascii() or not size.isdecimal() or len(size) > 8 or int(size) > limit
                ):
                    raise Issue(413, "BODY_TOO_LARGE", "This request is too large.")
                raw = bytearray()
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        if len(raw) + len(chunk) > limit:
                            raise Issue(413, "BODY_TOO_LARGE", "This request is too large.")
                        raw.extend(chunk)
                # Starlette caches a pre-read body for the downstream request.
                request._body = bytes(raw)
            response = await call_next(request)
        except Issue as error:
            response = issue_response(request, error)
        except TimeoutError:
            response = issue_response(request, Issue(408, "TIMEOUT", "The request timed out."))
        except (
            psycopg.OperationalError,
            PoolTimeout,
            TooManyRequests,
            psycopg.errors.QueryCanceled,
            psycopg.errors.LockNotAvailable,
            psycopg.errors.SerializationFailure,
            psycopg.errors.DeadlockDetected,
        ) as error:
            logger.warning(
                "database-unavailable id=%s type=%s", request.state.request_id, type(error).__name__
            )
            response = issue_response(
                request,
                Issue(
                    503,
                    "TEMPORARY_FAILURE",
                    "Service temporarily unavailable.",
                    {"Retry-After": "2"},
                ),
            )
        except Exception as error:  # noqa: BLE001 - redact all unexpected request errors
            logger.error(
                "request-failure id=%s type=%s", request.state.request_id, type(error).__name__
            )
            response = issue_response(
                request, Issue(500, "UNEXPECTED_FAILURE", "Something went wrong. Try again.")
            )
        response.headers.update(
            {
                "X-Request-ID": request.state.request_id,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "X-Robots-Tag": "noindex, nofollow",
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                    "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                ),
                "Cache-Control": "no-store"
                if not request.url.path.startswith("/static/")
                else "no-cache",
            }
        )
        if not config.demo:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        route = request.scope.get("route")
        logger.info(
            "request id=%s method=%s route=%s status=%s ms=%.1f",
            request.state.request_id,
            request.method,
            getattr(route, "path", "<unresolved>"),
            response.status_code,
            (time.monotonic() - started) * 1000,
        )
        return response

    @app.exception_handler(Issue)
    async def issue(request: Request, error):
        return issue_response(request, error)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error):
        return issue_response(
            request,
            unavailable()
            if error.status_code == 404
            else Issue(
                error.status_code,
                "REQUEST_FAILED",
                "This request could not be completed.",
                error.headers,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, _error):
        return issue_response(
            request, Issue(422, "INVALID_INPUT", "Check the request fields and try again.")
        )

    @app.get("/health/live")
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    async def ready(request: Request):
        async with connection(request) as conn:
            await verify_schema(conn)
        return JSONResponse({"status": "ready"})

    app.include_router(auth.router)
    app.include_router(ingest.router)
    app.include_router(impact.router)
    app.include_router(console.router)
    app.include_router(lineage.router)
    app.include_router(protection.router)
    app.include_router(managed_links.router)
    app.include_router(transfer_approvals.router)
    if config.demo:
        app.include_router(demo_flow.router)
        app.include_router(demo_managed.router)
    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    return app

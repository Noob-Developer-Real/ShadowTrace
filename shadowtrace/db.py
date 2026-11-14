import hashlib
from contextlib import asynccontextmanager

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def pool(dsn):
    return AsyncConnectionPool(
        dsn,
        open=False,
        min_size=1,
        max_size=8,
        timeout=3,
        max_waiting=45,
        kwargs={
            "row_factory": dict_row,
            "options": "-c statement_timeout=5000 -c lock_timeout=3000",
        },
    )


async def one(conn, query, values=()):
    return await (await conn.execute(query, values)).fetchone()


async def rows(conn, query, values=()):
    return await (await conn.execute(query, values)).fetchall()


async def bind(conn, name, value):
    await conn.execute("SELECT set_config(%s, %s, true)", (name, str(value)))


async def verify_runtime(conn):
    result = await one(
        conn,
        """
        SELECT current_user='shadowtrace_app' AND NOT rolsuper AND NOT rolbypassrls
          AND NOT rolcreaterole AND NOT rolcreatedb AND NOT
          EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='st' AND pg_has_role(c.relowner, 'USAGE')) AS restricted
        FROM pg_roles WHERE rolname=current_user
    """,
    )
    if not result or not result["restricted"]:
        raise RuntimeError("Use the restricted shadowtrace_app database role.")
    await verify_schema(conn)


async def verify_schema(conn):
    await conn.execute(
        """
        SELECT c.assignee_id,h.accepted,r.signature,i.state,f.owner,p.cumulative_limit,d.intent,l.id,a.state FROM st.cases c
        CROSS JOIN st.ingest_health h CROSS JOIN st.destination_receipts r
        CROSS JOIN st.impact_requests i CROSS JOIN st.followup_filters f
        CROSS JOIN st.protection_policy p CROSS JOIN st.protection_decisions d
        CROSS JOIN st.managed_links l CROSS JOIN st.transfer_approvals a LIMIT 0
        """
    )


@asynccontextmanager
async def connection(request):
    async with request.app.state.pool.connection() as conn:
        yield conn

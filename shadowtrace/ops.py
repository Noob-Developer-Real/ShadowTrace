import argparse
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from psycopg import sql

from .db import digest
from .schema import SLUG

MIGRATIONS = Path(__file__).parent / "migrations"


def dsn():
    result = os.environ.get("ST_OPERATOR_DATABASE_URL")
    if not result:
        raise ValueError("Set ST_OPERATOR_DATABASE_URL to the migration owner connection.")
    return result


def migrate(conn):
    conn.execute("SELECT pg_advisory_xact_lock(73288941)")
    role = conn.execute("""
        SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
        AND rolcanlogin FROM pg_roles WHERE rolname='shadowtrace_app'
    """).fetchone()
    if role != (True,):
        raise ValueError("Create a restricted login role named shadowtrace_app before migrating.")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS public.shadowtrace_schema (
          version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz DEFAULT now()
        )
    """)
    available = {path.name: path for path in sorted(MIGRATIONS.glob("*.sql"))}
    applied = dict(conn.execute("SELECT version,checksum FROM public.shadowtrace_schema"))
    if applied.keys() - available.keys():
        raise ValueError("Database contains a migration newer than this release.")
    for version, file in available.items():
        content = file.read_text()
        checksum = digest(content)
        if version in applied:
            if applied[version] != checksum:
                raise ValueError(f"Migration checksum changed: {version}")
            continue
        conn.execute(content)
        conn.execute(
            "INSERT INTO public.shadowtrace_schema(version,checksum) VALUES(%s,%s)",
            (version, checksum),
        )
        print(f"Applied {version}")


def workspace(conn, slug, name, retention=30):
    if (
        not re.fullmatch(SLUG, slug)
        or not 1 <= len(name.strip()) <= 80
        or not name.isprintable()
        or not 7 <= retention <= 365
    ):
        raise ValueError(
            "Use a valid slug, a workspace name of 1–80 characters and 7–365 retention days."
        )
    row = conn.execute(
        """
        INSERT INTO st.workspaces(slug,name,retention_days) VALUES(%s,%s,%s)
        RETURNING id
    """,
        (slug, name.strip(), retention),
    ).fetchone()
    conn.execute("INSERT INTO st.policy(workspace_id) VALUES(%s)", row)
    return row[0]


def grant(conn, slug, issuer, subject, name, role):
    if (
        not 1 <= len(subject) <= 255
        or not subject.isprintable()
        or not 1 <= len(name.strip()) <= 80
        or not name.isprintable()
    ):
        raise ValueError("Use a valid identity subject and a display name of 1–80 characters.")
    tenant = conn.execute("SELECT id FROM st.workspaces WHERE slug=%s", (slug,)).fetchone()
    if not tenant:
        raise ValueError("Workspace does not exist.")
    person = conn.execute(
        """
        INSERT INTO st.principals(issuer,subject,name) VALUES(%s,%s,%s)
        ON CONFLICT(issuer,subject) DO UPDATE SET name=excluded.name RETURNING id
    """,
        (issuer, subject, name.strip()),
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO st.memberships(workspace_id,principal_id,role) VALUES(%s,%s,%s)
        ON CONFLICT(workspace_id,principal_id) DO UPDATE SET role=excluded.role
    """,
        (tenant[0], person, role),
    )
    conn.execute(
        "INSERT INTO st.audit(workspace_id,actor,operation,subject) VALUES(%s,'Operator',%s,%s)",
        (tenant[0], f"Membership set to {role}", str(person)),
    )


def remove(conn, slug, issuer, subject):
    member = conn.execute(
        """
        DELETE FROM st.memberships m USING st.workspaces w, st.principals p
        WHERE m.workspace_id=w.id AND m.principal_id=p.id AND w.slug=%s
          AND p.issuer=%s AND p.subject=%s
        RETURNING m.workspace_id, m.principal_id
    """,
        (slug, issuer, subject),
    ).fetchone()
    if not member:
        raise ValueError("Membership does not exist.")
    conn.execute(
        "INSERT INTO st.audit(workspace_id,actor,operation,subject) VALUES(%s,'Operator','Membership revoked',%s)",
        (member[0], str(member[1])),
    )


def adjust_retention(conn, slug, days):
    if not 7 <= days <= 365:
        raise ValueError("Enter a retention period from 7 to 365 days.")
    item = conn.execute(
        "UPDATE st.workspaces SET retention_days=%s WHERE slug=%s RETURNING id", (days, slug)
    ).fetchone()
    if not item:
        raise ValueError("Workspace does not exist.")
    conn.execute(
        "INSERT INTO st.audit(workspace_id,actor,operation,subject) VALUES(%s,'Operator','Retention updated',%s)",
        (item[0], str(days)),
    )


def purge(conn):
    counts = {}
    conn.execute("SELECT pg_advisory_xact_lock(73288942)")
    conn.execute("""
        UPDATE st.cases c SET evidence_expired=true,version=c.version+1
        FROM st.workspaces w
        WHERE c.workspace_id=w.id AND NOT c.evidence_expired AND EXISTS(
          SELECT 1 FROM st.evidence a JOIN st.events e USING(workspace_id,event_id)
          WHERE a.workspace_id=c.workspace_id AND a.case_id=c.id
            AND e.received_at < now()-make_interval(days=>w.retention_days)
        )
    """)
    for table, column in (
        ("events", "received_at"),
        ("cases", "latest_at"),
        ("audit", "created_at"),
        ("protection_decisions", "decided_at"),
        ("transfer_approvals", "created_at"),
    ):
        statement = sql.SQL("""
            DELETE FROM st.{} t USING st.workspaces w WHERE t.workspace_id=w.id
              AND t.{} < now()-make_interval(days=>w.retention_days)
        """).format(sql.Identifier(table), sql.Identifier(column))
        counts[table] = conn.execute(statement).rowcount
    counts["ingest health days"] = conn.execute("""
        DELETE FROM st.ingest_health h USING st.workspaces w WHERE h.workspace_id=w.id
          AND h.day < (now() AT TIME ZONE 'UTC')::date-w.retention_days
    """).rowcount
    counts["sessions"] = conn.execute("""
        DELETE FROM st.sessions WHERE expires_at <= now() OR last_seen <= now()-interval '30 minutes'
    """).rowcount
    counts["OIDC states"] = conn.execute(
        "DELETE FROM st.oidc_state WHERE expires_at <= now()"
    ).rowcount
    counts["rate buckets"] = conn.execute("""
        DELETE FROM st.rate_limits WHERE bucket < (extract(epoch from now())/60)::bigint-60
    """).rowcount
    counts["revoked keys"] = conn.execute("""
        DELETE FROM st.keys k USING st.workspaces w WHERE k.workspace_id=w.id
          AND k.revoked_at < now()-make_interval(days=>w.retention_days) AND NOT EXISTS (
              SELECT 1 FROM st.events e WHERE e.workspace_id=k.workspace_id AND e.key_id=k.id
          ) AND NOT EXISTS (
              SELECT 1 FROM st.destination_receipts r WHERE r.workspace_id=k.workspace_id AND r.key_id=k.id
          ) AND NOT EXISTS (
              SELECT 1 FROM st.keys src WHERE src.workspace_id=k.workspace_id AND src.source_key_id=k.id
          ) AND NOT EXISTS (
              SELECT 1 FROM st.impact_requests i WHERE i.workspace_id=k.workspace_id
                AND (i.source_key_id=k.id OR i.completed_by=k.id)
          ) AND NOT EXISTS (
              SELECT 1 FROM st.protection_decisions p WHERE p.workspace_id=k.workspace_id AND p.key_id=k.id
          ) AND NOT EXISTS (
              SELECT 1 FROM st.transfer_approvals a WHERE a.workspace_id=k.workspace_id AND a.key_id=k.id
          )
    """).rowcount
    print("Purged " + ", ".join(f"{count} {key}" for key, count in counts.items()))


def demo_seed(conn):
    if os.environ.get("ST_MODE") != "demo":
        raise ValueError("Demo seed requires ST_MODE=demo.")
    if conn.execute("SELECT current_database()").fetchone()[0] != "shadowtrace_demo":
        raise ValueError("Demo seed requires the dedicated shadowtrace_demo database.")
    if conn.execute("SELECT count(*) FROM st.workspaces").fetchone()[0]:
        raise ValueError("The demo database is already seeded. Use the local launcher to reuse it.")
    keys = {}
    for slug, name in (("northwind", "Northwind Commerce"), ("harbor", "Harbor Supply")):
        tenant = workspace(conn, slug, name)
        grant(
            conn,
            slug,
            "demo",
            slug + "-analyst",
            ("Northwind" if slug == "northwind" else "Harbor") + " Analyst",
            "analyst",
        )
        if slug == "northwind":
            grant(conn, slug, "demo", "northwind-admin", "Northwind Admin", "admin")
        key = "st_demo_" + secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO st.keys(workspace_id,label,prefix,digest) VALUES(%s,%s,%s,%s)",
            (
                tenant,
                "Orders service" if slug == "northwind" else "Warehouse service",
                key[:15],
                digest(key),
            ),
        )
        keys[slug] = key
    return keys


def main():
    parser = argparse.ArgumentParser(prog="python -m shadowtrace.ops")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("purge")
    new = sub.add_parser("workspace")
    new.add_argument("slug")
    new.add_argument("name")
    new.add_argument("--retention", type=int, default=30)
    grant_cmd = sub.add_parser("grant")
    remove_cmd = sub.add_parser("revoke")
    for command in (grant_cmd, remove_cmd):
        command.add_argument("slug")
        command.add_argument("subject")
    grant_cmd.add_argument("name")
    grant_cmd.add_argument("role", choices=["analyst", "admin"])
    retention = sub.add_parser("retention")
    retention.add_argument("slug")
    retention.add_argument("days", type=int)
    args = parser.parse_args()
    try:
        with psycopg.connect(dsn(), connect_timeout=5) as conn:
            if args.command in {"grant", "revoke"}:
                issuer = os.environ.get("ST_OIDC_ISSUER", "")
                endpoint = urlsplit(issuer)
                if (
                    endpoint.scheme != "https"
                    or not endpoint.hostname
                    or endpoint.username
                    or endpoint.query
                    or endpoint.fragment
                    or issuer.endswith("/")
                ):
                    raise ValueError("Set ST_OIDC_ISSUER to the deployment issuer.")
                if args.command == "grant":
                    grant(conn, args.slug, issuer, args.subject, args.name, args.role)
                else:
                    remove(conn, args.slug, issuer, args.subject)
            elif args.command == "workspace":
                workspace(conn, args.slug, args.name, args.retention)
            elif args.command == "retention":
                adjust_retention(conn, args.slug, args.days)
            elif args.command == "migrate":
                migrate(conn)
            else:
                purge(conn)
        print(f"{args.command}: complete")
    except (ValueError, psycopg.Error) as error:
        print(
            f"Operation failed: {error if isinstance(error, ValueError) else type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

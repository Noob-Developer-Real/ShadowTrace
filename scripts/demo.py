"""Start or exercise a local synthetic installation. Requires PostgreSQL 16+ binaries."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import psycopg
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from psycopg import sql

from shadowtrace.db import digest
from shadowtrace.ops import demo_seed, migrate

ROOT = Path(__file__).resolve().parents[1]
STATE = Path(os.environ.get("ST_DEMO_STATE", str(ROOT / ".demo"))).resolve()
WEB_PORT = int(os.environ.get("ST_DEMO_PORT", "8787"))
PG_PORT = int(os.environ.get("ST_DEMO_DB_PORT", "54876"))
ORIGIN = f"http://127.0.0.1:{WEB_PORT}"


def safe_write(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(value, file)
        file.flush()
        os.fsync(file.fileno())
    tmp.replace(path)


def pg(command, *args, quiet=False, check=True):
    configured = os.environ.get("ST_PG_BIN")
    homebrew = Path("/opt/homebrew/opt/postgresql@16/bin")
    executable = f"{command}.exe" if os.name == "nt" else command
    binary = (
        str(Path(configured) / executable)
        if configured
        else str(homebrew / command)
        if (homebrew / command).exists()
        else shutil.which(executable) or shutil.which(command)
    )
    if not binary:
        raise RuntimeError("Install PostgreSQL 16+ or set ST_PG_BIN to its bin directory.")
    return subprocess.run(
        [binary, *map(str, args)], check=check, stdout=subprocess.DEVNULL if quiet else None
    )


def open_cluster():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    if os.name != "nt" and (len(str(STATE / f".s.PGSQL.{PG_PORT}")) >= 100 or "'" in str(STATE)):
        raise RuntimeError("Set ST_DEMO_STATE to a shorter local path without quotes.")
    db = STATE / "pg"
    if not (db / "PG_VERSION").exists():
        pg(
            "initdb",
            "-D",
            db,
            "-U",
            "shadowtrace_owner",
            "--auth-local=trust",
            "--auth-host=scram-sha-256",
            "--encoding=UTF8",
            "--no-locale",
            quiet=True,
        )
    if pg("pg_ctl", "-D", db, "status", quiet=True, check=False).returncode:
        server_options = (
            f"-c listen_addresses=127.0.0.1 -p {PG_PORT}"
            if os.name == "nt"
            else f"-k '{STATE}' -c listen_addresses='' -p {PG_PORT}"
        )
        pg(
            "pg_ctl",
            "-D",
            db,
            "-l",
            STATE / "postgres.log",
            "-o",
            server_options,
            "-w",
            "start",
            quiet=True,
        )
    return {
        "host": "127.0.0.1" if os.name == "nt" else str(STATE),
        "port": PG_PORT,
        "user": "shadowtrace_owner",
    }


def initialize():
    owner = open_cluster()
    os.environ["ST_MODE"] = "demo"
    with psycopg.connect(dbname="postgres", autocommit=True, **owner) as conn:
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname='shadowtrace_app'").fetchone():
            conn.execute(
                "CREATE ROLE shadowtrace_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
            )
        if not conn.execute(
            "SELECT 1 FROM pg_database WHERE datname='shadowtrace_demo'"
        ).fetchone():
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier("shadowtrace_demo")))
    with psycopg.connect(dbname="shadowtrace_demo", **owner) as conn:
        migrate(conn)
        known = STATE / "settings.json"
        if not known.exists():
            with conn.transaction():
                keys = demo_seed(conn)
                # A secret file is created only for the dedicated local demo database.
                safe_write(known, {"keys": keys, "session": secrets.token_urlsafe(48)})
    data = json.loads(known.read_text())
    receipt_keys, impact_keys = {}, {}
    with psycopg.connect(dbname="shadowtrace_demo", **owner) as conn:
        for slug, source in data["keys"].items():
            signer = Ed25519PrivateKey.from_private_bytes(
                hmac.digest(data["session"].encode(), f"demo-signer:{slug}".encode(), "sha256")
            )
            for purpose, label in (
                ("receipts", "Signed destination (demo)"),
                ("impact", "Source resolver (demo)"),
            ):
                secret = hmac.digest(
                    data["session"].encode(), f"demo-1.3:{purpose}:{slug}".encode(), hashlib.sha256
                )
                token = "st_demo_" + base64.urlsafe_b64encode(secret).decode().rstrip("=")
                conn.execute(
                    """
                    INSERT INTO st.keys(workspace_id,label,prefix,digest,purpose,destination,signing_public_key,source_key_id)
                    SELECT w.id,%s,%s,%s,%s,%s,%s,CASE WHEN %s='impact' THEN src.id END
                    FROM st.workspaces w JOIN st.keys src ON src.workspace_id=w.id AND src.digest=%s
                    WHERE w.slug=%s ON CONFLICT DO NOTHING
                    """,
                    (
                        label,
                        token[:15],
                        digest(token),
                        purpose,
                        "partner-import" if purpose == "receipts" else None,
                        signer.public_key().public_bytes_raw().hex()
                        if purpose == "receipts"
                        else None,
                        purpose,
                        digest(source),
                        slug,
                    ),
                )
                (receipt_keys if purpose == "receipts" else impact_keys)[slug] = token
    protection_keys = {}
    with psycopg.connect(dbname="shadowtrace_demo", **owner) as conn:
        for slug in data["keys"]:
            secret = hmac.digest(
                data["session"].encode(), f"demo-protection:{slug}".encode(), "sha256"
            )
            token = "st_demo_" + base64.urlsafe_b64encode(secret).decode().rstrip("=")
            conn.execute(
                """
                INSERT INTO st.keys(workspace_id,label,prefix,digest,purpose)
                SELECT id,%s,%s,%s,'protection' FROM st.workspaces WHERE slug=%s
                ON CONFLICT DO NOTHING
                """,
                ("Release connector (demo)", token[:15], digest(token), slug),
            )
            conn.execute(
                """
                INSERT INTO st.protection_policy(workspace_id,mode,export_limit,download_limit,share_limit,destinations)
                SELECT id,'active',500,100,50,ARRAY['approved-partner','internal-vault']
                FROM st.workspaces WHERE slug=%s ON CONFLICT DO NOTHING
            """,
                (slug,),
            )
            protection_keys[slug] = token
    data["protection_keys"] = protection_keys
    data["receipt_keys"] = receipt_keys
    data["impact_keys"] = impact_keys
    return data


def serve():
    data = initialize()
    from psycopg.conninfo import make_conninfo

    from shadowtrace.config import Settings
    from shadowtrace.main import create_app

    database = make_conninfo(
        host=str(STATE), port=PG_PORT, user="shadowtrace_app", dbname="shadowtrace_demo"
    )
    app = create_app(Settings("demo", ORIGIN, database, data["session"]))
    app.state.demo_keys = data["keys"]
    app.state.demo_receipt_keys = data["receipt_keys"]
    app.state.demo_impact_keys = data["impact_keys"]
    app.state.demo_protection_keys = data["protection_keys"]
    print(f"ShadowTrace demo: {ORIGIN}", flush=True)
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=WEB_PORT,
        access_log=False,
        proxy_headers=False,
        log_config=None,
        timeout_keep_alive=5,
        limit_concurrency=70,
    )


def send(key, event):
    request = Request(
        ORIGIN + "/api/v1/events",
        data=json.dumps(event).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    for attempt in range(3):
        try:
            with urlopen(request, timeout=8) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code not in {429, 502, 503, 504} or attempt == 2:
                raise RuntimeError(
                    f"Event {event['event_id']} returned HTTP {error.code}."
                ) from None
            time.sleep(min(int(error.headers.get("Retry-After", 1)), 60))
        except (URLError, TimeoutError):
            if attempt == 2:
                raise RuntimeError(
                    "ShadowTrace could not be reached. Start the demo and reuse the same run ID."
                ) from None
            time.sleep(1)


def scenario(name, slug, run_id):
    data = json.loads((STATE / "settings.json").read_text())
    runs = STATE / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    manifest = runs / f"{slug}-{name}-{run_id}.json"
    if not manifest.exists():
        from shadowtrace.demo_flow import events_for

        safe_write(manifest, events_for(name, run_id, datetime.now(UTC)))
    for event in json.loads(manifest.read_text()):
        receipt = send(data["keys"][slug], event)
        print(
            f"{event['action']:6s} {event['records_accessed']:4d} {event['resource_type']:9s} "
            f"{event['actor_id']} · {'already accepted' if receipt['replayed'] else 'accepted'}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("stop-db")
    for name in ("normal", "incident"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--workspace", choices=["northwind", "harbor"], default="northwind")
        cmd.add_argument("--run-id", default=secrets.token_hex(5))
    args = parser.parse_args()
    try:
        if args.command == "serve":
            import logging

            logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
            serve()
        elif args.command == "stop-db":
            pg("pg_ctl", "-D", STATE / "pg", "--mode", "fast", "stop")
        else:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", args.run_id):
                raise ValueError(
                    "Use 1–48 letters, numbers, hyphens or underscores for the run ID."
                )
            scenario(args.command, args.workspace, args.run_id)
    except (
        ValueError,
        RuntimeError,
        OSError,
        psycopg.Error,
        subprocess.CalledProcessError,
    ) as error:
        print(
            f"Demo command failed: {error if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

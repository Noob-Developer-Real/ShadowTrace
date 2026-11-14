import os
import secrets
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from shadowtrace.config import Settings
from shadowtrace.main import create_app
from shadowtrace.ops import grant, migrate, workspace

ORIGIN = "http://127.0.0.1:8787"
PROD = "https://trace.example.test"
ISSUER = "https://id.example.test"


@pytest.fixture(scope="module")
def database():
    bootstrap = os.environ.get("ST_TEST_BOOTSTRAP_DSN")
    app_url = os.environ.get("ST_TEST_APP_DSN")
    if not bootstrap or not app_url:
        pytest.fail("Set ST_TEST_BOOTSTRAP_DSN and ST_TEST_APP_DSN, or run scripts/test-local.sh.")
    name = "st_test_" + uuid.uuid4().hex[:12]
    with psycopg.connect(bootstrap, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        try:
            owner = make_conninfo(bootstrap, dbname=name)
            app = make_conninfo(app_url, dbname=name)
            with psycopg.connect(owner) as db:
                migrate(db)
                for slug in ("northwind", "harbor"):
                    workspace(db, slug, slug.title())
                    grant(db, slug, "demo", slug + "-analyst", slug.title() + " Analyst", "analyst")
                grant(db, "northwind", "demo", "northwind-admin", "Northwind Admin", "admin")
                grant(db, "northwind", ISSUER, "licensed-user", "SSO Analyst", "analyst")
            yield owner, app
        finally:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


@pytest.fixture
def client(database):
    app = create_app(Settings("demo", ORIGIN, database[1], secrets.token_urlsafe(48)))
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 43210)) as http:
        yield http

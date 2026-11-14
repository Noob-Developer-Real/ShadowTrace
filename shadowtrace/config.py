import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from psycopg.conninfo import conninfo_to_dict

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class Settings:
    mode: str
    origin: str
    database: str
    secret: str
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""

    @property
    def demo(self):
        return self.mode == "demo"

    @property
    def session_cookie(self):
        return "st_demo_session" if self.demo else "__Host-st_session"

    @classmethod
    def from_env(cls):
        config = cls(
            os.environ.get("ST_MODE", "production"),
            os.environ.get("ST_ORIGIN", ""),
            os.environ.get("ST_DATABASE_URL", ""),
            os.environ.get("ST_SESSION_SECRET", ""),
            os.environ.get("ST_OIDC_ISSUER", ""),
            os.environ.get("ST_OIDC_CLIENT_ID", ""),
            os.environ.get("ST_OIDC_CLIENT_SECRET", ""),
        )
        config.validate()
        return config

    def validate(self):
        origin = urlsplit(self.origin)
        if (
            self.mode not in {"demo", "production"}
            or not origin.hostname
            or origin.path
            or origin.query
            or origin.fragment
            or origin.username
            or not self.database
            or not re.fullmatch(r"[A-Za-z0-9_-]{43,256}", self.secret)
        ):
            raise ValueError("Set valid ST_MODE, ST_ORIGIN, ST_DATABASE_URL and ST_SESSION_SECRET.")
        if self.demo:
            if origin.hostname not in LOOPBACK or origin.scheme != "http":
                raise ValueError("Demo requires an HTTP loopback origin.")
        else:
            issuer = urlsplit(self.issuer)
            db_config = conninfo_to_dict(self.database)
            if (
                origin.scheme != "https"
                or issuer.scheme != "https"
                or not issuer.hostname
                or issuer.username
                or issuer.query
                or issuer.fragment
                or self.issuer.endswith("/")
                or not self.client_id
                or not self.client_secret
            ):
                raise ValueError("Production requires HTTPS and a configured OIDC client.")
            if (
                not re.fullmatch(r"/[^,]+", db_config.get("host", ""))
                and db_config.get("sslmode") != "verify-full"
            ):
                raise ValueError(
                    "Production database must use a Unix socket or sslmode=verify-full."
                )

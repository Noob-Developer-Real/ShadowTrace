import logging
import os

import uvicorn

from .config import Settings
from .main import create_app


def main():
    config = Settings.from_env()
    if config.demo:
        raise SystemExit("Use python -m scripts.demo serve for the local synthetic demo.")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if certificate := os.environ.get("ST_TLS_CERT"):
        options = {
            "ssl_certfile": certificate,
            "ssl_keyfile": os.environ["ST_TLS_KEY"],
            "proxy_headers": False,
        }
    else:
        options = {
            "proxy_headers": True,
            "forwarded_allow_ips": os.environ.get("ST_TRUSTED_PROXY", "127.0.0.1"),
        }
    uvicorn.run(
        create_app(config),
        host=os.environ.get("ST_BIND", "0.0.0.0"),
        port=int(os.environ.get("ST_PORT", "8080")),
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=15,
        limit_concurrency=80,
        **options,
    )


if __name__ == "__main__":
    main()

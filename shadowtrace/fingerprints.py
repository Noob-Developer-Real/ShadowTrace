"""Source-side helper. Keep the secret and raw identifiers in the monitored system."""

import hashlib
import hmac
import json
from uuid import UUID


def record_fingerprint(
    secret: bytes, workspace: str, token_set: UUID, resource_type: str, canonical_record_id: str
) -> str:
    if len(secret) < 32 or not canonical_record_id:
        raise ValueError("Use at least 32 secret bytes and a nonempty canonical record ID.")
    message = json.dumps(
        ["shadowtrace.record.v1", workspace, token_set.hex, resource_type, canonical_record_id],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

"""Connector and server contract for signatures over an ASCII-only receipt envelope."""

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .schema import DestinationReceipt
from .web import Issue

PROOF_LABELS = {
    "same": "Same file",
    "different": "Different file",
    "unknown": "Source digest unavailable",
    None: "Unsigned receipt",
}


def envelope(workspace, receipt):
    manifest = hashlib.sha256("".join(receipt.fingerprints).encode("ascii")).hexdigest()
    message = [
        "shadowtrace.destination-receipt.v1",
        workspace,
        receipt.receipt_id,
        receipt.export_id,
        receipt.destination,
        str(receipt.token_set),
        receipt.occurred_at.isoformat(timespec="microseconds"),
        manifest,
        receipt.artifact_sha256,
    ]
    return json.dumps(message, separators=(",", ":")).encode("ascii"), manifest


def sign_receipt(private_key, workspace, body):
    """Return a signature for a receipt body that already contains artifact_sha256."""
    # The model verifies normalized receipt fields and the public API requires both proof fields.
    receipt = DestinationReceipt.model_validate(body | {"signature": "0" * 128})
    message, _ = envelope(workspace, receipt)
    return private_key.sign(message).hex()


def verify_receipt(key, workspace, receipt, export):
    public = key["signing_public_key"]
    if not public and not receipt.signature:
        return None, None, []
    if not public or not receipt.signature or key["destination"] != receipt.destination:
        raise Issue(422, "SIGNING_KEY_REQUIRED", "Use the registered signing credential and alias.")
    message, manifest = envelope(workspace, receipt)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(receipt.signature), message
        )
    except (InvalidSignature, ValueError):
        raise Issue(
            422, "INVALID_SIGNATURE", "The destination receipt signature is invalid."
        ) from None
    source = export["artifact_sha256"]
    comparison = (
        "unknown"
        if source is None
        else "same"
        if source == receipt.artifact_sha256
        else "different"
    )
    findings = []
    if comparison == "different":
        findings.append("different")
    if export["expected_destination"] and export["expected_destination"] != receipt.destination:
        findings.append("unexpected")
    full_manifest = len(export["fingerprints"]) == export["records_accessed"]
    if full_manifest and set(receipt.fingerprints).difference(export["fingerprints"]):
        findings.append("extra")
    return manifest, comparison, findings

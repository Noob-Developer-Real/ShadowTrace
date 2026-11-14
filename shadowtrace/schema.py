import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

IDENT = r"^[A-Za-z0-9._-]{1,80}$"
SLUG = r"^[a-z0-9][a-z0-9-]{1,47}$"
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
Identifier = Annotated[str, StringConstraints(pattern=IDENT)]
Status = Literal["open", "in_review", "resolved", "dismissed"]
Severity = Literal["high", "critical"]
Action = Literal["view", "export"]
StatusList = ("open", "in_review", "resolved", "dismissed")


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")


Fingerprint = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Manifest(Payload):
    token_set: UUID
    fingerprints: Annotated[list[Fingerprint], Field(min_length=1, max_length=1000)]

    @field_validator("fingerprints")
    @classmethod
    def unique_fingerprints(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Include each fingerprint only once.")
        return sorted(values)


class Observed(Payload):
    occurred_at: datetime

    @field_validator("occurred_at", mode="before")
    @classmethod
    def utc_timestamp(cls, value):
        if not isinstance(value, str) or not RFC3339.fullmatch(value):
            raise ValueError("Use RFC 3339 with an explicit offset.")
        try:
            return datetime.fromisoformat(value).astimezone(UTC)
        except (ValueError, OverflowError) as error:
            raise ValueError("Use a valid RFC 3339 date and offset.") from error


class Event(Observed):
    event_id: Identifier
    actor_id: Identifier
    action: Action
    resource_type: Literal["customer", "order", "invoice"]
    records_accessed: Annotated[int, Field(strict=True, ge=0, le=1_000_000)]
    outcome: Literal["success", "failure"]
    lineage: Manifest | None = None
    artifact_sha256: Fingerprint | None = None
    expected_destination: Identifier | None = None
    receipt_due_minutes: Annotated[int, Field(strict=True, ge=1, le=10080)] | None = None

    @model_validator(mode="after")
    def count_matches_outcome(self):
        if (self.records_accessed > 0) != (self.outcome == "success"):
            raise ValueError("Report a positive count on success and zero on failure.")
        if self.lineage and len(self.lineage.fingerprints) > self.records_accessed:
            raise ValueError("Fingerprint count cannot exceed records accessed.")
        if (self.artifact_sha256 or self.expected_destination) and (
            self.action != "export" or not self.lineage or self.outcome != "success"
        ):
            raise ValueError("File evidence requires a successful export with a manifest.")
        if self.receipt_due_minutes and not self.expected_destination:
            raise ValueError("A receipt deadline requires an expected destination.")
        return self


class DestinationReceipt(Observed, Manifest):
    receipt_id: Identifier
    export_id: Identifier
    destination: Identifier
    artifact_sha256: Fingerprint | None = None
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")] | None = None

    @model_validator(mode="after")
    def proof_pair(self):
        if bool(self.artifact_sha256) != bool(self.signature):
            raise ValueError("Include both the destination digest and signature.")
        return self


class Review(Payload):
    version: Annotated[int, Field(strict=True, ge=1, le=2147483647)]
    mutation_id: UUID
    status: Status
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] = ""
    disposition: Literal["approved", "policy_violation", "false_positive", "other"] | None = None

    @field_validator("note")
    @classmethod
    def text_note(cls, value):
        if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
            raise ValueError("Use plain text in this note.")
        return value

    @model_validator(mode="after")
    def note_on_close(self):
        if self.status in {"resolved", "dismissed"} and not self.note:
            raise ValueError("Enter a note before closing this case.")
        if self.disposition and self.status not in {"resolved", "dismissed"}:
            raise ValueError("Choose a close reason only when closing the case.")
        return self


class Assignment(Payload):
    version: Annotated[int, Field(strict=True, ge=1, le=2147483647)]
    assignee_id: UUID | None


class Policy(Payload):
    version: Annotated[int, Field(strict=True, ge=1, le=2147483647)]
    view_limit: Annotated[int, Field(strict=True, ge=1, le=100000)]
    export_limit: Annotated[int, Field(strict=True, ge=1, le=100000)]


class KeyName(Payload):
    purpose: Literal["events", "receipts", "impact", "protection"] = "events"
    destination: Identifier | None = None
    signing_public_key: Fingerprint | None = None
    source_key_id: UUID | None = None

    @model_validator(mode="after")
    def valid_purpose_fields(self):
        if (self.purpose == "impact") != (self.source_key_id is not None):
            raise ValueError("Choose an audit event source for the impact key.")
        if bool(self.destination) != bool(self.signing_public_key) or (
            self.destination and self.purpose != "receipts"
        ):
            raise ValueError("Enter both signing fields for a signed destination key.")
        return self

    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]

    @field_validator("label")
    @classmethod
    def plain_label(cls, value):
        if not value.isprintable():
            raise ValueError("Use printable text for the key name.")
        return value

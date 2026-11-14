"""Common transfer intent and extension fields understood by source connectors."""

from datetime import UTC
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, StringConstraints, model_validator

from .schema import Fingerprint, Identifier, Observed, Payload

# boto3 treats the version as an opaque query value.
ObjectVersion = Annotated[
    str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[!-~]+$")
]


def occurrence_id(schedule_id, occurrence):
    timestamp = occurrence.astimezone(UTC).isoformat(timespec="microseconds")
    return uuid5(NAMESPACE_URL, f"shadowtrace:schedule:{schedule_id}:{timestamp}")


class ScheduleTime(Observed):
    pass


class Transfer(Payload):
    request_id: UUID
    actor_id: Identifier
    action: Literal["export", "download", "share"]
    resource_type: Literal["customer", "order", "invoice"]
    record_count: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    destination: Identifier
    content_sha256: Fingerprint
    channel: Literal["interactive", "scheduled", "cloud_link"] = "interactive"
    schedule_id: Identifier | None = None
    scheduled: ScheduleTime | None = None
    requester_id: UUID | None = None
    recipient_id: UUID | None = None
    object_version: ObjectVersion | None = None
    link_minutes: Annotated[int, Field(strict=True, ge=1, le=1440)] | None = None
    sensitive: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def channel_fields(self):
        if self.channel == "scheduled":
            if self.action != "export" or not self.schedule_id or not self.scheduled:
                raise ValueError("Scheduled exports require a schedule alias and occurrence time.")
            if self.request_id != occurrence_id(self.schedule_id, self.scheduled.occurred_at):
                raise ValueError("The operation must identify the nominal schedule occurrence.")
        elif self.schedule_id or self.scheduled:
            raise ValueError("Schedule fields require the scheduled channel.")
        cloud = (self.recipient_id, self.object_version, self.link_minutes)
        if self.channel == "cloud_link":
            if (
                self.action != "share"
                or not self.requester_id
                or not all(cloud)
                or self.object_version == "null"
            ):
                raise ValueError(
                    "Use a named recipient, requester, versioned object and link lifetime."
                )
        elif any(cloud):
            raise ValueError("Link fields require the cloud link channel.")
        return self

"""Private versioned storage used by managed cloud links."""

import os

import boto3
from botocore.config import Config

MAX_BYTES = 10 * 1024 * 1024


def object_key(workspace_id, operation_id):
    return f"shadowtrace/{workspace_id}/{operation_id}"


class S3Storage:
    def __init__(self, bucket, client):
        self.bucket = bucket
        self.client = client

    def read(self, workspace_id, operation_id, version):
        result = self.client.get_object(
            Bucket=self.bucket,
            Key=object_key(workspace_id, operation_id),
            VersionId=version,
        )
        body = result["Body"]
        try:
            if not 0 < result["ContentLength"] <= MAX_BYTES:
                raise ValueError("Unsupported object size.")
            return body.read(MAX_BYTES + 1)
        finally:
            body.close()


def storage_from_env():
    bucket = os.environ.get("ST_SHARE_S3_BUCKET")
    if not bucket:
        return None
    return S3Storage(
        bucket,
        boto3.client(
            "s3",
            config=Config(
                connect_timeout=2,
                read_timeout=3,
                retries={"total_max_attempts": 1},
                ignore_configured_endpoint_urls=True,
            ),
        ),
    )


class DemoStorage:
    """Synthetic fixture storage is keyed by a version and the precise transfer."""

    def __init__(self):
        self.objects = {}

    def put(self, workspace_id, operation_id, version, payload):
        if len(self.objects) >= 200:
            self.objects.pop(next(iter(self.objects)))
        self.objects[str(workspace_id), str(operation_id), version] = payload

    def read(self, workspace_id, operation_id, version):
        return self.objects[str(workspace_id), str(operation_id), version]

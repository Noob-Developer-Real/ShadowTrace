# Scheduled exports, managed cloud links, and approvals

Open **Protection** to set limits and review decisions. The source application still authenticates the user and decides which records and destinations that user may access. Each protected source path checks ShadowTrace before releasing data.

## Scheduled exports

The source scheduler runs the included runner once per scheduled occurrence. It can be cron, a Kubernetes CronJob, or a job platform you already operate. Give each schedule a stable alias unique within the workspace. Pass the nominal RFC 3339 scheduler timestamp, including its offset, on first execution and every retry. Do not substitute wall-clock retry time. Stage the CSV privately before calling the runner. Preserve the same file and metadata if a request is waiting for approval. The runner counts logical CSV rows excluding the header and supports files up to 10 MiB.

```sh
uv run --locked --no-dev python -m shadowtrace.scheduled_export \
  --origin https://shadowtrace.example \
  --schedule nightly-customers \
  --occurrence 2026-11-15T02:00:00Z \
  --actor svc-customer-exports \
  --destination internal-vault \
  --resource customer \
  --input /private/staging/nightly-customers.csv \
  --output-dir /private/delivery \
  --sensitive
```

Inject `ST_PROTECTION_KEY` with the scheduler’s secret manager. The output directory is a private, local filesystem handoff under source control. A downstream worker can deliver its files using their stable names. The runner writes a file named for the operation UUID with mode 0600 and publishes it atomically without overwriting an existing file. It returns exit code 75 while waiting for approval and 1 for withheld, duplicate or uncertain releases. Design the scheduler to stop at its normal retry and age bounds. Investigate uncertain execution through the source delivery state before authorizing another operation. Kubernetes users can use a CronJob with appropriate concurrency and deadline settings. [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

The API uses `channel: "scheduled"`, `schedule_id` and `scheduled: {"occurred_at":"<nominal RFC 3339 time>"}`. Its `request_id` must be UUIDv5 under the standard URL namespace over the UTF-8 string `shadowtrace:schedule:<schedule_id>:<UTC time>`, where UTC time uses six fractional digits and the `+00:00` offset.

## Managed S3 links

Configure `ST_SHARE_S3_BUCKET` and the AWS region in the server environment. Enable S3 versioning, Block Public Access and server-side encryption. Give the ShadowTrace runtime a read-only workload role scoped to `s3:GetObjectVersion` under the configured bucket’s `shadowtrace/` prefix, plus decrypt permission on the intended key if using customer-managed encryption. Give the staging source a separate writer role limited to its workspace prefix. Configure object lifecycle and the workspace retention policy. Use TLS on the public application endpoint and private or policy-restricted access to the bucket. The runtime uses the AWS SDK credential provider chain. [Amazon S3 versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) · [S3 GetObject](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_object.html)

Stage the exact CSV under `shadowtrace/<workspace UUID>/<operation UUID>` in the configured bucket. Record the resulting version ID. Use the **Workspace principal IDs** panel under **Protection** to map a trusted source identity to its requester and recipient IDs. Call the CLI with the staged bytes and exact metadata. One operation creates at most one link. Retrying an approved intent uses the same ID, bytes, and version. Inaccessible staging objects leave the download unavailable. The shipped CLI covers CSV files and the API can authorize other immutable formats up to the same reader limit.

```sh
uv run --locked --no-dev python -m shadowtrace.cloud_link_cli \
  --origin https://shadowtrace.example \
  --workspace example \
  --operation a174d419-d14c-45bd-8366-80175c0c386c \
  --requester 5ef8a53f-a17c-490c-8518-47f3c6930e1c \
  --recipient 588974e3-3182-4072-95ea-9640f285388a \
  --actor support-42 --destination internal-vault --resource customer \
  --object-version "$ST_OBJECT_VERSION" --minutes 30 --input /private/staging/customer.csv
```

The API uses action `share` and `channel: "cloud_link"`, with `requester_id`, `recipient_id`, `object_version`, and `link_minutes` (1–1440). ShadowTrace returns a `link_path` for the allowed operation. Its download route requires the named recipient’s current workspace membership. It reads the fixed object version, verifies its SHA-256, checks current link state and policy before release, and records the authorization in the audit log. The recipient receives the file through ShadowTrace over HTTPS. An admin can revoke access from **Protection → Cloud links**. Revocation applies to future downloads. Content already received remains with its recipient. Pausing protection, removing the destination alias, or reducing the share limit below the transfer count also withholds future downloads. Lowering a cumulative limit affects authorization of new transfers. A link’s repeated downloads of the same object do not create new reservations.

## Sensitive transfers and cumulative limits

- **Customer approval threshold** requires approval at or above the configured customer record count. Zero disables the threshold. A trusted source may send `sensitive: true` to require independent review for any resource. Interactive and cloud requests require `requester_id` when reviewed. Machine schedules can omit it. Reviewers must be workspace admins and cannot approve or deny their own request. Decisions appear in the audit log.
- A pending operation returns HTTP 202 with `outcome: "pending"`, `request_id` and `expires_at`. The reference connector raises `ApprovalRequired` and withholds the output. Hold the same operation, then retry with identical metadata, credential and content digest after approval. A policy change, expiry, credential change or modified intent requires a fresh request. For a scheduled task, wait for the next occurrence or open a separate recovery operation under your source release policy. A denied approval returns a blocked decision on retry. Approval expires after 24 hours. Existing release policies continue until explicitly updated.
- **24-hour actor limit** counts authorized record volume across export, download and share actions, including different credentials and destinations. The source must use one stable pseudonymous alias per person or scheduled service across its integrations. PostgreSQL serializes decisions for each workspace and actor, so simultaneous requests cannot exceed the limit. Zero disables the cumulative rule. Authorized operations count immediately, including later delivery failures. Pending and blocked operations add zero. Counts represent rows authorized, including repeated rows. [PostgreSQL transaction locks](https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS)

The local demo uses synthetic transfers and an in-process object store. Demo links expire or can be revoked through the normal controls. They also become unavailable after restarting the demo because synthetic object bytes are held in memory.

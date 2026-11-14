# Enforce protection at the source

ShadowTrace’s Protection workflow helps connected applications decide whether to release an export, download or share. It follows a policy decision and enforcement separation like the one described in [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final). Your source app stays responsible for enforcing the outcome and authenticating and authorizing its users.

## Configure the workspace

1. In **Settings → Integration**, create a **Protection checks** credential for each application and store it in the application’s secret store. An event, receipt or customer impact token cannot authorize transfers.
2. In **Protection**, set limits for export, download and share. Use zero to disable an action. Enter up to 20 exact destination aliases and choose **Active** to permit matching requests. **Paused** denies every new protected transfer. Unsaved workspaces start paused.
3. Map each alias to a known destination and route it on the source’s server. For a download, assign an alias only after the source verifies the type of download it is willing to allow, such as a managed workstation session. The alias itself does not attest that a device is managed. Treat arbitrary user-supplied URLs, external identities, permissions and routes as untrusted source inputs.

## Integrate a release

After the source authorizes the user, prepare the exact output in a private buffer or staging area with no public URL. Count the actual selected records and bind the action, destination and payload to a durable source operation ID. Put the check on every relevant server path, including background jobs, service accounts and alternate download routes. Do not initiate transfer, issue a usable link or apply a share permission before receiving a valid new authorization.

Use `shadowtrace.enforce.release_protected` with an `httpx.AsyncClient` configured for the trusted ShadowTrace HTTPS origin. Enable certificate verification, set `trust_env=False` unless your organization requires a verified private proxy, and keep the source and service clocks synchronized. The callback receives the same immutable bytes and alias used for the check.

```python
async with httpx.AsyncClient(base_url=trace_origin, trust_env=False) as client:
    try:
        result = await release_protected(
            client,
            credential=protection_secret,
            request_id=source_operation_uuid,
            actor_id=staff_pseudonym,
            action="export",
            resource_type="customer",
            record_count=actual_row_count,
            destination=verified_destination_alias,
            content=private_prepared_bytes,
            release=deliver_to_registered_destination,
        )
    except ReleaseDenied:
        return blocked_or_retry_page()
```

For a share, the immutable content can be the source’s canonical serialization of the exact sharing operation, including resource and target identity as resolved by the source. The callback should perform only that operation and enforce its existing permissions. The service receives a digest and metadata. It does not receive the staged bytes.

### Wire contract

Send bearer-authenticated `POST /api/v1/protection/authorize` over HTTPS. Maximum request size is 16 KiB. A source credential is limited to 240 integration calls per minute. The object contains:

| Field | Value |
|---|---|
| `request_id` | Source-owned UUID, unique per operation across the workspace |
| `actor_id` | Opaque identifier, 1–80 letters, digits, dots, underscores or hyphens |
| `action` | `export`, `download`, or `share` |
| `resource_type` | `customer`, `order`, or `invoice` |
| `record_count` | Integer from 1 to 1,000,000 |
| `destination` | Server-resolved opaque alias, same format as actor ID |
| `content_sha256` | SHA-256 of staged bytes, 64 lowercase hex characters |

HTTP 201 returns `request_id`, `content_sha256`, `outcome` (`allowed` or `blocked`), `reason`, `policy_version` and `decided_at`. Policy reasons are `paused`, `destination`, `disabled`, `limit`, and `allowed`. Confirm the new response matches the ID and hash. Fail closed on any unrecognized response, timeout, credential failure or policy denial. The reference connector uses a three-second HTTP timeout and checks timing and response identity before invoking the release callback. The endpoint records one authorization decision, not proof of delivery.

HTTP 409 means the operation already has a saved decision, even after switching credentials. A lost response can result in an authorization visible to an analyst while the source withheld the data. Check the source action and delivery state before creating a fresh operation. Avoid replaying the release or minting replacement operation IDs automatically. The source owns durable idempotency for delivery, including cases where the destination received bytes but its response was lost. Workspace retention purges historical decisions, so retain source operation IDs and avoid reusing them. Policy edits apply to new decisions. A payload already authorized or shared has its own source-side timing and revocation behavior.

## Verify a rollout

Start with a low-risk integration in staging. Confirm a known destination and bounded transfer work and test a blocked destination, oversized export, stale or duplicate operation, and a simulated ShadowTrace outage. Confirm no bytes, usable links or permissions are released when a check fails. Monitor authorization latency, blocked counts and rate-limit or availability failures. Test every instrumented source path and retain a local release receipt or delivery marker if needed. Receipt signing and Record lineage remain available for post-transfer investigation.

On the local demo, **Protection → Run protection demo** invokes the real decision endpoint and sends a synthetic CSV to an in-process receiver. The personal-drive attempt must leave that receiver at zero bytes. Production excludes the demo.

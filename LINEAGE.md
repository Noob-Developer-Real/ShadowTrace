# Record lineage

Record lineage answers three incident questions about an individual export: Which exported record identities also appeared in the actor’s earlier views? Which exported identities did a destination source report? Which remain unaccounted for in connected telemetry?

Activity-sequence tools already correlate behavior, and exact-data matching systems already use fingerprints. For examples, see Microsoft Purview’s [sequence policies](https://learn.microsoft.com/en-us/purview/insider-risk-management-policies) and [Exact Data Match](https://learn.microsoft.com/en-us/purview/sit-learn-about-exact-data-match-based-sits). Data lineage standards such as the [OpenLineage lineage job facet](https://openlineage.io/docs/spec/facets/job-facets/lineage/) describe flows between jobs, datasets and fields. ShadowTrace’s focus is an investigator’s count of overlapping record identities across actor activity, a specific export and receipts reported by separately credentialed integrations, with coverage gaps visible in the case.

## Connect sources

1. An admin creates an **Audit events** key for each monitored app and a **Destination receipts** key for each receiving integration. Keep each key in its owning integration’s secret store. Event keys cannot report destination receipts. Receipt keys cannot submit view or export events.
2. Provision a secret of at least 32 random bytes for HMAC in the authorized connectors, separately from their API keys. Use a separate secret per workspace. Agree on one canonical record ID per logical record and one UUID for the token set. With Python, use `shadowtrace.fingerprints.record_fingerprint` on the connector. It uses HMAC-SHA256 over a compact UTF-8 JSON array: `["shadowtrace.record.v1", workspace_slug, token_set_uuid_hex_without_hyphens, resource_type, canonical_record_id]`. Match canonicalization across connectors precisely. Rotate the secret with a new token set; keep the old set and secret usable on trusted connectors for outstanding exports during the planned transition. Matching across token sets is disabled.
3. A successful audit event can include `"lineage": {"token_set": "<uuid>", "fingerprints": ["<64 lowercase hexadecimal characters>", "..."]}`. Send only identities the app actually observed. A manifest can contain up to 1,000 distinct fingerprints and may cover fewer records than the reported count. Legacy events require no changes.
4. After observing records for an export at a destination, send `POST /api/v1/receipts` with the receipt key in the Bearer header and the following JSON fields.

| Field | Required value |
|---|---|
| `receipt_id` | Stable delivery ID, 1–80 letters, digits, underscores, dots or hyphens |
| `export_id` | ID of the original successful export with a manifest in this workspace; pass it along in your transfer metadata |
| `destination` | Opaque connector-assigned destination alias, same alphabet and length as IDs |
| `token_set` | The export’s fingerprint token-set UUID |
| `fingerprints` | 1–1,000 unique lowercase HMAC-SHA256 hex values computed for records actually observed at the destination |
| `occurred_at` | RFC 3339 timestamp with offset, at or after the export; no more than seven days old or five minutes ahead |

The destination must report its observation after the export event is ingested. For delivery reordering, queue and retry a 404 with bounded backoff only if the connector expects the parent export. Both endpoints accept up to 80 KiB and default to 240 requests per key per minute. The first successful receipt returns 201 with its receipt ID and acceptance time. Replay is 200 with `replayed: true` for the same credential, receipt ID and normalized payload. Changes under a previously accepted ID and replays from a different key return 409. Keep the same ID and payload for network retries; respect `Retry-After` when supplied.

## Interpret a trace

- `Previously viewed` and `Matched at destination` are subsets of the export manifest, not sequential totals. A record can be at a destination with no recorded prior view. `Matched across all three stages` is the intersection. Repeated sightings do not inflate counts.
- A receipt can contain identities outside the export manifest. This may reflect a mismatch, an incomplete export manifest or a receipt that covers more than that export. A missing match means destination unknown. Results are limited to seven days of earlier views for the same actor and resource, 500 eligible view reports and 50 destination receipts. The page flags when the report cap was reached and more reports were omitted. Receipt and view summaries show the most recent ten relevant reports of each kind.
- A case download captures the trace for up to three manifested exports among its saved evidence events, with an omission flag when relevant. It contains aggregates and source report metadata. Raw fingerprints are excluded from pages and evidence downloads; the database stores them for correlation and removes them under event retention.
- The design provides credential attribution and overlap of reported identities within instrumented systems. It does not prove a payload’s bytes, a third party’s possession, or an attacker’s intent. A compromised integration may send false claims. Pseudonyms are deliberately linkable inside a token set. Protect backups and avoid case notes, aliases or event labels that contain raw personal data.

Candidates for the next release: bind destination keys to registered endpoints and sign receipts over an export artifact digest; add an approved, audited workflow that resolves affected record IDs inside the customer’s source environment for incident response; expand large-export support with chunked manifests and completeness checks.

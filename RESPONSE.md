# Signed receipts, customer impact, and follow-up

## Verify a destination report

In **Settings → Integration → Create key**, choose **Destination receipts**. Enter the destination alias and the receiving connector’s Ed25519 public key as 64 lowercase hexadecimal characters representing the raw 32 bytes. Keep the private key in the destination environment. Use the new bearer token for signed delivery. Register different credentials for independent destinations. To rotate, create a credential with a new label and public key, switch the connector, then revoke the old credential. Already accepted signatures still identify the signer registered at intake.

For a successful export with a fingerprint manifest, the source may add these event fields:

| Field | Purpose |
|---|---|
| `artifact_sha256` | SHA-256 of the exact exported file bytes. Use 64 lowercase hexadecimal characters. |
| `expected_destination` | Alias that should report the receipt. Setting it starts monitoring for that export. |
| `receipt_due_minutes` | Optional 1–10,080 minutes from export acceptance. Defaults to 60. |

The destination computes `artifact_sha256` over the exact bytes it received, forms a normal receipt as in [LINEAGE.md](LINEAGE.md), and adds the `signature` field. Use `shadowtrace.receipt_proof.sign_receipt(private_key, workspace_slug, body)` to obtain the 128-character lowercase hexadecimal Ed25519 signature. The equivalent cross-language format is this compact JSON array encoded as ASCII:

```text
["shadowtrace.destination-receipt.v1",workspace_slug,receipt_id,export_id,destination,token_set,occurred_at,manifest_sha256,artifact_sha256]
```

The array contains strings, separated by commas without whitespace. Normalize `token_set` to lowercase hyphenated UUID format and `occurred_at` to UTC with six fractional digits and a `+00:00` offset. Sort the distinct fixed-width fingerprint strings lexicographically, concatenate them without delimiters, and hash those ASCII bytes to produce `manifest_sha256`. The signed report includes the workspace, IDs, alias, observation time, record manifest digest and file digest. See [Ed25519 library guidance](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

The server authenticates the receipt bearer and checks its registered alias and signature before saving. A registered signer must submit signed receipts. A legacy key without a signer may send unsigned receipts. Exact retry under the original active key is safe. Keep the receipt ID and payload stable across retries. An evidence download contains the public key, signed fields and signature for each included signed receipt. Independent verification should compare the included public key with the registered key held in the verifier’s own trust records. The receipt authenticates a connector’s report and a file digest comparison. It cannot establish what a compromised connector actually observed.

## Resolve customer impact in the source system

From Record lineage for a manifested customer export, open or locate the case, then select **Export manifest** or **Same-file receipt matches**, choose a reason, and enter an incident ticket ID. A different workspace admin approves the request. The requester or a workspace admin can cancel pending or approved work. The request expires 24 hours after creation. The result is scoped to the fingerprints saved when the request was created. Export manifest can include only a subset of the source’s reported count. Late receipts do not silently change an approved request. The approved lookup can be rerun locally while the job is active. Start a new request to use a new snapshot.

Set up a **Customer impact** key in Settings and bind it to the source audit event credential used for that export. This is a separate bearer token. Authorize it only for the resolver inside the source environment. An operator takes the approved request UUID from Record lineage and runs the supplied resolver with the source fingerprint secret and canonical ID catalog. Configure secrets outside shell history in the process environment via the source’s secret manager.

```sh
uv run --locked --no-dev python -m shadowtrace.resolve_impact \
  --origin https://shadowtrace.example \
  --workspace example \
  --job 0c934881-06f2-469c-8a2c-96a072f03714 \
  --catalog /private/source/customer-ids.txt \
  --output /private/source/INC-1042-result.json
```

The connector reads `ST_IMPACT_KEY` and `ST_RECORD_SECRET_HEX`. Use the secret for the job’s token set. If your deployment uses custom certificate authorities, set `ST_RESOLVER_CA` to the private CA bundle. The catalog holds one original canonical UTF-8 ID per line. Keep the result directory private. The local result file contains customer IDs and uses owner-only permissions. If delivery of the count is interrupted, rerun with the same job and output path. Confirm an accepted completion before using the results. Cancellation stops future pulls and result submission. A snapshot delivered before cancellation may already exist on the source connector and should be handled under your incident and retention procedures.

For a custom resolver, use `GET /api/v1/impact-jobs/{job_id}` with the impact bearer. The response includes the token set, approved fingerprints, scope, export ID and expiry. Complete via `POST /api/v1/impact-jobs/{job_id}/complete` with only `{"matched_count": 42}`. Report unique canonical IDs matched. The server enforces a nonnegative count up to the snapshot size. The source resolves identities and sends a count. The case trace and its evidence download include request status, reference, reason and reported count. Audit history records request, approval, snapshot delivery, cancellation and completion.

## Work the follow-up queue

Open **Cases → Follow-up**. Select a reason, review state, or **My cases**, then apply. **Save filters** stores one personal view per workspace. A copied filtered URL opens the same filters and still requires membership. **Clear** returns to the default for the current view.

An overdue item requires an expected destination and a deadline. Only a signed report from that alias whose digest comparison does not contradict the source can satisfy it. The queue also tracks the first qualifying receipt that arrived after the deadline, a signed report from a different alias, a different file digest, or extra reported records when the source supplied fingerprints for every exported row. It uses ShadowTrace’s acceptance time for deadline comparisons. Closing a case records its review. Later material findings return the export to **Needs review** and invalidate older versions of the review form. Use the case review form to reopen it. For an export without a case, open the trace and use **Open a case**.

The queue reads retained evidence when opened. Refresh to see newly arrived reports. Cases and receipts follow workspace retention. No scheduled delivery or external notifications are needed for the in-app queue.

# ShadowTrace · Vihaan X

ShadowTrace receives audit metadata from business applications and turns unusual access into an explainable case. It groups a burst of sensitive-record views and a subsequent export by workspace, actor and resource. Record lineage lets analysts compare the actual record identities reported by earlier views, exports and separately credentialed destination integrations without collecting raw record IDs.

## Run the local demo

Requirements are Python 3.12–3.14, uv, and PostgreSQL 16 or newer client/server tools. On this Mac the launcher finds the installed Homebrew PostgreSQL 16 binaries. On Linux set `ST_PG_BIN` to the directory containing `initdb` and `pg_ctl` if those commands are not on PATH. The first package install needs internet. All demo data and application assets are local after installing dependencies.

On a Mac, open **Start ShadowTrace.command** in the extracted folder, or run this from a terminal:

```sh
./scripts/demo.sh serve
```

On Windows, install `uv` and PostgreSQL 16 or newer, then open **Start ShadowTrace.bat**. If PostgreSQL is installed outside the default `C:\Program Files\PostgreSQL\16\bin` folder, set `ST_PG_BIN` to the folder containing `initdb.exe` and `pg_ctl.exe` before opening the launcher.

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). The dedicated demo database and synthetic ingest keys live in `.demo/` with restrictive permissions. Use `ST_DEMO_STATE`, `ST_DEMO_PORT` and `ST_DEMO_DB_PORT` on all commands to select another isolated run. Keep the state path short on macOS and Linux because PostgreSQL uses a Unix socket. On Windows, the demo uses PostgreSQL TCP bound only to loopback. The app listens on loopback on every platform.

## Walk through the live demo

1. Sign in as **Northwind Commerce · Analyst**. In **Overview**, choose **Run record lineage demo**, then **Open record lineage**. The source reports 570 exported records. Of those, 520 were also reported by prior views and 410 matched a destination receipt. Exactly 390 matched across all three stages. The destination is unknown for 160 tracked records. A second, mismatched file receipt contains 12 fingerprints outside the export manifest.
2. Open the related case. At the default rules the synthetic 620-record view burst is 18.2 times the actor’s prior 90th percentile. Open **View actor profile** for the history. Assign an owner, write a review, and use **Download evidence** for the case record and its lineage snapshot.
3. Sign in as **Harbor Supply · Analyst** and paste the Northwind trace URL. The app returns its generic unavailable page.
4. Sign in as **Northwind Commerce · Workspace admin**. **Settings → Integration** shows the audit and destination sources separately. In **Settings → Rules**, try raising both thresholds to 1,000 and choose **Preview impact**. Check which rule matches would disappear.
5. **Run normal activity** and **Run suspicious export** are also available for legacy count-only scenarios.

The launcher's temporary database captures the results. Use a fresh `ST_DEMO_STATE` for an empty rehearsal. The equivalent CLI commands remain available:

```sh
./scripts/demo.sh normal --run-id vihaan-live
./scripts/demo.sh incident --run-id vihaan-live
./scripts/demo.sh normal --workspace harbor --run-id vihaan-live
```

A repeated CLI run uses the original event IDs. Both browser incident scenarios also load twelve synthetic history windows. The browser Record lineage scenario delivers through both real endpoints with synthetic inputs. Ctrl+C stops the app. Use `./scripts/demo.sh stop-db` with the same state environment to stop its database.

To check a downloaded evidence bundle:

```sh
uv run --locked --no-dev python -m shadowtrace.integrity /path/to/shadowtrace-case.json
```

The verifier checks the SHA-256 digest of the canonical evidence JSON. To verify a file came from your workspace export, compare the digest with the value you recorded at download. Treat the bundle as sensitive workspace data.

## Demo the incident response workflow

1. Sign in as **Northwind Commerce · Analyst** and run the record lineage demo. Its two signed reports demonstrate **Same file** and **Different file** with overlapping records.
2. In **Customer impact**, request the **Export manifest** scope for incident scoping with a ticket such as `INC-1042`.
3. Open the same trace as **Northwind Commerce · Workspace admin**. Approve the lookup and choose **Run synthetic resolver**. The deliberately incomplete fixture catalog resolves 520 of the 570 tracked records.
4. Open **Cases → Follow-up** and inspect the file difference. Save a filter view, open the case, and record a review. Choose **Reviewed** to find the export after closure.

See [RESPONSE.md](RESPONSE.md) for production connector setup, signed payloads, approval, and operating behavior.

## Try active protection

Open **Protection → Run protection demo**. The source releases a synthetic CSV to an approved destination and withholds it from a personal drive. In the admin view, change the action limits or pause new releases, then inspect the decision history. See [PROTECTION.md](PROTECTION.md) to enforce the same check in a connected source.

## Try managed transfers

In **Protection → Try managed transfers**, run a scheduled export with sensitive approval required. A workspace admin reviews it under **Approvals**, then the source retries the same occurrence. Create a managed cloud link for a workspace member, download it as that recipient, then revoke it as an admin. Set a **24-hour actor limit** to cap combined authorized volume. The [managed transfer guide](MANAGED-TRANSFERS.md) covers the scheduler, S3 and API setup.

## Ingest contract

Send `POST /api/v1/events` with `Authorization: Bearer <integration-key>` and `Content-Type: application/json`. An admin creates and revokes keys under **Settings → Integration**. Keep the one-time secret in the source application’s secret store. Only send allowlisted audit metadata.

| Field | Value |
|---|---|
| `event_id`, `actor_id` | 1–80 letters, digits, dots, underscores or hyphens. Use a stable unique event ID and a pseudonymous actor ID. |
| `action` | `view` or `export` |
| `resource_type` | `customer`, `order` or `invoice` |
| `records_accessed` | Integer 1–1,000,000 on success, 0 on failure |
| `occurred_at` | RFC 3339 with explicit offset. At most seven days old and five minutes in the future. |
| `outcome` | `success` or `failure` |
| `lineage` | Optional fingerprint manifest for successful views and exports. See [LINEAGE.md](LINEAGE.md). |

201 is an accepted event. 200 with `replayed: true` is a replay of the same accepted event. 409 means that event ID already exists with different content. For response loss, 429 or temporary 5xx, honor `Retry-After` when supplied and use bounded backoff with the same event ID and payload. 401 requires a valid key. 4xx schema errors require a corrected request. The event API does not expose cases. Workspace comes from the key. The event and receipt endpoints cap requests at 80 KiB. The default limit is 240 requests per key per minute.

The five-minute view rule is computed by receipt time. The export rule uses the count in one successful event. The ten-minute correlation window groups qualifying signals into an Open or In review case. Closed cases retain their history. Each signal records the policy version, threshold, and measured count. Treat cases as a queue for human review.

## Verify or deploy

```sh
uv sync --locked
./scripts/test-local.sh -q
uv run --locked ruff check
uv run --locked ruff format --check
```

See [OPERATIONS.md](OPERATIONS.md) for a controlled deployment, backup/restore and rollbacks. See [RELEASE.md](RELEASE.md) for the verification record and remaining deployment evidence. Release sources include the pinned container build and CI checks.

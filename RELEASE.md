# ShadowTrace 1.5.0 release record

14 November 2026 · Local release and deployment candidate

Scheduled exports, private managed cloud links, sensitive transfer approvals and rolling actor limits extend the Protection workflow. See [MANAGED-TRANSFERS.md](MANAGED-TRANSFERS.md) for setup and [OPERATIONS.md](OPERATIONS.md) for the upgrade.

| Area | Verified result |
|---|---|
| Scheduled exports | The standalone runner withheld output until independent approval, delivered one mode-0600 CSV and rejected a duplicate trigger. Tests verify occurrence binding and CSV row counts. |
| Cloud links | Chrome exercised named recipient access and admin revocation. Tests covered foreign and wrong recipients, expiry, digest mismatch and the AWS SDK request for the exact private object version. The local demo uses synthetic storage. The AWS call was stubbed, so a configured S3 bucket, workload role and customer SSO still require staging validation. |
| Approval and limits | Tests covered self-review rejection, expired and changed approvals, repeat authorization, credential separation and concurrent transfers across destinations and keys. A 20-record actor limit authorized one 12-record transfer and blocked the other. |
| Release checks | 28 tests passed locally and with a restricted PostgreSQL role over verified TLS. Chrome checks covered the packaged workflow and sampled accessibility at desktop and 320 CSS pixels in dark appearance. No known issues were reported by the pinned dependency audit. Migration 006 preserved prior records and protection settings. |

The export runner uses the source’s existing scheduler. Cloud links cover the configured private S3 bucket and use workspace membership for recipients. Staging should verify protected routes, representative file sizes, expected volume and operational ownership.

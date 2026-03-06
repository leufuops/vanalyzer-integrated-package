# Automox Integration Guide

## Overview
This guide explains how to configure the Automox integration in vAnalyzer.
The integration pulls asset inventory, pending software updates, and CVE data from the **Automox REST API** and stores it in the following tables:

- `automox_assets_inventory` — Device/endpoint inventory and hardware details
- `automox_pending_software` — Pending software updates per device
- `automox_asset_cves` — Asset ↔ CVE relationships derived from pending patches
- `automox_etl_runs` — ETL execution audit log

> **ETL behavior:** vAnalyzer creates an Automox ETL that runs **every 6 hours by default** (or as defined during vAnalyzer installation). It keeps the data updated automatically.

---

## Prerequisites

- An active **Automox** account with at least one organization configured
- A user account with the **Administrator** role in your Automox organization (recommended to generate API keys)
- Your Automox **Organization ID** (numeric value shown in **Global Setup → Organizations**)

---

## Step 1 — Locate Your Organization ID

The Organization ID is a numeric identifier that scopes all API calls to your specific organization.

### 1.1 Via Global Setup → Organizations (recommended)

1. Go to:
   - `https://console.automox.com/global/setup/organizations?limit=25&page=1`
2. In the table, locate your organization and copy the value in the **Organization ID** column.

> **Tip:** Do **not** use **Organization UUID** (GUID). vAnalyzer requires the **Organization ID** integer (e.g., `126036`).

### 1.2 Via the Automox Console URL (alternative)

In many pages, the org is referenced by the `o=` query parameter:

```
https://console.automox.com/settings/keys?o=123456
                                         ^^^^^^
                                    Organization ID
```

Copy the numeric value after `?o=` — this is your **Organization ID**.

---

## Step 2 — Generate an API Key

Automox API keys can be generated as **Global API Keys** (usable across all organizations in the account) or as organization-scoped keys depending on your console/plan.

### 2.1 Global API Keys (recommended)

1. Go to:
   - `https://console.automox.com/global/setup/api-keys`
2. Under **Global API Keys**, click **Add**
3. Fill in the form:

| Field | Value |
|---|---|
| **Name / Description** | `vAnalyzer Integration` (or any name you prefer) |
| **Expiration** | Choose an appropriate expiry, or leave as non-expiring if your policy allows |

4. Click **Create / Generate**
5. **IMPORTANT:** Copy the API key value immediately — it may only be shown once.

```
API Key Value  →  automox_api_key
```

> ⚠️ If you close the dialog without copying the key, you must delete it and generate a new one.

### 2.2 Required Permissions

The API key inherits the permissions of the user who created it.
The generating user should have sufficient permissions (Administrator recommended) so the ETL can read:

- Device/server inventory (`/servers`)
- Package and patch data (`/servers/{id}/packages`)
- Organization details (`/orgs`)

> **Tip:** For security best practices, create a dedicated **service account** user in Automox with
> the minimum required role (Administrator), and generate the API key from that account.

---

## Step 3 — Configure vAnalyzer

Run the interactive setup and enter the values collected in Steps 1 and 2:

```bash
vanalyzer init
```

When prompted for the Automox integration:

```
Enable Automox integration? [y/N]: y

Enter Automox API Key:           [hidden]
Enter Automox Organization ID:   123456
```

The setup will create two Docker secrets automatically:

| Docker Secret | Description |
|---|---|
| `automox_api_key` | Your Automox API key |
| `automox_org_id` | Your Automox numeric Organization ID |

---

## Step 4 — Verify the Integration

After deploying or restarting vAnalyzer, the Automox sync will run as part of the regular schedule.
You can verify it is working by checking the ETL run log:

```sql
SELECT run_id, started_at, finished_at, status,
       rows_assets, rows_pending_sw, rows_cves, error_message
FROM automox_etl_runs
ORDER BY started_at DESC
LIMIT 10;
```

A successful run will show `status = 'success'` (or `'partial'` if some devices had fetch errors)
and non-zero values in `rows_assets`, `rows_pending_sw`, and `rows_cves`.

To check synced assets:

```sql
SELECT hostname, os_name, os_version, last_seen_at, pending_patches_count
FROM automox_assets_inventory
ORDER BY ingested_at DESC
LIMIT 20;
```

---

## Troubleshooting

| Symptom | Likely Cause | Solution |
|---|---|---|
| `status = 'error'` in `automox_etl_runs` | Invalid API key or Org ID | Re-run `vanalyzer init` and re-enter the credentials |
| `rows_assets = 0` | API key lacks permissions or wrong Org ID | Verify the key owner has Administrator role; confirm the Org ID |
| `rows_cves = 0` but assets present | No pending patches with CVE data | Normal if all devices are fully patched |
| HTTP 401 in logs | Expired or revoked API key | Generate a new API key and update the Docker secret |
| HTTP 429 in logs | API rate limit hit | Reduce `AUTOMOX_LIMIT` env var or increase `AUTOMOX_SLEEP_S` |

### Updating Credentials After Initial Setup

If you need to rotate the API key without re-running the full `vanalyzer init`:

```bash
# Remove and recreate the secret
docker secret rm automox_api_key
echo "your_new_api_key" | docker secret create automox_api_key -

# Redeploy the stack to pick up the new secret
vanalyzer deploy
```

---

## Environment Variables (Advanced)

The following optional environment variables can be set in your `.env` file to tune the Automox ETL behavior:

| Variable | Default | Description |
|---|---|---|
| `AUTOMOX_LIMIT` | `500` | Page size for API pagination (max 500) |
| `AUTOMOX_MAX_PACKAGES` | `0` (unlimited) | Max packages to fetch per device (0 = all) |
| `AUTOMOX_TIMEOUT_S` | `60` | HTTP request timeout in seconds |
| `AUTOMOX_RETRIES` | `6` | Number of retries on transient errors |
| `AUTOMOX_SLEEP_S` | `0.05` | Delay in seconds between API requests |
| `AUTOMOX_MIN_CVSS` | *(none)* | Only store CVEs at or above this CVSS score |
| `AUTOMOX_DRY_RUN` | `false` | If `true`, fetches data but does not write to DB |
| `AUTOMOX_FETCH_INVENTORY` | `true` | Fetch extended hardware/OS inventory per device |
| `AUTOMOX_BASE_URL` | `https://console.automox.com/api` | Override the Automox API base URL |
| `AUTOMOX_VERIFY_SSL` | `true` | Set to `false` to skip SSL verification (not recommended) |
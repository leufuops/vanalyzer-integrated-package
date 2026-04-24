# Sevco (Arctic Wolf) Integration Guide

## Overview

This guide explains how to configure the Sevco (Arctic Wolf) integration in vAnalyzer.
The integration pulls unified asset inventory, vulnerability data, and CVE-to-device mappings from the **Sevco REST API** and stores it in the following tables:

- `sevco_device` — Unified device/endpoint inventory across all connected sources
- `sevco_vuln` — Vulnerability catalog exploded by scanner source (Tenable, MDE, etc.)
- `sevco_vuln_device` — CVE ↔ device mapping (one row per affected device per CVE)
- `sevco_device_event` — Telemetry attribute change events per device
- `sevco_etl_runs` — ETL execution audit log

> **ETL behavior:** vAnalyzer creates a Sevco ETL that runs **every 6 hours by default** (or as defined during vAnalyzer installation). The CVE-to-device mapping step runs in parallel using 8 workers to handle large CVE catalogs efficiently.

---

## Prerequisites

- An active **Sevco** (Arctic Wolf) account with at least one organization configured
- Access to the **Sevco console** at `https://console.sev.co`
- A Sevco API token with read access to your organization's asset inventory and vulnerability data

---

## Step 1 — Locate Your Organization ID

The Organization ID scopes all API calls to your specific Sevco organization. The easiest way to find it is by querying the Sevco API directly with your token.

### 1.1 Via cURL (recommended)

Once you have your API token (see Step 2), run the following command to list your organizations and find the correct ID:

```bash
curl -s -X GET "https://api.sev.co/v1/orgs" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

The response will look like:

```json
[
  {
    "id": "2c8a1f3d-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "Arauco Chile",
    "slug": "arauco-cl",
    "created_at": "2023-08-14T10:22:00Z"
  }
]
```

Copy the `"id"` field — this is your **Organization ID** (`sevco_org_id`).

> **Tip:** If you have multiple organizations, you will see multiple entries in the array. Select the `"id"` corresponding to the organization whose assets you want to sync into vAnalyzer.

### 1.2 Verify the Organization ID

You can verify the ID is correct by querying device inventory scoped to that organization:

```bash
curl -s -X POST "https://api.sev.co/v3/asset/device" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "x-sevco-target-org: YOUR_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{"query": {}, "pagination": {"limit": 1, "page": 0}}' | python3 -m json.tool
```

A successful response will contain a `"pagination"` object with a `"total"` field showing the number of devices in that organization. An incorrect Org ID will return an HTTP 403 or an empty result.

---

## Step 2 — Generate an API Token

Sevco API tokens are generated per user from the Sevco console.

### 2.1 Create a Token via the Console

1. Log in to the Sevco console: `https://console.sev.co`
2. Navigate to **Settings → API Keys** (or **User Settings → API Tokens** depending on your console version)
3. Click **Create API Key** or **Generate Token**
4. Fill in the form:

| Field | Value |
|---|---|
| **Name / Description** | `vAnalyzer Integration` (or any name you prefer) |
| **Expiration** | Choose an appropriate expiry, or leave as non-expiring if your policy allows |
| **Scope / Permissions** | Read access to Asset Inventory and Vulnerability data |

5. Click **Create** or **Save**
6. **IMPORTANT:** Copy the token value immediately — it is only shown once.

```
Token Value  →  sevco_api_token
```

> ⚠️ If you close the dialog without copying the token, you must revoke it and generate a new one.

### 2.2 Required Permissions

The token must have at minimum **read** access to:

| Resource | Endpoint used |
|---|---|
| Device inventory | `POST /v3/asset/device` |
| Vulnerability catalog | `POST /v3/asset/vulnerabilities` |
| Device events / telemetry | `POST /v2/asset/device/events` |
| Organization list | `GET /v1/orgs` |

> **Tip:** For security best practices, create a dedicated **service account** user in Sevco with read-only permissions and generate the token from that account.

---

## Step 3 — Configure vAnalyzer

Run the interactive setup and enter the values collected in Steps 1 and 2:

```bash
vanalyzer init
```

When prompted for the Sevco integration:

```
Enable Sevco (Arctic Wolf) integration? [y/N]: y

Enter Sevco Organization ID:   2c8a1f3d-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enter Sevco API Token:         [hidden]
```

The setup will create two Docker secrets automatically:

| Docker Secret | Description |
|---|---|
| `sevco_org_id` | Your Sevco Organization ID (UUID) |
| `sevco_api_token` | Your Sevco API token |

---

## Step 4 — Verify the Integration

After deploying or restarting vAnalyzer, the Sevco sync will run as part of the regular schedule. You can verify it is working by checking the ETL run log:

```sql
SELECT run_id, started_at, finished_at, status,
       rows_devices, rows_vulns, rows_events, rows_vuln_devices, error_message
FROM public.sevco_etl_runs
ORDER BY started_at DESC
LIMIT 10;
```

A successful run will show `status = 'success'` and non-zero values in `rows_devices`, `rows_vulns`, and `rows_vuln_devices`.

To check synced devices:

```sql
SELECT hostname, os_platform, os_version, primary_ip,
       source_count, last_observed_at
FROM public.sevco_device
ORDER BY ingested_at DESC
LIMIT 20;
```

To check CVE coverage:

```sql
SELECT cve_id, severity, cvss3_base_score, epss_score,
       weaponized_exploit_found, cisa_kev_exploit_add
FROM public.sevco_vuln
WHERE cisa_kev_exploit_add IS NOT NULL
ORDER BY cvss3_base_score DESC NULLS LAST
LIMIT 20;
```

To check CVE-to-device mapping:

```sql
SELECT cve_id, COUNT(DISTINCT device_id) AS affected_devices
FROM public.sevco_vuln_device
GROUP BY cve_id
ORDER BY affected_devices DESC
LIMIT 20;
```

---

## ETL Steps

The Sevco ETL executes in 4 sequential steps:

| Step | Description | Table written |
|---|---|---|
| **1 — Devices** | Full device inventory across all connected sources | `sevco_device` |
| **2 — Vulnerabilities** | Vulnerability catalog, exploded by scanner source | `sevco_vuln` |
| **3 — Device Events** | Telemetry attribute changes (capped at 10,000 records due to API pagination limit) | `sevco_device_event` |
| **4 — CVE → Device Mapping** | Per-CVE cross-asset query to identify affected devices, parallelized with 8 workers | `sevco_vuln_device` |

> **Note on Step 4:** With ~1,545 unique CVEs and 8 parallel workers, this step typically takes 10–20 minutes. Each worker opens an independent HTTP session against the Sevco API.

---

## Troubleshooting

| Symptom | Likely Cause | Solution |
|---|---|---|
| `status = 'error'` in `sevco_etl_runs` | Invalid API token or Org ID | Re-run `vanalyzer init` and re-enter the credentials |
| `rows_devices = 0` | Wrong Org ID or token lacks permissions | Verify with the cURL command in Step 1.2 |
| `rows_vuln_devices = 0` | CVE mapping step failed | Check `error_message` column in `sevco_etl_runs` |
| HTTP 403 in logs | Token lacks read scope or wrong Org ID | Verify token permissions in the Sevco console |
| HTTP 400 at page 200 in events | Sevco API pagination limit for `/v2/asset/device/events` | Normal — the ETL stops gracefully at page 200 |
| `rows_events` capped at 10,000 | API hard limit on event pagination | Expected behavior — no action needed |

### Updating Credentials After Initial Setup

If you need to rotate the API token without re-running the full `vanalyzer init`:

```bash
# Remove and recreate the secrets
docker secret rm sevco_api_token
echo "your_new_token" | docker secret create sevco_api_token -

# Redeploy the stack to pick up the new secret
vanalyzer deploy
```

To update the Organization ID:

```bash
docker secret rm sevco_org_id
echo "your_org_id" | docker secret create sevco_org_id -
vanalyzer deploy
```

---

## Environment Variables (Advanced)

The following optional environment variables can be set to tune the Sevco ETL behavior:

| Variable | Default | Description |
|---|---|---|
| `SEVCO_CVE_WORKERS` | `8` | Number of parallel workers for CVE-to-device mapping |
| `POSTGRES_HOST` | `appdb` | PostgreSQL host (set automatically by Docker Compose) |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `PG_SSLMODE` | `disable` | PostgreSQL SSL mode |

To adjust the number of parallel CVE workers (e.g., reduce to 4 to lower API load):

```bash
# In your .env file
SEVCO_CVE_WORKERS=4
```

Then redeploy:

```bash
vanalyzer deploy
```

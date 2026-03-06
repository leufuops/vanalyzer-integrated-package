# Wiz Integration Guide

## Overview
This guide explains how to configure the Wiz integration in vAnalyzer.
The integration pulls vulnerability finding and asset data from the **Wiz GraphQL API** and stores it in the following tables:

- `wiz_assets` — Cloud asset/VM inventory
- `wiz_cves` — CVE knowledge base enriched by Wiz
- `wiz_software_vulnerable` — Asset ↔ vulnerability relationships (fact table)
- `wiz_etl_runs` — ETL execution audit log

---

## Prerequisites

- An active **Wiz** tenant with access to the **Wiz Portal**
- A user account with the **Global Admin** or **Project Admin** role to create Service Accounts
- The integration fetches data for the following asset types: Virtual Machines, Endpoints, and VM Images. Container and serverless workloads are excluded by default.

---

## Step 1 — Create a Service Account in Wiz

### 1.1 Open the Service Accounts Section

1. Go to [https://app.wiz.io](https://app.wiz.io) and sign in
2. Click your tenant name in the top-right corner and select **"Settings"**
3. In the left sidebar navigate to **"Service Accounts"**

   > Direct URL: `https://app.wiz.io/settings/service-accounts`

4. Click **"+ Add Service Account"**

### 1.2 Configure the Service Account

Fill in the form as follows:

| Field | Value |
|---|---|
| **Name** | `vAnalyzer-Integration` (or any name you prefer) |
| **Type** | `Custom Integration (GraphQL API)` |
| **Expiration** | Choose an appropriate expiry (e.g., `1 year`) |

For **Permissions / Scopes**, assign the following read-only scopes:

```
✅  read:vulnerabilities     — Vulnerability findings and CVE data
✅  read:assets              — Cloud asset and VM inventory
```

Click **"Create Service Account"**.

---

## Step 2 — Collect Your Credentials

After creation, Wiz will display the credentials **only once**.
Copy and save both values immediately — you will need them during `vanalyzer init`:

```
Client ID      →  wiz_client_id
Client Secret  →  wiz_client_secret
```

> ⚠️ The **Client Secret** is shown only at creation time. If you navigate away without
> copying it, you must delete the Service Account and create a new one.

---

## Step 3 — Identify Your API Endpoint URL

The Wiz API endpoint depends on the data center region where your tenant is hosted.
You can find your tenant's region in the Wiz Portal URL or under **Settings → General**.

| Region | API Endpoint URL |
|---|---|
| **US1** | `https://api.us1.app.wiz.io/graphql` |
| **US2** | `https://api.us2.app.wiz.io/graphql` |
| **EU1** | `https://api.eu1.app.wiz.io/graphql` |
| **EU2** | `https://api.eu2.app.wiz.io/graphql` |
| **GOV** | `https://api.gov.wiz.io/graphql` |

> **Tip:** If you are unsure of your region, check the URL in your browser when logged into
> the Wiz Portal. For example, `https://app.us2.wiz.io` indicates the **US2** region.

```
API Endpoint URL  →  wiz_api_endpoint_url
```

---

## Step 4 — Configure vAnalyzer

Run the interactive setup and enter the values collected in Steps 2 and 3:

```bash
vanalyzer init
```

When prompted for the Wiz integration:

```
Enable Wiz integration? [y/N]: y

Enter Wiz Client ID:      <your-client-id>
Enter Wiz Client Secret:  [hidden]

Select Wiz API Endpoint:
  1. US1   (https://api.us1.app.wiz.io/graphql)
  2. US2   (https://api.us2.app.wiz.io/graphql)
  3. EU1   (https://api.eu1.app.wiz.io/graphql)
  4. EU2   (https://api.eu2.app.wiz.io/graphql)
  5. GOV   (https://api.gov.wiz.io/graphql)
  6. Custom URL
Select endpoint [1-6] (default: 1): 1
```

The setup will create three Docker secrets automatically:

| Docker Secret | Description |
|---|---|
| `wiz_client_id` | Your Wiz Service Account Client ID |
| `wiz_client_secret` | Your Wiz Service Account Client Secret |
| `wiz_api_endpoint_url` | The GraphQL API endpoint for your Wiz tenant region |

---

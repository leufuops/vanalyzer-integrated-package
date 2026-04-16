
# TrendMicro Vision One Integration Guide

## Overview
This guide explains how to obtain the credentials needed to enable the TrendMicro Vision One integration in vAnalyzer.

---

## Step 1 — Determine Your Region

After logging into Vision One, check the URL in your browser to identify your region:

| Console URL | API URL |
|---|---|
| `portal.xdr.trendmicro.com` | `https://api.xdr.trendmicro.com` |
| `portal.xdr.us.trendmicro.com` | `https://api.xdr.us.trendmicro.com` |
| `portal.xdr.eu.trendmicro.com` | `https://api.xdr.eu.trendmicro.com` |
| `portal.xdr.jp.trendmicro.com` | `https://api.xdr.jp.trendmicro.com` |
| `portal.xdr.au.trendmicro.com` | `https://api.xdr.au.trendmicro.com` |
| `portal.xdr.in.trendmicro.com` | `https://api.xdr.in.trendmicro.com` |
| `portal.xdr.sg.trendmicro.com` | `https://api.xdr.sg.trendmicro.com` |

Keep the **API URL** for your region — you will need it during `vanalyzer init`.

---

## Step 2 — Create an API Key

1. In your Vision One console go to **Administration → API Keys**
2. Click **Add API Key** and fill in:

| Field | Value |
|---|---|
| **Name** | `vAnalyzer Integration` |
| **Role** | `Viewer` (read-only is sufficient) |
| **Expiration** | Set according to your policy |

3. Click **Add**
4. **Copy the API key immediately** — it will not be shown again

> The integration only reads data. No write permissions are required.

---

## Step 3 — Configure vAnalyzer

Run the interactive setup:

```bash
vanalyzer init
```

When prompted for TrendMicro Vision One:

```
Enable TrendMicro Vision One integration? [y/N]: y

Select TrendMicro Vision One Region:
  1. Global  (https://api.xdr.trendmicro.com)
  ...
Select region [1-8] (default: 1): 1

Enter TrendMicro Vision One API Key: [hidden]
```

The setup will create two Docker secrets automatically:

| Docker Secret | Value |
|---|---|
| `trendmicro_api_url` | The API URL for your region (from Step 1) |
| `trendmicro_api_key` | The API key created in Step 2 |

---

## Troubleshooting

If the integration fails to collect data, the most common causes are:

| Symptom | Cause | Resolution |
|---|---|---|
| `401 Unauthorized` | API key invalid or expired | Regenerate the key in Vision One and re-run `vanalyzer init` |
| `403 Forbidden` | Viewer role missing a module permission | Ask your Vision One admin to verify the key's role includes Endpoint Security and XDR read access |
| Connection error | Wrong API URL | Confirm the API URL matches your console region (Step 1) |

To rotate the API key without a full redeploy:

```bash
docker secret rm trendmicro_api_key
echo "new_key_here" | docker secret create trendmicro_api_key -
docker service update --force vanalyzer-stack_app
```

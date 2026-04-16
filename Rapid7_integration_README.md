# Rapid7 InsightVM Integration Guide

## Overview
This guide explains how to obtain the credentials needed to enable the Rapid7 InsightVM integration in vAnalyzer.

---

## Step 1 — Determine Your Region

After logging into the Insight Platform, check the URL in your browser to identify your region:

| Console URL | Region code |
|---|---|
| `insight.rapid7.com` | `us` |
| `us2.insight.rapid7.com` | `us2` |
| `us3.insight.rapid7.com` | `us3` |
| `eu.insight.rapid7.com` | `eu` |
| `ca.insight.rapid7.com` | `ca` |
| `au.insight.rapid7.com` | `au` |
| `ap.insight.rapid7.com` | `ap` |

Keep the **region code** — you will need it during `vanalyzer init`.

---

## Step 2 — Create an API Key

1. Log in to the **Insight Platform** at `insight.rapid7.com` (or your regional URL)
2. Click your user icon in the top-right corner and select **API Keys**
3. Click **New User Key**
4. Enter a name such as `vAnalyzer Integration` and click **Generate**
5. **Copy the API key immediately** — it will not be shown again

> The integration uses the Insight Platform API key, not an InsightVM console credential.
> No special roles or permissions need to be assigned beyond having access to InsightVM in your organization.

---

## Step 3 — Configure vAnalyzer

Run the interactive setup:

```bash
vanalyzer init
```

When prompted for Rapid7 InsightVM:

```
Enable Rapid7 InsightVM integration? [y/N]: y

Select Rapid7 Insight Platform Region:
  1. US  (us)  — https://us.api.insight.rapid7.com
  2. US2 (us2) — https://us2.api.insight.rapid7.com
  3. US3 (us3) — https://us3.api.insight.rapid7.com
  ...
Select region [1-7] (default: 3): 3

Region: us3  (https://us3.api.insight.rapid7.com)

Enter Rapid7 Insight API Key: [hidden]
```

The setup will create two Docker secrets automatically:

| Docker Secret | Value |
|---|---|
| `rapid7_region` | Your region code (from Step 1) |
| `rapid7_api_key` | The API key created in Step 2 |

---

## Troubleshooting

If the integration fails to collect data, the most common causes are:

| Symptom | Cause | Resolution |
|---|---|---|
| `401 Unauthorized` | API key invalid or expired | Regenerate the key in the Insight Platform and re-run `vanalyzer init` |
| `403 Forbidden` | User account lacks InsightVM access | Ask your Rapid7 admin to confirm your account has InsightVM enabled in the platform |
| Connection error | Wrong region | Confirm the region code matches your console URL (Step 1) |

To rotate the API key without a full redeploy:

```bash
docker secret rm rapid7_api_key
echo "new_key_here" | docker secret create rapid7_api_key -
docker service update --force vanalyzer-stack_app
```

# Microsoft Defender for Endpoint (MDE) Integration Guide

## Overview
This guide explains how to configure the Microsoft Defender for Endpoint integration in vAnalyzer.
The integration pulls vulnerability and asset data from the **Microsoft Defender TVM (Threat & Vulnerability Management)** API and stores it in the following tables:

- `mde_asset` — Device/endpoint inventory
- `mde_cve` — CVE knowledge base enriched by MDE
- `mde_asset_vuln` — Asset ↔ vulnerability relationships (fact table)
- `mde_etl_runs` — ETL execution audit log

---

## Prerequisites

- An active **Microsoft 365 / Azure** tenant with Microsoft Defender for Endpoint Plan 1 or Plan 2
- Access to the **Azure Portal** with permissions to create App Registrations (`Application Administrator` role or higher)
- Admin consent capability in your tenant (Global Administrator or Privileged Role Administrator)

> **Note:** Microsoft has rebranded Azure Active Directory (Azure AD) to **Microsoft Entra ID**.
> All references in this guide use the current name. In the Azure Portal you may still see
> both names depending on your portal version — they refer to the same service.

---

## Step 1 — Create the App Registration in Microsoft Entra ID

### 1.1 Open Microsoft Entra ID

1. Go to [https://portal.azure.com](https://portal.azure.com) and sign in
2. In the top search bar type **"Microsoft Entra ID"** and click it

   > Alternatively, go directly to [https://entra.microsoft.com](https://entra.microsoft.com)

3. In the left sidebar click **"App registrations"**
4. Click **"+ New registration"**

### 1.2 Configure the Registration

Fill in the form as follows:

| Field | Value |
|---|---|
| **Name** | `vAnalyzer-MDE-Integration` (or any name you prefer) |
| **Supported account types** | `Accounts in this organizational directory only (Single tenant)` |
| **Redirect URI** | Leave blank |

Click **"Register"**.

---

## Step 2 — Collect Your Credentials

After registering, you will land on the app's **Overview** page.
Copy and save the following values — you will need them during `vanalyzer init`:

```
Application (client) ID   →  mde_client_id
Directory (tenant) ID     →  mde_tenant_id
```

Both values look like GUIDs: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

> **Tip:** Keep this browser tab open while completing the next steps.

---

## Step 3 — Create a Client Secret

1. In the left sidebar of your App Registration click **"Certificates & secrets"**
2. Click the **"Client secrets"** tab
3. Click **"+ New client secret"**
4. Fill in the form:

| Field | Value |
|---|---|
| **Description** | `vAnalyzer MDE Secret` |
| **Expires** | Choose an appropriate expiry (e.g., `24 months`) |

5. Click **"Add"**
6. **IMPORTANT:** Copy the secret **Value** immediately — it will only be shown once.

```
Secret Value  →  mde_client_secret
```

> ⚠️ If you navigate away without copying the value, you must delete it and create a new one.
> The **Secret ID** column is NOT the secret — you need the **Value** column.

---

## Step 4 — Assign API Permissions

The integration requires read-only access to the Microsoft Defender for Endpoint API.

### 4.1 Add the Permission

1. In the left sidebar click **"API permissions"**
2. Click **"+ Add a permission"**
3. In the panel that opens, click **"APIs my organization uses"**
4. Search for **"WindowsDefenderATP"** and click it

> If it does not appear, search for **"Microsoft Threat Protection"** instead.

5. Select **"Application permissions"** (NOT Delegated)
6. Expand the **"Vulnerability"** group and check:

```
✅  Vulnerability.Read.All
```

7. Click **"Add permissions"**

### 4.2 Optional — Additional Read Permissions (Recommended)

For full asset and software inventory data, also add the following **Application permissions** from the same `WindowsDefenderATP` API:

```
✅  Machine.Read.All          — Device/asset inventory
✅  Software.Read.All         — Installed software inventory
```

### 4.3 Grant Admin Consent

After adding the permissions:

1. You will see the permissions listed with status **"Not granted for \<tenant\>"**
2. Click **"Grant admin consent for \<your tenant name\>"**
3. Click **"Yes"** to confirm
4. All permissions should now show a green checkmark: **"Granted for \<tenant\>"**

> ⚠️ This step requires **Global Administrator** or **Privileged Role Administrator** privileges.
> If you do not have these, ask your **Microsoft Entra ID** admin to grant consent.

---

## Step 5 — Configure vAnalyzer

Run the interactive setup and enter the values collected in Steps 2 and 3:

```bash
vanalyzer init
```

When prompted for the MDE integration:

```
Enable Microsoft Defender for Endpoint integration? [y/N]: y

Enter Azure Tenant ID (GUID):   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enter App Registration Client ID (GUID):   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enter App Registration Client Secret:   [hidden]
```

The setup will create three Docker secrets automatically:

| Docker Secret | Description |
|---|---|
| `mde_tenant_id` | Your Microsoft Entra ID Directory (tenant) ID |
| `mde_client_id` | Your App Registration Application (client) ID |
| `mde_client_secret` | Your App Registration client secret value |

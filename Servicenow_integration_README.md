# ServiceNow Integration Guide

## Overview
This guide explains how to configure the ServiceNow integration in vAnalyzer.
The integration synchronizes vulnerability data between vAnalyzer and ServiceNow by:

- **Creating** Problem records (`problem` table) for every active CVE detected on your assets
- **Closing** those Problem records automatically when the vulnerability is mitigated (detected via the `public.incident` table)

The sync uses two ServiceNow mechanisms:
- **Table API** — to create Problem records
- **Import Set API** (`u_vuln_sync` staging table + Transform Map) — to close/resolve Problem records in a controlled, auditable way

---

## Prerequisites

- An active **ServiceNow** instance (Madrid release or later recommended)
- A ServiceNow user account with sufficient permissions to create and update Problem records (detailed below)
- A configured **Transform Map** in ServiceNow for the Import Set table `u_vuln_sync` (detailed in Step 3)
- The `public.activevulnerabilities` and `public.incident` tables populated in the vAnalyzer database

---

## Step 1 — Create a Dedicated ServiceNow User

It is strongly recommended to create a dedicated integration user rather than using a personal account.

### 1.1 Create the User

1. In your ServiceNow instance go to **User Administration → Users**
2. Click **New**
3. Fill in the form:

| Field | Value |

| **User ID** | `vanalyzer_integration` (or any name you prefer) |
| **First name** | `vAnalyzer` |
| **Last name** | `Integration` |
| **Email** | your IT team's shared mailbox |
| **Password** | Generate a strong password and save it securely |
| **Active** | ✅ Checked |
| **Web service access only** | ✅ Checked (prevents UI login, API only) |

4. Click **Submit**

### 1.2 Assign Roles

Open the user record and go to the **Roles** tab. Add the following roles:

| Role | Purpose |

| `itil` | Read/write access to Problem, Incident, and CMDB tables |
| `import_set_loader` | Permission to push records to Import Set tables |
| `import_transformer` | Permission to trigger Transform Maps |

> **Minimum required:** `itil` alone is enough to create Problem records via the Table API.
> The `import_set_loader` and `import_transformer` roles are additionally required for the
> Import Set closure mechanism (`u_vuln_sync`).

> ⚠️ If your ServiceNow instance uses **scoped applications** or custom ACLs, your ServiceNow
> admin may need to grant explicit read/write access to the `problem` and `u_vuln_sync` tables.

---

## Step 2 — Gather Your ServiceNow Credentials

After creating the user, collect the three values needed during `vanalyzer init`:

```
Instance URL   →  servicenow_instance_url
User ID        →  servicenow_user
Password       →  servicenow_password
```

The instance URL must include the full base URL with no trailing slash, for example:

```
https://yourcompany.service-now.com
```

---

## Step 3 — Configure the Import Set Table and Transform Map

The integration closes Problem records through an Import Set staging table called `u_vuln_sync`.
This table must exist and have a working Transform Map that targets the `problem` table.

### 3.1 Create the Import Set Table `u_vuln_sync`

1. In ServiceNow go to **System Import Sets → Tables → Create table**
2. Fill in:

| Field | Value |

| **Label** | `Vuln Sync` |
| **Name** | `u_vuln_sync` (auto-filled) |

3. Add the following fields to the table:

| Column label | Column name | Type |

| Number | `u_number` | String (40) |
| State | `u_state` | String (10) |
| Resolution code | `u_resolution_code` | String (40) |
| Assigned to | `u_assigned_to` | String (36) |
| Cause notes | `u_cause_notes` | String (4000) |
| Fix notes | `u_fix_notes` | String (4000) |
| Close notes | `u_close_notes` | String (4000) |

4. Click **Submit**

### 3.2 Create the Transform Map

1. Go to **System Import Sets → Transform Maps → New**
2. Fill in:

| Field | Value |

| **Name** | `Vuln Sync to Problem` |
| **Source table** | `u_vuln_sync` |
| **Target table** | `problem` |
| **Run business rules** | ✅ Checked |

3. In the **Field Maps** tab add the following mappings:

| Source field (`u_vuln_sync`) | Target field (`problem`) | Notes |

| `u_number` | — | Used to look up the Problem record (coalesce key) |
| `u_state` | `state` | Maps the numeric state value |
| `u_resolution_code` | `resolution_code` | e.g. `fix_applied` |
| `u_assigned_to` | `assigned_to` | sys_id of the user |
| `u_cause_notes` | `cause_notes` | Root cause text |
| `u_fix_notes` | `fix_notes` | Fix description |
| `u_close_notes` | `close_notes` | Closure summary |

4. Set the **Coalesce** field to `u_number` so the transform updates the correct Problem record by number rather than creating a duplicate

5. Click **Submit** and then **Run Transform** once to verify the mapping is valid

> **Problem state value `106`** — The integration sends state `106` which is the default
> ServiceNow state for **Resolved**. If your instance uses a different state value for
> resolution, update the `u_state` constant in `snow_vuln_problem_sync.py`.

---

## Step 4 — Configure vAnalyzer

Run the interactive setup:

```bash
vanalyzer init
```

When prompted for the ServiceNow integration:

```
Enable ServiceNow integration? [y/N]: y

Enter ServiceNow Instance URL (e.g., https://company.service-now.com): https://yourcompany.service-now.com
Enter ServiceNow Username: vanalyzer_integration
Enter ServiceNow Password: [hidden]
```

The setup will create three Docker secrets automatically:

| Docker Secret | Description |

| `servicenow_instance_url` | Your ServiceNow instance base URL |
| `servicenow_user` | The integration user ID created in Step 1 |
| `servicenow_password` | The integration user password |

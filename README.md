# Veracode Tenant Audit

Standalone **read-only** audit script for a Veracode tenant. Executes six independent checks against the Identity and Applications APIs and produces per-check CSV evidence plus a consolidated HTML report suitable for compliance auditability.

## What it audits

| # | Check | What it verifies | Domain |
|---|---|---|---|
| 1 | **Identity Model** | Every user has an immutable `user_id` GUID distinct from email/username. Empirical proof that authorization does not depend on mutable attributes. | Identity Management |
| 2 | **RBAC** | Role distribution, Administrator ratio (least privilege), API service account privileges, Segregation of Duties conflicts. | Least Privilege / SoD |
| 3 | **Team Segregation** | Applications without team assignment, with special severity for HIGH/VERY_HIGH business criticality apps. | Access Segregation |
| 4 | **Privileged Users & Stale Accounts** | Active privileged users for RACI validation, accounts with no login in N days, disabled accounts inventory. | Account Lifecycle |
| 5 | **Traceability** | Inventory of audit capabilities available vs gaps. Flags whether check 7 was run. | Audit & Traceability |
| 6 | **Account Hardening** | IP restriction coverage, SAML SSO coverage vs local authentication. | Authentication Strength |
| 7 | **Identity Drift Detection** *(opt-in)* | Detects identity changes per UID by diffing against a snapshot from a previous run: field changes (email/name), account lifecycle (added/removed/reactivated/deactivated), privilege transitions, username collisions, email collisions, cross-domain email changes, and email changes on privileged accounts. Requires `--enable-change-detection`. | Identity Integrity |

## Requirements

- Python 3.9+
- Veracode API service account with **Admin API** role
- HMAC credentials: `API ID` and `API KEY`

## Installation

```bash
pip install -r requirements.txt
```

## Credentials

Option A — environment variables:

```bash
export VERACODE_API_KEY_ID="..."
export VERACODE_API_KEY_SECRET="..."
```

Option B — `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = ...
veracode_api_key_secret = ...
```

## Usage

```bash
# Commercial region (default)
python veracode_tenant_audit.py --output ./audit_output

# European region
python veracode_tenant_audit.py --region european --output ./audit_output

# Federal region
python veracode_tenant_audit.py --region federal --output ./audit_output

# Custom staleness threshold (default 90 days)
python veracode_tenant_audit.py --stale-days 60

# Skip application inventory (faster)
python veracode_tenant_audit.py --skip-apps

# Enable check 7: detect email/name changes per UID via snapshot diff
# First run creates the baseline; subsequent runs detect changes
python veracode_tenant_audit.py --enable-change-detection

# Custom snapshot location (for shared/scheduled runs)
python veracode_tenant_audit.py --enable-change-detection --snapshot-dir /var/lib/veracode-audit
```

## Check 7 drift categories

| Category | Severity | What it catches |
|---|---|---|
| `username_collisions` | **Critical** | Current user_name appears under a different UID than before. Veracode says usernames are non-recyclable; if this triggers, escalate immediately. |
| `privileged_email_changes` | **High** | Email change on an account holding Administrator, Security Lead, or other privileged roles. |
| `privilege_acquired` | **High** | UID gained privileged role status since the last snapshot. |
| `email_collisions` | **High** | Same email address held by 2+ active UIDs. Indicates duplicate accounts, IdP misconfiguration, or attempted impersonation. |
| `cross_domain_emails` | **High** | Email change crossed organizational domain (e.g. `@corp.com` → `@gmail.com`). |
| `field_changes` | **Medium** | Per-field changes to email, user_name, first_name, last_name. Note: user_name changes should never appear; if they do, escalate. |
| `reactivated` | **Medium** | Account transitioned from inactive to active. |
| `privilege_lost` | Informational | UID lost privileged role status. Routine but recorded. |
| `deactivated` | Informational | Routine offboarding signal. |
| `added` | Informational | New UIDs since last snapshot. |
| `removed` | Informational | UIDs no longer present. Veracode does not recycle usernames so removal is rare. |

Each category writes its own CSV (`07_<category>.csv`), so even empty categories provide explicit "we checked, found nothing" evidence for the audit trail.

## Scheduling check 7

Check 7 is designed for periodic execution. The snapshot is persisted between runs, and each run reports the delta. **Recommended cadence: daily**; weekly is acceptable but increases the intra-window blind spot for change-and-revert patterns.

Example cron entry (daily at 02:00):
```
0 2 * * * cd /opt/veracode-audit && python veracode_tenant_audit.py --enable-change-detection --snapshot-dir /var/lib/veracode-audit --output ./reports/$(date +\%Y-\%m-\%d)
```

The previous N snapshots are auto-rotated under `--snapshot-dir` as `users_snapshot.<timestamp>.json` so you can compare across multiple runs back if needed for forensics.

Check 7 is designed for periodic execution. Snapshot is persisted between runs, and each run reports the delta. Recommended cadence: **daily** for high-security environments, **weekly** for standard use.

Example cron entry:
```
0 2 * * * cd /opt/veracode-audit && python veracode_tenant_audit.py --enable-change-detection --snapshot-dir /var/lib/veracode-audit --output ./reports/$(date +\%Y-\%m-\%d)
```

## Outputs

All files are written to the directory specified by `--output`:

| File | Content |
|---|---|
| `veracode_tenant_audit.html` | Consolidated report with executive summary and findings sorted by severity |
| `findings.json` | All findings in structured JSON (SIEM/ingest ready) |
| `01_identity_model.csv` | Full user inventory with UID vs email verification |
| `02_rbac_all_users.csv` | Every user with roles and teams |
| `02_rbac_administrators.csv` | Active users holding Administrator role |
| `02_rbac_api_service_accounts.csv` | All API service accounts |
| `02_rbac_sod_conflicts.csv` | Users with conflicting role combinations |
| `02_rbac_role_distribution.json` | Role distribution summary |
| `03_teams_inventory.csv` | All teams in the tenant |
| `03_applications_team_assignment.csv` | Every application with its team(s) and criticality |
| `03_applications_without_team.csv` | Applications missing team assignment |
| `04_privileged_users_active.csv` | Active users with privileged roles |
| `04_stale_accounts.csv` | Active accounts without recent login |
| `04_disabled_accounts.csv` | Inactive/disabled accounts |
| `05_traceability_capabilities.csv` | Matrix of audit capabilities vs platform gaps |
| `06_account_hardening.csv` | IP restriction and authentication type per user |
| `07_field_changes.csv` | *(check 7 only)* Per-field changes vs previous snapshot, with old/new values |
| `07_added.csv` | *(check 7 only)* New UIDs since last snapshot |
| `07_removed.csv` | *(check 7 only)* UIDs removed since last snapshot |
| `07_reactivated.csv` | *(check 7 only)* UIDs that went from inactive to active |
| `07_deactivated.csv` | *(check 7 only)* UIDs that went from active to inactive |
| `07_privilege_acquired.csv` | *(check 7 only)* UIDs that gained privileged roles |
| `07_privilege_lost.csv` | *(check 7 only)* UIDs that lost privileged roles |
| `07_username_collisions.csv` | *(check 7 only)* user_name appearing under a different UID than before |
| `07_email_collisions.csv` | *(check 7 only)* Same email on 2+ active UIDs in current state |
| `07_cross_domain_emails.csv` | *(check 7 only)* Email changes that crossed organizational domain |
| `07_privileged_email_changes.csv` | *(check 7 only)* Email changes on privileged accounts |
| `<snapshot-dir>/users_snapshot.json` | *(check 7 only)* Current baseline for the next run |
| `<snapshot-dir>/users_snapshot.<ts>.json` | *(check 7 only)* Rotated snapshots from previous runs (last 4 retained) |

## Severity thresholds

| Condition | Severity |
|---|---|
| Users without immutable UID | High |
| Administrator ratio > 5% of active users | High |
| HIGH/VERY_HIGH applications without team | High |
| Privileged users inactive 90+ days | High |
| API service accounts with elevated privileges | Medium |
| Segregation of Duties conflicts | Medium |
| Non-critical apps without team | Medium |
| Standard users inactive 90+ days | Medium |
| Self-service audit log gap | Medium |
| SAML coverage < 80% of active users | Medium |

Thresholds are defined as constants at the top of the script and can be tuned per engagement.

## Limitations

The platform **does not expose profile attribute changes (email, first_name, last_name, user_name) through the Reporting API or standard audit query interfaces**, so they are not directly retrievable via native reporting.

However, these changes still exist internally, they are simply not surfaced through the publicly queryable API layer. Please contact Veracode Support for more information.

The AUDIT report is limited to events such as:
- Authentication activity (logins, sessions)
- Authorization changes (roles, teams, permissions)
- Other control-plane security events

It does **not include field-level profile mutations** in its queryable dataset.

### Check 7 behavior (snapshot diffing)
Check 7 implements a compensating control by performing **state-based diffing**:

- Captures a full snapshot of user state on each execution
- Compares against the previous snapshot on the next run
- Reports only detected deltas between runs

## Security

- Uses the official `veracode-api-signing` HMAC implementation. Credentials are never embedded in code.
- API credentials should be rotated every 90 days per Veracode guidance.
- No sensitive data is persisted outside the directory specified by `--output`.

## Exit codes

- `0` — audit completed successfully
- `2` — `veracode-api-signing` not installed
- Non-zero on authentication (401) or authorization (403) errors from the Veracode API

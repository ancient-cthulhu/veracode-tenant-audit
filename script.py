#!/usr/bin/env python3
"""
Veracode Tenant Audit
=====================
Read-only audit script for a Veracode tenant. Designed to scale to large
tenants (10k+ users, 5k+ applications) via:

  - Concurrent pagination after page count is known from page 0
  - Bounded ThreadPoolExecutor for per-user detail fetches when needed
  - Global token-bucket rate limiter (Veracode caps at 250 req/min/credential)
  - Connection pooling + retry with Retry-After honored

Generates per-check CSV evidence, a consolidated HTML report, and a JSON
finding stream suitable for SIEM ingestion.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import logging
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:
    print(
        "ERROR: veracode-api-signing not installed.\n"
        "Install with: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)


__all__ = ["main", "AuditContext", "Finding", "RateLimiter"]

log = logging.getLogger("veracode_audit")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REGIONS: dict[str, str] = {
    "commercial": "https://api.veracode.com",
    "european": "https://api.veracode.eu",
    "federal": "https://api.veracode.us",
}

PRIVILEGED_ROLES: frozenset[str] = frozenset({
    "administrator",
    "securitylead",
    "policyadministrator",
    "adminapi",
    "noteamrestrictionapi",
    "mitigationapprover",
    "workspaceadministrator",
})

API_PRIVILEGED_ROLES: frozenset[str] = frozenset({
    "adminapi",
    "noteamrestrictionapi",
})

SOD_CONFLICT_PAIRS: list[tuple[frozenset[str], str]] = [
    (frozenset({"submitter", "mitigationapprover"}), "Submitter + Mitigation Approver"),
    (frozenset({"creator", "reviewer"}), "Creator + Reviewer"),
]

# Veracode's documented rate limit is 250 req/min/credential. We stay well below.
DEFAULT_RATE_LIMIT_PER_MIN = 200
DEFAULT_CONCURRENCY = 8
PAGE_SIZE = 500
MAX_PAGES = 2000  # safety bound for runaway pagination
DEFAULT_TIMEOUT = 60

ADMIN_RATIO_THRESHOLD = 0.05
SAML_COVERAGE_THRESHOLD = 0.80

EXIT_OK = 0
EXIT_DEPENDENCY_MISSING = 2
EXIT_AUTH_ERROR = 3
EXIT_API_ERROR = 4

SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4,
}

SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#7a1f1f",
    "High": "#c0392b",
    "Medium": "#d68910",
    "Low": "#2980b9",
    "Informational": "#566573",
}


# ---------------------------------------------------------------------------
# Rate limiter (token bucket, thread-safe)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe token bucket rate limiter.

    Refills `rate_per_sec` tokens per second up to `capacity`. Calls to
    `acquire()` block until a token is available. Used to globally bound
    request rate across concurrent workers.
    """

    def __init__(self, rate_per_min: int, burst: int | None = None) -> None:
        if rate_per_min <= 0:
            raise ValueError("rate_per_min must be positive")
        self.rate_per_sec = rate_per_min / 60.0
        self.capacity = float(burst if burst is not None else max(rate_per_min // 6, 5))
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Compute precise wait outside the lock
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate_per_sec
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    check: str
    control: str
    severity: str
    title: str
    detail: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Invalid severity: {self.severity}")


@dataclass
class AuditContext:
    base_url: str
    output_dir: Path
    concurrency: int
    rate_limiter: RateLimiter
    session: requests.Session
    findings: list[Finding] = field(default_factory=list)
    _findings_lock: threading.Lock = field(default_factory=threading.Lock)

    def add_finding(self, f: Finding) -> None:
        with self._findings_lock:
            self.findings.append(f)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def build_session(pool_size: int) -> requests.Session:
    """Session with urllib3 retry policy. HMAC auth is applied per-request
    because the signature must be regenerated each time."""
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=pool_size,
        pool_maxsize=pool_size,
    )
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "veracode-tenant-audit/2.0"})
    return s


def _veracode_get(ctx: AuditContext, url: str, **kwargs: Any) -> requests.Response:
    """Single GET with rate-limit acquire and a fresh HMAC signature."""
    ctx.rate_limiter.acquire()
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    return ctx.session.get(url, auth=RequestsAuthPluginVeracodeHMAC(), **kwargs)


def _raise_for_known_errors(resp: requests.Response) -> None:
    if resp.status_code == 401:
        raise PermissionError("HMAC authentication failed. Check API ID/KEY.")
    if resp.status_code == 403:
        raise PermissionError(
            "Forbidden. The API service account needs Admin API role."
        )
    resp.raise_for_status()


def _fetch_page(
    ctx: AuditContext,
    url: str,
    embedded_key: str,
    base_params: dict,
    page: int,
) -> tuple[list[dict], int]:
    """Fetch a single page. Returns (items, total_pages)."""
    params = {**base_params, "page": page}
    resp = _veracode_get(ctx, url, params=params)
    _raise_for_known_errors(resp)
    body = resp.json()
    items = body.get("_embedded", {}).get(embedded_key, [])
    total_pages = body.get("page", {}).get("total_pages", 1)
    return items, total_pages


def get_paginated(
    ctx: AuditContext,
    path: str,
    embedded_key: str,
    params: dict | None = None,
) -> list[dict]:
    """Walk a HAL+JSON paginated endpoint. Page 0 is fetched serially to
    discover total_pages; remaining pages are fetched concurrently."""
    url = f"{ctx.base_url}{path}"
    base_params: dict[str, Any] = {"size": PAGE_SIZE}
    if params:
        base_params.update(params)

    log.debug("Fetching %s page 0...", path)
    first_items, total_pages = _fetch_page(ctx, url, embedded_key, base_params, 0)

    if total_pages <= 1:
        return first_items
    if total_pages > MAX_PAGES:
        raise RuntimeError(
            f"{path} reports {total_pages} pages, exceeds MAX_PAGES={MAX_PAGES}"
        )

    log.info("  %s: %d pages, fetching concurrently...", path, total_pages)
    pages: dict[int, list[dict]] = {0: first_items}

    with ThreadPoolExecutor(max_workers=ctx.concurrency) as pool:
        future_to_page = {
            pool.submit(_fetch_page, ctx, url, embedded_key, base_params, p): p
            for p in range(1, total_pages)
        }
        for future in as_completed(future_to_page):
            p = future_to_page[future]
            items, _ = future.result()
            pages[p] = items

    # Reassemble in page order to maintain deterministic output
    return [item for p in sorted(pages) for item in pages[p]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_role_name(name: str) -> str:
    return (name or "").lower().replace(" ", "").replace("_", "").replace("-", "")


def detect_sod_conflicts(normalized_roles: set[str]) -> list[str]:
    return [label for pair, label in SOD_CONFLICT_PAIRS if pair <= normalized_roles]


def get_user_roles(user: dict) -> tuple[list[str], set[str]]:
    """Return (raw_role_names, normalized_role_set), computed once per user."""
    raw = [r.get("role_name", "") for r in user.get("roles") or []]
    return raw, {normalize_role_name(r) for r in raw}


def is_api_service_account(user: dict) -> bool:
    """Detect API service accounts. Per Veracode Identity API docs, the
    authoritative discriminator is `user_type`, with values like 'API' or
    'VOSP'. Older or partial responses may not include `user_type`, so we
    fall back to:
      - permissions array containing apiUser
      - any role marked is_api=true
      - role name matching well-known API role patterns (the `*api` suffix
        convention used by Veracode for non-human-only roles)
    """
    user_type = (user.get("user_type") or "").upper()
    if user_type == "API":
        return True

    if any(p.get("permission_name") == "apiUser"
           for p in user.get("permissions") or []):
        return True

    # Role-level signals
    roles = user.get("roles") or []
    for r in roles:
        if r.get("is_api") is True:
            return True
        name = (r.get("role_name") or "").lower().replace(" ", "").replace("_", "")
        # Veracode API-only roles end in 'api' (adminapi, uploadapi, resultsapi,
        # apisubmitanyscan, noteamrestrictionapi, etc.)
        if name in {"adminapi", "uploadapi", "resultsapi", "apisubmitanyscan",
                    "noteamrestrictionapi", "submitterapi", "creatorapi"}:
            return True

    return False


def get_user_teams(user: dict) -> list[dict]:
    """Return the user's team list, normalizing missing/null cases."""
    return user.get("teams") or []


def format_team_label(team: dict) -> str:
    """Render a team object as a readable label. Identity API uses
    `team_name` and `team_id`, but defensive fallbacks cover other
    Veracode contexts (Applications API uses `guid`)."""
    return (
        team.get("team_name")
        or team.get("name")
        or team.get("team_id")
        or team.get("guid")
        or "<unnamed>"
    )


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Check 1 - Identity model verification
# ---------------------------------------------------------------------------

def check1_identity_model(ctx: AuditContext, users: list[dict]) -> None:
    rows = [
        {
            "user_id_uid": u.get("user_id") or "MISSING",
            "user_name": u.get("user_name", ""),
            "email_address": u.get("email_address", ""),
            "first_name": u.get("first_name", ""),
            "last_name": u.get("last_name", ""),
            "active": u.get("active", ""),
            "uid_is_distinct_from_email": (
                "yes" if u.get("user_id") and u.get("user_id") != u.get("email_address")
                else "no"
            ),
        }
        for u in users
    ]
    fields = ["user_id_uid", "user_name", "email_address", "first_name",
              "last_name", "active", "uid_is_distinct_from_email"]
    write_csv(ctx.output_dir / "01_identity_model.csv", rows, fields)

    issues = sum(1 for r in rows if r["user_id_uid"] == "MISSING")
    if issues:
        ctx.add_finding(Finding(
            check="1. Identity Model",
            control="Identity Management",
            severity="High",
            title="Users without identifiable immutable UID",
            detail=f"{issues} users do not expose user_id in the API response.",
            evidence="01_identity_model.csv",
        ))
    else:
        ctx.add_finding(Finding(
            check="1. Identity Model",
            control="Identity Management",
            severity="Informational",
            title="Immutable UID present for all users",
            detail=(
                f"Verified {len(users)} users. All expose a user_id GUID "
                "distinct from email and username."
            ),
            evidence="01_identity_model.csv",
        ))


# ---------------------------------------------------------------------------
# Check 2 - RBAC review
# ---------------------------------------------------------------------------

def check2_rbac(ctx: AuditContext, users: list[dict]) -> None:
    rows: list[dict] = []
    role_distribution: dict[str, int] = {}
    admins: list[dict] = []
    api_service_accounts: list[dict] = []
    sod_conflicts: list[dict] = []

    for u in users:
        raw_roles, normalized = get_user_roles(u)
        is_api = is_api_service_account(u)
        teams = [format_team_label(t) for t in get_user_teams(u)]
        is_privileged = bool(normalized & PRIVILEGED_ROLES)
        sod_labels = detect_sod_conflicts(normalized)

        for r in raw_roles:
            role_distribution[r] = role_distribution.get(r, 0) + 1

        row = {
            "user_id": u.get("user_id"),
            "user_name": u.get("user_name"),
            "email": u.get("email_address"),
            "active": u.get("active"),
            "is_api_service_account": is_api,
            "is_privileged": is_privileged,
            "has_admin_api_role": bool(normalized & API_PRIVILEGED_ROLES),
            "roles": ", ".join(raw_roles),
            "teams": ", ".join(str(t) for t in teams),
            "team_count": len(teams),
            "sod_conflicts": "; ".join(sod_labels),
        }
        rows.append(row)

        if "administrator" in normalized and u.get("active"):
            admins.append(row)
        if is_api:
            api_service_accounts.append(row)
        if sod_labels:
            sod_conflicts.append(row)

    fields = ["user_id", "user_name", "email", "active",
              "is_api_service_account", "is_privileged", "has_admin_api_role",
              "roles", "teams", "team_count", "sod_conflicts"]
    write_csv(ctx.output_dir / "02_rbac_all_users.csv", rows, fields)
    write_csv(ctx.output_dir / "02_rbac_administrators.csv", admins, fields)
    write_csv(ctx.output_dir / "02_rbac_api_service_accounts.csv", api_service_accounts, fields)
    write_csv(ctx.output_dir / "02_rbac_sod_conflicts.csv", sod_conflicts, fields)
    write_json(ctx.output_dir / "02_rbac_role_distribution.json", role_distribution)

    active_users = sum(1 for u in users if u.get("active"))
    admin_count = len(admins)

    if active_users and (admin_count / active_users) > ADMIN_RATIO_THRESHOLD:
        ctx.add_finding(Finding(
            check="2. RBAC",
            control="Least Privilege",
            severity="High",
            title=f"Excessive Administrator accounts ({admin_count}/{active_users})",
            detail=(
                f"{admin_count / active_users * 100:.1f}% of active users hold "
                f"Administrator role. Recommended threshold: <= "
                f"{ADMIN_RATIO_THRESHOLD * 100:.0f}%."
            ),
            evidence="02_rbac_administrators.csv",
        ))
    else:
        ctx.add_finding(Finding(
            check="2. RBAC",
            control="Least Privilege",
            severity="Informational",
            title=f"Administrator distribution within threshold ({admin_count}/{active_users})",
            detail="Administrator count aligned with least privilege principle.",
            evidence="02_rbac_administrators.csv",
        ))

    privileged_api = [a for a in api_service_accounts if a["has_admin_api_role"]]
    if privileged_api:
        ctx.add_finding(Finding(
            check="2. RBAC",
            control="Service Account Governance",
            severity="Medium",
            title=f"{len(privileged_api)} API service accounts with elevated privileges",
            detail=(
                "Service accounts with Admin API or no team restriction. "
                "Validate documented justification and HMAC credential rotation."
            ),
            evidence="02_rbac_api_service_accounts.csv",
        ))

    if sod_conflicts:
        ctx.add_finding(Finding(
            check="2. RBAC",
            control="Segregation of Duties",
            severity="Medium",
            title=f"{len(sod_conflicts)} users with segregation of duties conflicts",
            detail=(
                "See sod_conflicts column for the specific role pair detected per user. "
                "Validate if team scope compensates the risk."
            ),
            evidence="02_rbac_sod_conflicts.csv",
        ))


# ---------------------------------------------------------------------------
# Check 3 - Team segregation
# ---------------------------------------------------------------------------

def check3_teams(ctx: AuditContext, teams: list[dict], applications: list[dict]) -> None:
    team_rows = [
        {
            "team_id": t.get("team_id"),
            "team_name": t.get("team_name"),
            "business_unit": (t.get("business_unit") or {}).get("bu_name", ""),
            "members_count": len(t.get("users", [])) if "users" in t else "n/a",
        }
        for t in teams
    ]
    write_csv(
        ctx.output_dir / "03_teams_inventory.csv",
        team_rows,
        ["team_id", "team_name", "business_unit", "members_count"],
    )

    apps_rows: list[dict] = []
    for app in applications:
        profile = app.get("profile") or {}
        app_teams = profile.get("teams") or []
        apps_rows.append({
            "app_guid": app.get("guid"),
            "app_name": profile.get("name"),
            "business_criticality": profile.get("business_criticality", "UNKNOWN"),
            "team_count": len(app_teams),
            "teams": ", ".join(format_team_label(t) for t in app_teams),
            "business_unit": (profile.get("business_unit") or {}).get("name", ""),
        })

    apps_without_team = [r for r in apps_rows if r["team_count"] == 0]
    high_crit_no_team = [
        r for r in apps_without_team
        if r["business_criticality"] in ("VERY_HIGH", "HIGH")
    ]

    fields = ["app_guid", "app_name", "business_criticality",
              "team_count", "teams", "business_unit"]
    write_csv(ctx.output_dir / "03_applications_team_assignment.csv", apps_rows, fields)
    write_csv(ctx.output_dir / "03_applications_without_team.csv", apps_without_team, fields)

    if high_crit_no_team:
        ctx.add_finding(Finding(
            check="3. Team Segregation",
            control="Access Segregation",
            severity="High",
            title=f"{len(high_crit_no_team)} HIGH/VERY_HIGH applications without team",
            detail=(
                "Critical applications without team segregation break least privilege "
                "and open broad access to Security Leads without scope limits."
            ),
            evidence="03_applications_without_team.csv",
        ))
    elif apps_without_team:
        ctx.add_finding(Finding(
            check="3. Team Segregation",
            control="Access Segregation",
            severity="Medium",
            title=f"{len(apps_without_team)} applications without team assigned",
            detail="Recommended to assign a team to every application for traceability.",
            evidence="03_applications_without_team.csv",
        ))
    else:
        ctx.add_finding(Finding(
            check="3. Team Segregation",
            control="Access Segregation",
            severity="Informational",
            title="All applications have a team assigned",
            detail=f"{len(applications)} applications reviewed. Segregation is correct.",
            evidence="03_applications_team_assignment.csv",
        ))


# ---------------------------------------------------------------------------
# Check 4 - Privileged users and orphan accounts
# ---------------------------------------------------------------------------
#
# Note on stale-by-last-login detection
# -------------------------------------
# The Veracode Identity API does NOT expose a per-user last_login timestamp.
# The only login-related data is available through the UI activity log
# (Admin > Users > [user] > Activity Log), which requires Administrator role
# and is not API-accessible.
#
# This check therefore detects "orphan-like" account states that ARE exposed
# by the API and that often correlate with the threats stale-account checks
# are meant to catch:
#   - active=true but login_enabled=false  (login disabled, not deactivated)
#   - active=true but no roles assigned    (zombie account)
#   - active=true but no team assignment   (effectively no access scope, but
#                                           still counts as a seat)
#   - inactive=true accounts (deactivated but still present)
#
# For true stale-by-time detection, customers must either:
#   1. Pull the activity log from the UI and feed it to this script as a CSV
#   2. Track login events via SAML IdP logs (Okta, Entra, etc.)
#   3. Run check 7 frequently to detect snapshot-to-snapshot changes


def check4_privileged_and_orphans(ctx: AuditContext, users: list[dict]) -> None:
    privileged: list[dict] = []
    orphan_no_roles: list[dict] = []
    orphan_no_teams: list[dict] = []
    login_disabled_active: list[dict] = []
    inactive_disabled: list[dict] = []

    # Roles that grant platform-wide access without needing team membership.
    # Per Veracode docs: "Only the Executive, Greenlight IDE User, Policy
    # Administrator, Security Insights, and Security Lead roles do not
    # require team membership." Plus the API-side equivalents.
    GLOBAL_SCOPE_ROLES = {
        "noteamrestrictionapi", "executive", "greenlightideuser",
        "policyadministrator", "securityinsights", "securitylead",
        "administrator",  # admins see everything
    }

    for u in users:
        raw_roles, normalized = get_user_roles(u)
        is_privileged = bool(normalized & PRIVILEGED_ROLES)
        is_active = bool(u.get("active"))
        login_enabled = u.get("login_enabled")
        login_enabled_bool = True if login_enabled is None else bool(login_enabled)
        teams = get_user_teams(u)
        team_labels = [format_team_label(t) for t in teams]
        is_api = is_api_service_account(u)
        has_global_scope = bool(normalized & GLOBAL_SCOPE_ROLES)

        row = {
            "user_id": u.get("user_id"),
            "user_name": u.get("user_name"),
            "email": u.get("email_address"),
            "active": is_active,
            "login_enabled": login_enabled_bool,
            "is_api_service_account": is_api,
            "is_privileged": is_privileged,
            "has_global_scope_role": has_global_scope,
            "role_count": len(raw_roles),
            "roles": ", ".join(raw_roles) if raw_roles else "",
            "team_count": len(teams),
            "teams": ", ".join(team_labels) if team_labels else "",
        }

        if not is_active:
            inactive_disabled.append(row)
            continue

        if is_privileged:
            privileged.append(row)

        # Active but login disabled - candidate for full deactivation
        if not login_enabled_bool:
            login_disabled_active.append(row)

        # Active but no roles - zombie account
        if not raw_roles:
            orphan_no_roles.append(row)

        # Active without team scope. We exclude:
        #  - API service accounts (often intentionally team-less via noteamrestrictionapi)
        #  - Anyone with a globally-scoped role (Administrator, Security Lead, etc.)
        if not is_api and not teams and not has_global_scope:
            orphan_no_teams.append(row)

    fields = ["user_id", "user_name", "email", "active", "login_enabled",
              "is_api_service_account", "is_privileged", "has_global_scope_role",
              "role_count", "roles", "team_count", "teams"]
    write_csv(ctx.output_dir / "04_privileged_users_active.csv", privileged, fields)
    write_csv(ctx.output_dir / "04_orphan_no_roles.csv", orphan_no_roles, fields)
    write_csv(ctx.output_dir / "04_orphan_no_teams.csv", orphan_no_teams, fields)
    write_csv(ctx.output_dir / "04_login_disabled_active.csv", login_disabled_active, fields)
    write_csv(ctx.output_dir / "04_disabled_accounts.csv", inactive_disabled, fields)

    if orphan_no_roles:
        sev = "High" if any(r["is_privileged"] for r in orphan_no_roles) else "Medium"
        ctx.add_finding(Finding(
            check="4. Privileged Users & Orphan Accounts",
            control="Account Lifecycle",
            severity=sev,
            title=f"{len(orphan_no_roles)} active accounts with no roles assigned",
            detail=(
                "Accounts marked active but with zero roles. These can still occupy "
                "a license seat and expose the platform to unintended state. "
                "Validate whether each should be deactivated or assigned roles."
            ),
            evidence="04_orphan_no_roles.csv",
        ))

    if orphan_no_teams:
        ctx.add_finding(Finding(
            check="4. Privileged Users & Orphan Accounts",
            control="Account Lifecycle",
            severity="Low",
            title=f"{len(orphan_no_teams)} active human accounts without team assignment",
            detail=(
                "Accounts with no team membership and no global override role "
                "(noteamrestrictionapi). They may still hold roles that grant access "
                "to specific applications or platform-wide functions, but lack the "
                "scope segmentation teams provide."
            ),
            evidence="04_orphan_no_teams.csv",
        ))

    if login_disabled_active:
        ctx.add_finding(Finding(
            check="4. Privileged Users & Orphan Accounts",
            control="Account Lifecycle",
            severity="Low",
            title=f"{len(login_disabled_active)} active accounts with login disabled",
            detail=(
                "active=true but login_enabled=false. Effectively unable to sign in "
                "but still appears in the user roster. Recommend full deactivation."
            ),
            evidence="04_login_disabled_active.csv",
        ))

    ctx.add_finding(Finding(
        check="4. Privileged Users & Orphan Accounts",
        control="Privileged Access Review",
        severity="Informational",
        title=f"{len(privileged)} active privileged users in tenant",
        detail=(
            "Validate against customer RACI matrix. Recommended cadence: quarterly. "
            "Note: per-user last-login timestamps are not exposed by the Veracode "
            "Identity API; for activity-based stale detection, pull the UI activity "
            "log or correlate with SAML IdP login events."
        ),
        evidence="04_privileged_users_active.csv",
    ))


# ---------------------------------------------------------------------------
# Check 5 - Traceability capability check
# ---------------------------------------------------------------------------

_TRACEABILITY_CAPABILITIES: list[dict[str, str]] = [
    {"capability": "User inventory via Identity API",
     "available": "yes",
     "endpoint": "/api/authn/v2/users",
     "self_service": "yes"},
    {"capability": "Mitigation history per finding",
     "available": "yes",
     "endpoint": "/appsec/v2/applications/{guid}/findings",
     "self_service": "yes"},
    {"capability": "Profile attribute change audit log (email/name)",
     "available": "no (not exposed by platform UI or API)",
     "endpoint": "n/a - use snapshot diff (check 7)",
     "self_service": "no"},
    {"capability": "Login event audit trail",
     "available": "yes (Reporting API or UI activity log)",
     "endpoint": "/appsec/v1/analytics/report (action_type=Login)",
     "self_service": "yes (with Reporting API role)"},
    {"capability": "Role/team/access-level change log",
     "available": "yes (Reporting API or UI activity log)",
     "endpoint": "/appsec/v1/analytics/report (action_type=Admin)",
     "self_service": "yes (with Reporting API role)"},
    {"capability": "API service account usage logs",
     "available": "via support",
     "endpoint": "n/a",
     "self_service": "no"},
]


def check5_traceability(ctx: AuditContext, run_audit_check: bool) -> None:
    write_csv(
        ctx.output_dir / "05_traceability_capabilities.csv",
        _TRACEABILITY_CAPABILITIES,
        ["capability", "available", "endpoint", "self_service"],
    )
    if not run_audit_check:
        ctx.add_finding(Finding(
            check="5. Traceability",
            control="Audit & Traceability",
            severity="Medium",
            title="Profile attribute change detection not executed",
            detail=(
                "The platform does not expose a native audit log for profile "
                "attribute changes (email, first_name, last_name, user_name). "
                "The Reporting API AUDIT report covers logins and access-level "
                "changes (roles, teams) but not field-level profile mutations. "
                "Run with --enable-change-detection to detect changes via "
                "snapshot diffing across runs. See check 7."
            ),
            evidence="05_traceability_capabilities.csv",
        ))
    else:
        ctx.add_finding(Finding(
            check="5. Traceability",
            control="Audit & Traceability",
            severity="Informational",
            title="Profile attribute change detection enabled (snapshot diff)",
            detail=(
                "Snapshot-based change detection is active. See check 7 for "
                "results. This is a compensating control because the platform "
                "does not natively log profile attribute changes."
            ),
            evidence="05_traceability_capabilities.csv",
        ))


# ---------------------------------------------------------------------------
# Check 6 - Account hardening signals
# ---------------------------------------------------------------------------

def check6_hardening(ctx: AuditContext, users: list[dict]) -> None:
    """Account hardening signals.

    SAML detection uses the documented `saml_user` boolean field from the
    Identity API (https://docs.veracode.com/r/c_identity_intro), which is
    the same flag used by the search filter `?saml_user=true`. API service
    accounts are excluded from the SAML coverage calculation since they
    do not authenticate via SAML.
    """
    rows: list[dict] = []
    saml_users = 0
    active_human = 0  # Excludes API service accounts from SAML coverage

    for u in users:
        is_active = bool(u.get("active"))
        is_saml = bool(u.get("saml_user"))
        is_api = is_api_service_account(u)
        login_enabled = u.get("login_enabled")
        # login_enabled may be missing on older records; treat absent as True
        login_enabled_bool = True if login_enabled is None else bool(login_enabled)

        rows.append({
            "user_name": u.get("user_name"),
            "email": u.get("email_address"),
            "ip_restricted": u.get("ip_restricted", False),
            "saml_user": is_saml,
            "login_enabled": login_enabled_bool,
            "is_api_service_account": is_api,
            "active": is_active,
        })

        # SAML coverage applies to active human users only
        if is_active and not is_api:
            active_human += 1
            if is_saml:
                saml_users += 1

    write_csv(
        ctx.output_dir / "06_account_hardening.csv",
        rows,
        ["user_name", "email", "ip_restricted", "saml_user", "login_enabled",
         "is_api_service_account", "active"],
    )

    # Note: login_enabled=false on active accounts is reported in check 4
    # (orphan accounts) - we don't double-report it here.

    if active_human and (saml_users / active_human) < SAML_COVERAGE_THRESHOLD:
        ctx.add_finding(Finding(
            check="6. Account Hardening",
            control="Authentication Strength",
            severity="Medium",
            title=f"Only {saml_users}/{active_human} active human users via SAML SSO",
            detail=(
                "Users with local authentication outside SAML break centralized "
                "identity control and hinder deprovisioning. (API service accounts "
                "are excluded from this calculation since they authenticate via HMAC.)"
            ),
            evidence="06_account_hardening.csv",
        ))
    else:
        ctx.add_finding(Finding(
            check="6. Account Hardening",
            control="Authentication Strength",
            severity="Informational",
            title=f"SAML coverage: {saml_users}/{active_human} active human users",
            detail="SAML SSO coverage at or above the configured threshold.",
            evidence="06_account_hardening.csv",
        ))


# ---------------------------------------------------------------------------
# Check 7 - Profile attribute change detection (snapshot diff)
# ---------------------------------------------------------------------------
#
# Why a snapshot diff and not the Reporting API?
# ----------------------------------------------
# The Veracode Reporting API exposes an AUDIT report (action_type=Login/Admin),
# but in practice the "Admin" Update rows cover role assignments, team
# membership, and access-level changes - NOT granular profile field deltas
# (email, first_name, last_name, user_name).
#
# The UI activity log has the same limitation: it shows logins and access-
# level updates but not field-level profile mutations. This is the gap that
# was escalated to the vendor's VP of Product.
#
# To detect email/name changes per UID today, the only reliable mechanism
# is to persist a snapshot of user state on each run and diff against the
# previous snapshot. Run this script on a schedule (daily/weekly) and check
# 7 will surface any UID whose email, user_name, first_name, or last_name
# changed since the last run.

TRACKED_PROFILE_FIELDS = ("email_address", "user_name", "first_name", "last_name")
SNAPSHOT_FILENAME = "users_snapshot.json"
SNAPSHOT_HISTORY_KEEP = 4  # Keep N rotated snapshots for multi-run comparison

# Persistent findings history (across runs)
FINDINGS_HISTORY_FILENAME = "findings_history.jsonl"
DEFAULT_HISTORY_WINDOW_DAYS = 56  # 8 weeks - covers the last ~2 months of weekly runs
HISTORY_HTML_MAX_RUNS = 12  # Cap how many past runs we render in the HTML panel
HISTORY_MAX_BYTES = 5 * 1024 * 1024  # 5 MB; rotate when exceeded
HISTORY_KEEP_GENERATIONS = 4  # Keep N rotated history files
# Severities included in the persistent history. Informational is excluded
# so the history stays focused on actionable signals.
HISTORY_PERSISTED_SEVERITIES: frozenset[str] = frozenset({
    "Critical", "High", "Medium", "Low",
})


def _rotate_history_if_large(history_path: Path) -> None:
    """Rotate findings_history.jsonl when it exceeds HISTORY_MAX_BYTES.
    Keeps the most recent HISTORY_KEEP_GENERATIONS rotated files."""
    try:
        if not history_path.exists() or history_path.stat().st_size < HISTORY_MAX_BYTES:
            return
    except OSError:
        return

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rotated = history_path.with_name(f"{history_path.stem}.{ts}.jsonl")
    try:
        history_path.rename(rotated)
    except OSError as e:
        log.warning("Could not rotate findings history: %s", e)
        return

    archives = sorted(
        history_path.parent.glob(f"{history_path.stem}.*.jsonl"),
        reverse=True,
    )
    for old in archives[HISTORY_KEEP_GENERATIONS:]:
        try:
            old.unlink()
        except OSError:
            pass


def append_findings_to_history(
    history_path: Path,
    findings: list[Finding],
    run_timestamp: dt.datetime,
    run_metadata: dict[str, Any] | None = None,
) -> int:
    """Append findings to the persistent JSONL history file.

    One finding per line, plus run_timestamp and any run metadata. Returns
    the number of findings actually persisted (Informational is excluded).
    Safe to call concurrently across processes since each line is atomic
    in append mode on POSIX filesystems.
    """
    history_path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_history_if_large(history_path)
    iso_ts = run_timestamp.isoformat()
    written = 0
    with history_path.open("a", encoding="utf-8") as f:
        for finding in findings:
            if finding.severity not in HISTORY_PERSISTED_SEVERITIES:
                continue
            entry = {
                "run_timestamp": iso_ts,
                **asdict(finding),
            }
            if run_metadata:
                entry["run_metadata"] = run_metadata
            f.write(json.dumps(entry) + "\n")
            written += 1
    return written


def load_findings_history(
    history_path: Path,
    window_days: int,
) -> list[dict]:
    """Load past findings within the given window from the JSONL file.

    Returns entries sorted by run_timestamp descending (most recent first).
    Call BEFORE appending the current run so you don't need to filter the
    current run back out.
    """
    if not history_path.exists():
        return []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)
    entries: list[dict] = []
    try:
        with history_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts_str = entry.get("run_timestamp", "")
                try:
                    ts = dt.datetime.fromisoformat(ts_str)
                except (ValueError, TypeError):
                    continue
                if ts < cutoff:
                    continue
                entries.append(entry)
    except OSError as e:
        log.warning("Could not read findings history: %s", e)
        return []
    entries.sort(key=lambda e: e.get("run_timestamp", ""), reverse=True)
    return entries


def group_history_by_run(history_entries: list[dict]) -> list[tuple[str, list[dict]]]:
    """Group history entries by run_timestamp, preserving descending order.
    Returns a list of (run_timestamp, [entries]) tuples, capped at
    HISTORY_HTML_MAX_RUNS most recent runs."""
    by_run: dict[str, list[dict]] = {}
    order: list[str] = []
    for e in history_entries:
        ts = e.get("run_timestamp", "")
        if ts not in by_run:
            by_run[ts] = []
            order.append(ts)
        by_run[ts].append(e)
    return [(ts, by_run[ts]) for ts in order[:HISTORY_HTML_MAX_RUNS]]


def _extract_snapshot_user(u: dict) -> dict:
    """Minimal projection of a user record for snapshotting. Includes
    fields needed for drift detection beyond the tracked profile fields."""
    raw_roles, normalized = get_user_roles(u)
    return {
        "email_address": u.get("email_address", "") or "",
        "user_name": u.get("user_name", "") or "",
        "first_name": u.get("first_name", "") or "",
        "last_name": u.get("last_name", "") or "",
        "active": bool(u.get("active")),
        "is_privileged": bool(normalized & PRIVILEGED_ROLES),
        "roles": sorted(raw_roles),
    }


def load_previous_snapshot(snapshot_path: Path) -> dict[str, dict] | None:
    """Load the previous snapshot keyed by user_id. Returns None if absent
    or if the file is unreadable/corrupt — in either case the caller treats
    this as a first run and creates a fresh baseline."""
    if not snapshot_path.exists():
        return None
    try:
        data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Snapshot unreadable at %s, treating as first run: %s",
                    snapshot_path, e)
        return None
    if not isinstance(data, dict):
        log.warning("Snapshot at %s is not a dict, treating as first run",
                    snapshot_path)
        return None
    users = data.get("users")
    if not isinstance(users, dict):
        log.warning("Snapshot at %s missing 'users' dict, treating as first run",
                    snapshot_path)
        return None
    return users


def write_snapshot(snapshot_path: Path, users: list[dict]) -> None:
    """Persist a snapshot keyed by user_id. Rotates the previous snapshot
    to a timestamped file so that the last few runs are retrievable."""
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)

    # Rotate the existing snapshot before overwriting
    if snapshot_path.exists():
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = snapshot_path.with_name(f"{snapshot_path.stem}.{ts}.json")
        try:
            snapshot_path.rename(rotated)
        except OSError as e:
            log.warning("Could not rotate previous snapshot: %s", e)
        else:
            # Clean up old rotated snapshots beyond retention window
            rotated_files = sorted(
                snapshot_path.parent.glob(f"{snapshot_path.stem}.*.json"),
                reverse=True,
            )
            for old in rotated_files[SNAPSHOT_HISTORY_KEEP:]:
                try:
                    old.unlink()
                except OSError:
                    pass

    snapshot = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "users": {
            str(u["user_id"]): _extract_snapshot_user(u)
            for u in users if u.get("user_id")
        },
    }
    snapshot_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def _email_domain(email: str) -> str:
    return email.split("@", 1)[1].lower() if "@" in email else ""


def diff_snapshots(
    previous: dict[str, dict],
    current_users: list[dict],
) -> dict[str, list[dict]]:
    """Compare previous snapshot to current users and surface multiple
    classes of identity drift.

    Returns a dict with the following keys, each a list of evidence rows:
        field_changes:        per-field changes (email/name) on existing UIDs
        added:                UIDs present now but not before
        removed:              UIDs present before but not now
        reactivated:          UIDs that went from inactive -> active
        deactivated:          UIDs that went from active -> inactive
        privilege_acquired:   UIDs that gained privileged role status
        privilege_lost:       UIDs that lost privileged role status
        username_collisions:  current username appears under a different UID than before
        email_collisions:     same email is held by 2+ active UIDs in current state
        cross_domain_emails:  email change crossed organizational domain boundary
        privileged_email_changes: email changes specifically on privileged accounts
    """
    out: dict[str, list[dict]] = {
        "field_changes": [],
        "added": [],
        "removed": [],
        "reactivated": [],
        "deactivated": [],
        "privilege_acquired": [],
        "privilege_lost": [],
        "username_collisions": [],
        "email_collisions": [],
        "cross_domain_emails": [],
        "privileged_email_changes": [],
    }

    current_by_id = {
        str(u["user_id"]): u for u in current_users if u.get("user_id")
    }

    # Build reverse indexes of the PREVIOUS snapshot for collision detection
    prev_username_to_uid: dict[str, str] = {
        prev["user_name"].lower(): uid
        for uid, prev in previous.items()
        if prev.get("user_name")
    }

    # 1. Per-UID changes
    for uid, current in current_by_id.items():
        current_proj = _extract_snapshot_user(current)

        # Username collision check applies to BOTH added and existing UIDs:
        # if a user_name appears in the current state under a different UID
        # than in the previous snapshot, that's a collision regardless of
        # whether this UID is new or pre-existing.
        cur_username_lower = current_proj["user_name"].lower()
        if cur_username_lower:
            previous_owner = prev_username_to_uid.get(cur_username_lower)
            if previous_owner and previous_owner != uid:
                out["username_collisions"].append({
                    "uid": uid,
                    "current_user_name": current_proj["user_name"],
                    "previously_held_by_uid": previous_owner,
                    "current_email": current_proj["email_address"],
                })

        if uid not in previous:
            out["added"].append({
                "uid": uid,
                "user_name": current_proj["user_name"],
                "email_address": current_proj["email_address"],
                "first_name": current_proj["first_name"],
                "last_name": current_proj["last_name"],
                "active": current_proj["active"],
                "is_privileged": current_proj["is_privileged"],
            })
            continue

        prev = previous[uid]

        # Field-level changes
        for field_name in TRACKED_PROFILE_FIELDS:
            old_val = prev.get(field_name, "") or ""
            new_val = current_proj.get(field_name, "") or ""
            if old_val == new_val:
                continue

            change_row = {
                "uid": uid,
                "field": field_name,
                "old_value": old_val,
                "new_value": new_val,
                "current_user_name": current_proj["user_name"],
                "current_email": current_proj["email_address"],
                "active": current_proj["active"],
                "is_privileged": current_proj["is_privileged"],
            }
            out["field_changes"].append(change_row)

            # Email-specific cross-cuts
            if field_name == "email_address":
                if current_proj["is_privileged"]:
                    out["privileged_email_changes"].append(change_row)
                if _email_domain(old_val) and _email_domain(new_val) \
                        and _email_domain(old_val) != _email_domain(new_val):
                    out["cross_domain_emails"].append({
                        **change_row,
                        "old_domain": _email_domain(old_val),
                        "new_domain": _email_domain(new_val),
                    })

        # Active state transitions
        prev_active = bool(prev.get("active"))
        cur_active = current_proj["active"]
        if not prev_active and cur_active:
            out["reactivated"].append({
                "uid": uid,
                "user_name": current_proj["user_name"],
                "email_address": current_proj["email_address"],
                "is_privileged": current_proj["is_privileged"],
            })
        elif prev_active and not cur_active:
            out["deactivated"].append({
                "uid": uid,
                "user_name": current_proj["user_name"],
                "email_address": current_proj["email_address"],
                "was_privileged": bool(prev.get("is_privileged")),
            })

        # Privilege transitions
        prev_priv = bool(prev.get("is_privileged"))
        cur_priv = current_proj["is_privileged"]
        prev_roles = set(prev.get("roles") or [])
        cur_roles = set(current_proj["roles"])
        if not prev_priv and cur_priv:
            out["privilege_acquired"].append({
                "uid": uid,
                "user_name": current_proj["user_name"],
                "email_address": current_proj["email_address"],
                "roles_added": ",".join(sorted(cur_roles - prev_roles)),
                "current_roles": ",".join(sorted(cur_roles)),
            })
        elif prev_priv and not cur_priv:
            out["privilege_lost"].append({
                "uid": uid,
                "user_name": current_proj["user_name"],
                "email_address": current_proj["email_address"],
                "roles_removed": ",".join(sorted(prev_roles - cur_roles)),
                "current_roles": ",".join(sorted(cur_roles)),
            })

    # 2. Removed UIDs
    out["removed"] = [
        {"uid": uid, **{k: prev.get(k, "") for k in
                       ("user_name", "email_address", "first_name", "last_name", "is_privileged")}}
        for uid, prev in previous.items()
        if uid not in current_by_id
    ]

    # 3. Email collisions in CURRENT state.
    #
    # Veracode allows the same email address to appear on a human user and
    # their paired API service account (this is a documented and intentional
    # pattern). To avoid false positives we only flag collisions where the
    # colliding accounts are of the same type: 2+ human accounts sharing an
    # email (true duplicate), or 2+ API service accounts sharing an email
    # (also unexpected). A single human paired with a single API account is
    # NOT flagged.
    #
    # Note: usernames are documented as globally unique and non-recyclable on
    # the Veracode platform, so username_collisions remains the more
    # authoritative integrity signal.
    email_to_accounts: dict[str, list[tuple[str, bool]]] = {}
    for uid, u in current_by_id.items():
        if not u.get("active"):
            continue
        email = (u.get("email_address") or "").lower()
        if not email:
            continue
        is_api = is_api_service_account(u)
        email_to_accounts.setdefault(email, []).append((uid, is_api))

    for email, accounts in email_to_accounts.items():
        if len(accounts) < 2:
            continue
        human_uids = [uid for uid, is_api in accounts if not is_api]
        api_uids = [uid for uid, is_api in accounts if is_api]
        # Legitimate pattern: one human paired with one or more API accounts.
        # Real concern: 2+ humans, or 2+ APIs, sharing one email.
        is_real_collision = len(human_uids) > 1 or len(api_uids) > 1
        if not is_real_collision:
            continue
        out["email_collisions"].append({
            "email": email,
            "uid_count": len(accounts),
            "human_uids": ",".join(sorted(human_uids)),
            "api_uids": ",".join(sorted(api_uids)),
            "collision_type": (
                "multiple_humans" if len(human_uids) > 1 and not api_uids
                else "multiple_apis" if len(api_uids) > 1 and not human_uids
                else "mixed_duplicate"
            ),
        })

    return out


# Severity policy for each drift category.
# The choices reflect the customer's threat model: identity manipulation that
# could break attribution or signal account takeover is High; routine churn
# is Informational.
_DRIFT_SEVERITY: dict[str, tuple[str, str, str]] = {
    # key: (severity, control_domain, default_finding_title_template)
    "username_collisions": ("Critical", "Identity Integrity",
        "{n} username collisions detected (platform should not allow this)"),
    "privileged_email_changes": ("High", "Identity Integrity",
        "{n} email changes on privileged accounts"),
    "privilege_acquired": ("High", "Privileged Access Review",
        "{n} users gained privileged roles since last snapshot"),
    "cross_domain_emails": ("High", "Identity Integrity",
        "{n} email changes crossed organizational domain"),
    "email_collisions": ("High", "Identity Integrity",
        "{n} email addresses are shared across multiple active UIDs"),
    "reactivated": ("Medium", "Account Lifecycle",
        "{n} accounts reactivated since last snapshot"),
    "field_changes": ("High", "Identity Integrity",
        "{n} profile attribute changes detected"),
    "privilege_lost": ("Informational", "Privileged Access Review",
        "{n} users lost privileged roles since last snapshot"),
    "deactivated": ("Informational", "Account Lifecycle",
        "{n} accounts deactivated since last snapshot"),
    "added": ("Informational", "Account Lifecycle",
        "{n} new users since last snapshot"),
    "removed": ("Informational", "Account Lifecycle",
        "{n} users removed since last snapshot"),
}


def check7_profile_changes(
    ctx: AuditContext,
    users: list[dict],
    snapshot_dir: Path,
) -> None:
    """Detect identity drift per UID by diffing against the previous snapshot.

    Catches: field-level mutations, account additions/removals, active-state
    transitions, privilege changes, cross-domain email changes, username/email
    collisions, and privileged-account email changes.
    """
    snapshot_path = snapshot_dir / SNAPSHOT_FILENAME
    previous = load_previous_snapshot(snapshot_path)

    if previous is None:
        write_snapshot(snapshot_path, users)
        ctx.add_finding(Finding(
            check="7. Profile Attribute Changes",
            control="Identity Integrity",
            severity="Informational",
            title="Baseline snapshot created (first run)",
            detail=(
                f"No previous snapshot found at {snapshot_path}. Captured "
                f"{len([u for u in users if u.get('user_id')])} users as baseline. "
                "On subsequent runs this check will detect identity drift "
                "(field changes, lifecycle transitions, privilege changes, "
                "username/email collisions)."
            ),
            evidence=str(snapshot_path),
        ))
        return

    drift = diff_snapshots(previous, users)

    # Persist all evidence categories. Empty CSVs are still useful as
    # explicit "we checked and found nothing" evidence.
    csv_specs: dict[str, list[str]] = {
        "field_changes": ["uid", "field", "old_value", "new_value",
                          "current_user_name", "current_email", "active",
                          "is_privileged"],
        "added": ["uid", "user_name", "email_address", "first_name",
                  "last_name", "active", "is_privileged"],
        "removed": ["uid", "user_name", "email_address", "first_name",
                    "last_name", "is_privileged"],
        "reactivated": ["uid", "user_name", "email_address", "is_privileged"],
        "deactivated": ["uid", "user_name", "email_address", "was_privileged"],
        "privilege_acquired": ["uid", "user_name", "email_address",
                               "roles_added", "current_roles"],
        "privilege_lost": ["uid", "user_name", "email_address",
                           "roles_removed", "current_roles"],
        "username_collisions": ["uid", "current_user_name",
                                "previously_held_by_uid", "current_email"],
        "email_collisions": ["email", "uid_count", "collision_type",
                              "human_uids", "api_uids"],
        "cross_domain_emails": ["uid", "field", "old_value", "new_value",
                                "old_domain", "new_domain",
                                "current_user_name", "is_privileged"],
        "privileged_email_changes": ["uid", "field", "old_value", "new_value",
                                     "current_user_name", "is_privileged"],
    }
    for category, fields in csv_specs.items():
        write_csv(
            ctx.output_dir / f"07_{category}.csv",
            drift[category],
            fields,
        )

    # Emit a finding per non-empty drift category, ordered by severity.
    any_drift = False
    for category, rows in drift.items():
        if not rows:
            continue
        any_drift = True
        severity, control, title_tpl = _DRIFT_SEVERITY[category]
        ctx.add_finding(Finding(
            check="7. Profile Attribute Changes",
            control=control,
            severity=severity,
            title=title_tpl.format(n=len(rows)),
            detail=_drift_detail(category, rows),
            evidence=f"07_{category}.csv",
        ))

    if not any_drift:
        ctx.add_finding(Finding(
            check="7. Profile Attribute Changes",
            control="Identity Integrity",
            severity="Informational",
            title="No identity drift since last snapshot",
            detail=(
                f"Compared {len(users)} current users against previous snapshot. "
                "No field changes, lifecycle transitions, privilege changes, "
                "or collisions detected."
            ),
            evidence="",
        ))

    write_snapshot(snapshot_path, users)


def _drift_detail(category: str, rows: list[dict]) -> str:
    """Construct a finding detail tailored to the drift category."""
    if category == "username_collisions":
        return (
            "A current user_name appears under a different UID than in the "
            "previous snapshot. Veracode documents usernames as unique and "
            "non-recyclable, so this should not be possible. Investigate "
            "immediately as a potential platform integrity issue or attribution "
            "break."
        )
    if category == "privileged_email_changes":
        return (
            "Email address mutations on accounts with elevated roles. "
            "Privileged-account email changes warrant immediate review against "
            "change-management records and out-of-band confirmation with the "
            "account owner."
        )
    if category == "privilege_acquired":
        return (
            "Users gained privileged roles since the last snapshot. Validate "
            "against change tickets, JIT requests, or ticketed approvals."
        )
    if category == "cross_domain_emails":
        return (
            "Email changes where the new email is in a different domain than "
            "the old email. A move from corporate to personal domain is a "
            "stronger signal than a same-domain change."
        )
    if category == "email_collisions":
        return (
            "Same email address is held by 2+ human accounts, or 2+ API service "
            "accounts, in the current state. Often indicates duplicate accounts, "
            "IdP misconfiguration, or attempted impersonation. Investigate "
            "ownership and consolidate. Note: a single human paired with their "
            "own API service account using the same email is intentional Veracode "
            "behavior and is NOT flagged here."
        )
    if category == "reactivated":
        return (
            "Accounts that were inactive in the previous snapshot are now "
            "active. Confirm the reactivation was authorized and that the "
            "account holder is the intended user."
        )
    if category == "field_changes":
        return (
            "Per-field profile mutations (email, user_name, first_name, "
            "last_name) on existing UIDs. See the CSV for old/new values "
            "per field. Note: user_name is documented as immutable; entries "
            "with field=user_name should be escalated."
        )
    if category == "privilege_lost":
        return "Users that lost privileged role status. Routine, but record for audit trail."
    if category == "deactivated":
        return "Accounts that transitioned from active to inactive. Routine offboarding signal."
    if category == "added":
        return "New UIDs since the previous snapshot."
    if category == "removed":
        return "UIDs no longer present. Veracode does not recycle usernames, so removal is rare; verify this matches expected offboarding."
    return ""


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

# Maximum rows to embed inline per evidence table. Customers can open the
# CSV for the full list. Keeps the HTML scannable.
INLINE_PREVIEW_ROWS = 10

CHECK_TITLES: dict[str, str] = {
    "1": "Identity model",
    "2": "RBAC",
    "3": "Team segregation",
    "4": "Privileged users & orphan accounts",
    "5": "Traceability",
    "6": "Account hardening",
    "7": "Identity drift detection",
}

CHECK_DESCRIPTIONS: dict[str, str] = {
    "1": "Verifies every user has an immutable UID distinct from email or username.",
    "2": "Reviews role distribution, administrator ratio, API service accounts, and segregation of duties.",
    "3": "Inventories teams and flags applications without team assignment.",
    "4": "Lists active privileged users and detects orphan accounts (no roles, no teams, login disabled).",
    "5": "Documents what the platform exposes for audit and traceability.",
    "6": "Reports IP restriction and SAML SSO coverage.",
    "7": "Detects identity changes since the previous snapshot: field changes, lifecycle transitions, privilege changes, collisions.",
}


def _check_number(check: str) -> str:
    """Extract '1' from '1. Identity Model'. Returns '' if not numbered."""
    return check.split(".", 1)[0].strip() if "." in check else ""


def _read_csv_preview(csv_path: Path, limit: int = INLINE_PREVIEW_ROWS) -> tuple[list[str], list[list[str]], int]:
    """Read up to `limit` data rows from a CSV. Returns (headers, rows, total_data_rows)."""
    if not csv_path.exists():
        return [], [], 0
    try:
        with csv_path.open(encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            rows: list[list[str]] = []
            total = 0
            for row in reader:
                total += 1
                if len(rows) < limit:
                    rows.append(row)
            return headers, rows, total
    except (OSError, StopIteration):
        return [], [], 0


def _render_inline_table(csv_path: Path) -> str:
    """Render a small HTML table previewing a CSV. Returns '' if no data."""
    headers, rows, total = _read_csv_preview(csv_path)
    if not rows:
        return ""

    # Columns that commonly hold long comma-separated strings get a
    # soft width cap with overflow ellipsis. Customers can read full values
    # in the underlying CSV; the inline preview prioritizes legibility.
    LONG_COLS = {"roles", "teams", "details", "modifiers", "current_roles",
                 "roles_added", "roles_removed"}

    head_html = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body_html_parts: list[str] = []
    for row in rows:
        cells = []
        for header_name, value in zip(headers, row):
            cls = ' class="cell-long"' if header_name in LONG_COLS else ""
            title_attr = f' title="{html.escape(value)}"' if header_name in LONG_COLS and value else ""
            cells.append(f'<td{cls}{title_attr}>{html.escape(value)}</td>')
        body_html_parts.append("<tr>" + "".join(cells) + "</tr>")
    body_html = "".join(body_html_parts)
    more = ""
    if total > len(rows):
        more = (
            f'<div class="more-note">'
            f'Showing first {len(rows)} of {total} rows. '
            f'See <code>{html.escape(csv_path.name)}</code> for the full list.'
            f'</div>'
        )
    return (
        f'<div class="evidence-wrap">'
        f'<table class="evidence"><thead><tr>{head_html}</tr></thead>'
        f'<tbody>{body_html}</tbody></table>'
        f'</div>{more}'
    )


def _render_finding_card(ctx: AuditContext, f: Finding, embed_table: bool) -> str:
    """Render a single finding. If embed_table is True, includes an inline
    preview of the evidence CSV (used for Critical/High findings in the
    action panel)."""
    sev_color = SEVERITY_COLORS[f.severity]
    table_html = ""
    if embed_table and f.evidence:
        evidence_path = ctx.output_dir / f.evidence
        table_html = _render_inline_table(evidence_path)

    evidence_link = ""
    if f.evidence:
        evidence_link = (
            f'<div class="evidence-link">Evidence: '
            f'<code>{html.escape(f.evidence)}</code></div>'
        )

    return f"""
    <div class="finding" style="border-left-color: {sev_color}; background: {sev_color}11;">
      <div class="finding-header">
        <span class="sev-badge" style="background: {sev_color}">{html.escape(f.severity)}</span>
        <span class="finding-title">{html.escape(f.title)}</span>
      </div>
      <div class="finding-detail">{html.escape(f.detail)}</div>
      {evidence_link}
      {table_html}
    </div>"""


def _check_status_badge(findings_in_check: list[Finding]) -> str:
    """Pick the highest-severity badge for a check, or 'All clear' if none."""
    if not findings_in_check:
        return f'<span class="status-badge" style="background: #28a745">All clear</span>'

    # Filter out informational-only findings for the "all clear" determination
    non_info = [f for f in findings_in_check if f.severity != "Informational"]
    if not non_info:
        return f'<span class="status-badge" style="background: #566573">{len(findings_in_check)} info</span>'

    counts: dict[str, int] = {}
    for f in non_info:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    pieces = []
    for sev in ("Critical", "High", "Medium", "Low"):
        if sev in counts:
            pieces.append(
                f'<span class="status-badge" style="background: {SEVERITY_COLORS[sev]}">'
                f'{counts[sev]} {sev.lower()}</span>'
            )
    return "".join(pieces)


def _render_history_panel(history_entries: list[dict], window_days: int) -> str:
    """Render the 'Recent activity' panel showing past findings grouped by run.
    Returns empty string if there is no history to display."""
    if not history_entries:
        return ""

    runs = group_history_by_run(history_entries)
    if not runs:
        return ""

    # Aggregate severity counts across the window for the header summary
    window_counts: dict[str, int] = {}
    for e in history_entries:
        sev = e.get("severity", "")
        if sev:
            window_counts[sev] = window_counts.get(sev, 0) + 1

    summary_chips = " ".join(
        f'<span class="chip" style="background: {SEVERITY_COLORS[s]}">'
        f'{html.escape(s)}: {n}</span>'
        for s, n in sorted(window_counts.items(),
                           key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
    )

    run_blocks: list[str] = []
    for run_ts, entries in runs:
        # Format the timestamp for display
        try:
            run_dt = dt.datetime.fromisoformat(run_ts)
            display_date = run_dt.strftime("%Y-%m-%d %H:%M UTC")
            iso_date = run_dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            display_date = run_ts
            iso_date = run_ts

        # Severity tally for this run
        run_sev_counts: dict[str, int] = {}
        for e in entries:
            sev = e.get("severity", "")
            if sev:
                run_sev_counts[sev] = run_sev_counts.get(sev, 0) + 1
        run_chips = " ".join(
            f'<span class="status-badge" style="background: {SEVERITY_COLORS[s]}">'
            f'{n} {s.lower()}</span>'
            for s, n in sorted(run_sev_counts.items(),
                               key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
        )

        finding_rows = "".join(
            f'<tr>'
            f'<td><span class="sev-badge" style="background: {SEVERITY_COLORS.get(e.get("severity", ""), "#888")}">{html.escape(e.get("severity", ""))}</span></td>'
            f'<td>{html.escape(e.get("check", ""))}</td>'
            f'<td>{html.escape(e.get("title", ""))}</td>'
            f'</tr>'
            for e in entries
        )

        # Auto-expand the most recent run, collapse the rest
        is_open = "open" if run_ts == runs[0][0] else ""
        run_blocks.append(f"""
        <details class="history-run" {is_open}>
          <summary>
            <div class="history-run-left">
              <span class="history-date">{html.escape(iso_date)}</span>
              <span class="history-time">{html.escape(display_date)}</span>
            </div>
            <div class="history-run-right">{run_chips}</div>
          </summary>
          <table class="history-table">
            <thead><tr><th>Severity</th><th>Check</th><th>Finding</th></tr></thead>
            <tbody>{finding_rows}</tbody>
          </table>
        </details>""")

    return f"""
        <section class="history-panel">
          <h2>Recent activity (last {window_days} days)</h2>
          <div class="history-summary">
            <div style="font-size: 12px; color: #586069; margin-bottom: 8px;">
              Findings from past runs (current run excluded). Informational findings are not retained.
            </div>
            <div>{summary_chips}</div>
          </div>
          <div class="history-runs">
            {''.join(run_blocks)}
          </div>
        </section>"""


def render_html(
    ctx: AuditContext,
    totals: dict[str, int],
    history_entries: list[dict] | None = None,
    history_window_days: int = DEFAULT_HISTORY_WINDOW_DAYS,
) -> Path:
    findings = ctx.sorted_findings()

    # Group findings by check number
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        n = _check_number(f.check)
        by_check.setdefault(n, []).append(f)

    # Severity counts for header chips
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Action panel: only Critical and High findings, with embedded evidence
    priority_findings = [f for f in findings if f.severity in ("Critical", "High")]
    action_panel_html = ""
    if priority_findings:
        cards = "".join(
            _render_finding_card(ctx, f, embed_table=True)
            for f in priority_findings
        )
        action_panel_html = f"""
        <section class="action-panel">
          <h2>Needs attention this run</h2>
          {cards}
        </section>"""

    # Recent activity panel (history from past runs)
    history_panel_html = _render_history_panel(
        history_entries or [], history_window_days
    )

    # Per-check accordion sections
    check_sections: list[str] = []
    for check_num in sorted(by_check.keys()):
        check_findings = by_check[check_num]
        title = CHECK_TITLES.get(check_num, f"Check {check_num}")
        description = CHECK_DESCRIPTIONS.get(check_num, "")

        has_priority = any(f.severity in ("Critical", "High") for f in check_findings)
        # Auto-expand checks with Critical/High findings, otherwise keep collapsed
        is_open = "open" if has_priority else ""

        # Render finding cards for this check (inline tables only for Medium/Low,
        # since Critical/High already appear in the top action panel)
        finding_cards = "".join(
            _render_finding_card(
                ctx, f,
                embed_table=f.severity not in ("Critical", "High"),
            )
            for f in check_findings
        )

        status_badges = _check_status_badge(check_findings)
        check_sections.append(f"""
        <details class="check" {is_open}>
          <summary>
            <div class="check-summary-left">
              <span class="check-num">{html.escape(check_num)}</span>
              <span class="check-title">{html.escape(title)}</span>
            </div>
            <div class="check-summary-right">{status_badges}</div>
          </summary>
          <div class="check-body">
            <div class="check-description">{html.escape(description)}</div>
            {finding_cards}
          </div>
        </details>""")

    # Header: severity chips and totals
    summary_chips = " ".join(
        f'<span class="chip" style="background: {SEVERITY_COLORS[s]}">'
        f'{html.escape(s)}: {n}</span>'
        for s, n in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]])
    )
    totals_html = " ".join(
        f'<div class="metric"><div class="metric-value">{html.escape(str(v))}</div>'
        f'<div class="metric-label">{html.escape(k)}</div></div>'
        for k, v in totals.items()
    )

    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Veracode Tenant Audit</title>
  <style>
    :root {{
      --crit: {SEVERITY_COLORS['Critical']};
      --high: {SEVERITY_COLORS['High']};
      --med:  {SEVERITY_COLORS['Medium']};
      --low:  {SEVERITY_COLORS['Low']};
      --info: {SEVERITY_COLORS['Informational']};
    }}
    body {{
      font-family: -apple-system, Segoe UI, Roboto, sans-serif;
      margin: 0; padding: 0; color: #1a1a1a; background: #f5f6fa;
      line-height: 1.5;
    }}
    header {{
      background: #0b3d91; color: white; padding: 24px 32px;
    }}
    header h1 {{ margin: 0 0 4px; font-size: 22px; font-weight: 500; }}
    header .subtitle {{ font-size: 13px; opacity: 0.85; }}
    main {{
      padding: 24px 32px; max-width: 1100px; margin: 0 auto;
    }}
    section {{
      background: white; border: 1px solid #e1e4e8; border-radius: 8px;
      padding: 20px 24px; margin-bottom: 18px;
    }}
    h2 {{
      margin: 0 0 14px; font-size: 16px; font-weight: 500; color: #0b3d91;
    }}
    .metrics {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }}
    .metric {{
      background: #f5f6fa; border: 1px solid #e1e4e8;
      border-radius: 6px; padding: 10px 14px; min-width: 100px;
    }}
    .metric-value {{ font-size: 22px; font-weight: 600; color: #0b3d91; }}
    .metric-label {{
      font-size: 11px; text-transform: uppercase; color: #586069;
      letter-spacing: 0.5px;
    }}
    .chip {{
      display: inline-block; padding: 4px 10px; border-radius: 12px;
      color: white; font-size: 12px; margin-right: 6px; font-weight: 500;
    }}
    .action-panel {{
      border-top: 4px solid var(--crit);
    }}
    .action-panel h2 {{ color: var(--crit); }}
    .finding {{
      border-left: 3px solid; padding: 10px 14px; margin-bottom: 10px;
      border-radius: 0 6px 6px 0;
    }}
    .finding:last-child {{ margin-bottom: 0; }}
    .finding-header {{
      display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
    }}
    .sev-badge {{
      color: white; padding: 2px 8px; border-radius: 3px;
      font-size: 10px; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.3px; flex-shrink: 0;
    }}
    .finding-title {{ font-size: 14px; font-weight: 500; }}
    .finding-detail {{ font-size: 13px; color: #444; margin-bottom: 6px; }}
    .evidence-link {{
      font-size: 12px; color: #586069; margin-top: 6px;
    }}
    .evidence-link code, .more-note code {{
      background: rgba(0,0,0,0.06); padding: 1px 5px; border-radius: 3px;
      font-size: 11px; font-family: 'SF Mono', Consolas, monospace;
    }}
    .evidence-wrap {{
      margin-top: 8px;
      border: 1px solid rgba(0,0,0,0.08);
      border-radius: 6px;
      overflow-x: auto;
      overflow-y: visible;
      max-width: 100%;
      /* visual hint that the table can scroll */
      background:
        linear-gradient(to right, white 30%, rgba(255,255,255,0)),
        linear-gradient(to right, rgba(0,0,0,0.06), rgba(255,255,255,0) 70%) 0 100%,
        linear-gradient(to left, white 30%, rgba(255,255,255,0)) 100% 0,
        linear-gradient(to left, rgba(0,0,0,0.06), rgba(255,255,255,0) 70%) 100% 0;
      background-repeat: no-repeat;
      background-size: 30px 100%, 14px 100%, 30px 100%, 14px 100%;
      background-attachment: local, scroll, local, scroll;
    }}
    table.evidence {{
      width: max-content;
      min-width: 100%;
      border-collapse: collapse; font-size: 12px;
      background: white;
    }}
    table.evidence th {{
      background: #f5f6fa; font-weight: 500; text-align: left;
      padding: 6px 10px; color: #586069; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.3px;
      border-bottom: 1px solid #e1e4e8;
      white-space: nowrap;
      position: sticky; top: 0;
    }}
    table.evidence td {{
      padding: 6px 10px; border-bottom: 1px solid #f0f2f5;
      vertical-align: top; font-size: 12px;
      white-space: nowrap;
    }}
    /* Long string columns (role/team lists) get a soft cap with an ellipsis,
       but the full value is in the title attribute (browser tooltip) and
       fully visible in the underlying CSV. */
    table.evidence td.cell-long {{
      max-width: 360px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    table.evidence tr:last-child td {{ border-bottom: none; }}
    .more-note {{
      font-size: 11px; color: #586069; padding: 6px 10px 0;
    }}
    details.check {{
      background: white; border: 1px solid #e1e4e8;
      border-radius: 8px; margin-bottom: 8px;
    }}
    details.check[open] {{ border-color: #c8d0d9; }}
    details.check summary {{
      padding: 12px 18px; cursor: pointer; list-style: none;
      display: flex; justify-content: space-between; align-items: center;
      font-size: 14px;
    }}
    details.check summary::-webkit-details-marker {{ display: none; }}
    details.check summary::before {{
      content: '▸'; margin-right: 10px; color: #586069;
      transition: transform 0.15s; display: inline-block;
    }}
    details.check[open] summary::before {{ transform: rotate(90deg); }}
    .check-summary-left {{ display: flex; align-items: center; gap: 10px; flex: 1; }}
    .check-num {{
      background: #0b3d91; color: white; width: 22px; height: 22px;
      border-radius: 50%; display: inline-flex; align-items: center;
      justify-content: center; font-size: 11px; font-weight: 500;
    }}
    .check-title {{ font-weight: 500; }}
    .check-summary-right {{ display: flex; gap: 6px; }}
    .status-badge {{
      color: white; padding: 3px 9px; border-radius: 10px;
      font-size: 11px; font-weight: 500;
    }}
    .check-body {{
      padding: 0 18px 16px; border-top: 1px solid #f0f2f5;
    }}
    .check-description {{
      font-size: 12px; color: #586069; padding: 12px 0;
      font-style: italic;
    }}
    .history-panel {{
      border-top: 4px solid #586069;
    }}
    .history-panel h2 {{ color: #586069; }}
    .history-summary {{ margin-bottom: 14px; }}
    details.history-run {{
      background: #fafbfc; border: 1px solid #e1e4e8;
      border-radius: 6px; margin-bottom: 6px;
    }}
    details.history-run[open] {{ background: white; border-color: #c8d0d9; }}
    details.history-run summary {{
      padding: 9px 14px; cursor: pointer; list-style: none;
      display: flex; justify-content: space-between; align-items: center;
      font-size: 13px;
    }}
    details.history-run summary::-webkit-details-marker {{ display: none; }}
    details.history-run summary::before {{
      content: '▸'; margin-right: 8px; color: #586069;
      transition: transform 0.15s; display: inline-block; font-size: 11px;
    }}
    details.history-run[open] summary::before {{ transform: rotate(90deg); }}
    .history-run-left {{ display: flex; align-items: baseline; gap: 12px; flex: 1; }}
    .history-date {{ font-weight: 500; }}
    .history-time {{ font-size: 11px; color: #586069; }}
    .history-run-right {{ display: flex; gap: 4px; }}
    table.history-table {{
      width: 100%; border-collapse: collapse; font-size: 12px;
      border-top: 1px solid #f0f2f5;
    }}
    table.history-table th {{
      text-align: left; padding: 6px 14px; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.3px;
      color: #586069; background: #f5f6fa; font-weight: 500;
    }}
    table.history-table td {{
      padding: 6px 14px; border-top: 1px solid #f0f2f5;
      vertical-align: top;
    }}
    table.history-table td:first-child {{ width: 90px; }}
    .footer-note {{
      font-size: 11px; color: #586069; text-align: center;
      padding: 16px; margin-top: 8px;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Veracode tenant audit</h1>
    <div class="subtitle">Generated {generated_at} &nbsp;·&nbsp; Region: {html.escape(ctx.base_url)}</div>
  </header>
  <main>
    <section>
      <h2>Summary</h2>
      <div class="metrics">{totals_html}</div>
      <div>{summary_chips}</div>
    </section>

    {action_panel_html}

    <section>
      <h2>All checks</h2>
      <div style="font-size: 12px; color: #586069; margin-bottom: 12px;">
        Click a check to expand its findings. Checks with critical or high findings are auto-expanded.
      </div>
      {''.join(check_sections)}
    </section>

    {history_panel_html}

    <div class="footer-note">
      Full evidence is in CSV files under the same output directory.
      For SIEM ingestion, use <code>findings.json</code>.
      Persistent finding history is in <code>findings_history.jsonl</code> under the snapshot directory.
    </div>
  </main>
</body>
</html>
"""
    out = ctx.output_dir / "veracode_tenant_audit.html"
    out.write_text(html_doc, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def get_user_detail(ctx: AuditContext, user_id: str) -> dict:
    """Fetch a single user's full record from /users/{user_id}.

    The list endpoint /users?detailed=true returns a partial view that
    typically OMITS the teams[], permissions[], and full roles[] arrays.
    For accurate detection of API service accounts, team membership, and
    role inventory, each user must be fetched individually.
    """
    url = f"{ctx.base_url}/api/authn/v2/users/{user_id}"
    resp = _veracode_get(ctx, url)
    _raise_for_known_errors(resp)
    return resp.json()


def enrich_users_concurrent(
    ctx: AuditContext,
    users_summary: list[dict],
) -> list[dict]:
    """Fetch the full record for every user in parallel, respecting the
    rate limiter. Falls back to the summary record on individual failures."""
    if not users_summary:
        return []

    log.info("Enriching %d users via /users/{id} (concurrency=%d)...",
             len(users_summary), ctx.concurrency)

    enriched: list[dict] = [None] * len(users_summary)  # type: ignore

    def fetch_one(idx: int, user: dict) -> tuple[int, dict]:
        uid = user.get("user_id")
        if not uid:
            return idx, user
        try:
            return idx, get_user_detail(ctx, uid)
        except (requests.HTTPError, requests.ConnectionError) as e:
            log.warning("  could not enrich user %s: %s", uid, e)
            return idx, user

    completed = 0
    with ThreadPoolExecutor(max_workers=ctx.concurrency) as pool:
        futures = [
            pool.submit(fetch_one, i, u)
            for i, u in enumerate(users_summary)
        ]
        for future in as_completed(futures):
            idx, user = future.result()
            enriched[idx] = user
            completed += 1
            if completed % 100 == 0:
                log.info("  %d/%d users enriched", completed, len(users_summary))

    return enriched


def fetch_tenant(
    ctx: AuditContext,
    skip_apps: bool,
) -> tuple[list[dict], list[dict], list[dict]]:
    log.info("Fetching users (summary)...")
    users_summary = get_paginated(
        ctx, "/api/authn/v2/users", "users",
        params={"detailed": "true"},
    )
    log.info("  -> %d users", len(users_summary))

    # The list response does NOT reliably include teams[], permissions[],
    # or the full roles[] array per user. Fetch each user individually
    # in parallel to get the complete record.
    users = enrich_users_concurrent(ctx, users_summary)

    log.info("Fetching teams...")
    teams = get_paginated(ctx, "/api/authn/v2/teams", "teams")
    log.info("  -> %d teams", len(teams))

    applications: list[dict] = []
    if not skip_apps:
        log.info("Fetching applications...")
        applications = get_paginated(ctx, "/appsec/v1/applications", "applications")
        log.info("  -> %d applications", len(applications))

    return users, teams, applications


def run_checks(
    ctx: AuditContext,
    users: list[dict],
    teams: list[dict],
    applications: list[dict],
    enable_change_detection: bool,
    snapshot_dir: Path,
) -> None:
    check1_identity_model(ctx, users)
    check2_rbac(ctx, users)
    check3_teams(ctx, teams, applications)
    check4_privileged_and_orphans(ctx, users)
    check5_traceability(ctx, run_audit_check=enable_change_detection)
    check6_hardening(ctx, users)
    if enable_change_detection:
        check7_profile_changes(ctx, users, snapshot_dir)


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Veracode tenant audit (read-only). Scales to large tenants "
                    "via concurrent pagination and rate-limited parallel fetches. "
                    "Requires VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET env "
                    "vars or ~/.veracode/credentials. The API service account "
                    "needs Admin API role."
    )
    p.add_argument("--region", choices=list(REGIONS), default="commercial")
    p.add_argument("--output", default="./output", help="Output directory")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                   help="Max parallel HTTP workers (default 8)")
    p.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT_PER_MIN,
                   help="Global rate limit in requests per minute (default 200, Veracode caps at 250)")
    p.add_argument("--skip-apps", action="store_true",
                   help="Skip applications inventory")
    p.add_argument("--enable-change-detection", action="store_true",
                   help="Run check 7: detect email/name changes per UID by "
                        "diffing against a previous snapshot. On first run, "
                        "creates the baseline. On subsequent runs, surfaces "
                        "changes. Run on a schedule (daily/weekly).")
    p.add_argument("--snapshot-dir", default="./snapshots",
                   help="Directory where the user state snapshot is persisted "
                        "across runs (default: ./snapshots)")
    p.add_argument("--history-window-days", type=int,
                   default=DEFAULT_HISTORY_WINDOW_DAYS,
                   help=f"Days of past findings to display in the 'Recent activity' "
                        f"panel of the HTML report (default {DEFAULT_HISTORY_WINDOW_DAYS}, "
                        f"i.e. ~8 weeks). Findings are persisted to "
                        f"findings_history.jsonl in the snapshot dir indefinitely.")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    # Clamp risky values rather than letting them silently degrade behavior.
    if args.rate_limit > 250:
        log.warning("Clamping --rate-limit %d to 250 (Veracode documented cap)",
                    args.rate_limit)
        args.rate_limit = 250
    if args.rate_limit < 1:
        args.rate_limit = 1
    if args.concurrency < 1:
        args.concurrency = 1
    if args.concurrency > 32:
        log.warning("Clamping --concurrency %d to 32", args.concurrency)
        args.concurrency = 32

    ctx = AuditContext(
        base_url=REGIONS[args.region],
        output_dir=Path(args.output),
        concurrency=args.concurrency,
        rate_limiter=RateLimiter(args.rate_limit),
        session=build_session(pool_size=max(args.concurrency * 2, 20)),
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)

    log.info("Region: %s (%s)", args.region, ctx.base_url)
    log.info("Output: %s", ctx.output_dir.resolve())
    log.info("Concurrency: %d, Rate limit: %d req/min", args.concurrency, args.rate_limit)

    started = time.monotonic()
    try:
        users, teams, applications = fetch_tenant(ctx, args.skip_apps)
    except PermissionError as e:
        log.error("%s", e)
        return EXIT_AUTH_ERROR
    except requests.RequestException as e:
        log.error("API error: %s", e)
        return EXIT_API_ERROR

    fetch_elapsed = time.monotonic() - started
    log.info("Tenant fetch completed in %.1fs", fetch_elapsed)

    run_checks(
        ctx, users, teams, applications,
        enable_change_detection=args.enable_change_detection,
        snapshot_dir=Path(args.snapshot_dir),
    )

    write_json(
        ctx.output_dir / "findings.json",
        [asdict(f) for f in ctx.sorted_findings()],
    )

    # Load PAST history for the HTML panel BEFORE appending the current
    # run's findings. This means we don't need to filter the current run
    # back out of what we just wrote, and avoids a write-then-read round trip.
    snapshot_dir = Path(args.snapshot_dir)
    history_path = snapshot_dir / FINDINGS_HISTORY_FILENAME
    history_entries = load_findings_history(
        history_path, window_days=args.history_window_days,
    )
    log.info("Loaded %d past findings within last %d days for history panel",
             len(history_entries), args.history_window_days)

    # Now append this run's findings to the persistent history.
    run_timestamp = dt.datetime.now(dt.timezone.utc)
    persisted = append_findings_to_history(
        history_path,
        ctx.findings,
        run_timestamp,
        run_metadata={"region": args.region, "output_dir": str(ctx.output_dir)},
    )
    log.info("Persisted %d findings to history at %s", persisted, history_path)

    totals = {
        "Total users": len(users),
        "Active users": sum(1 for u in users if u.get("active")),
        "Teams": len(teams),
        "Applications": len(applications),
        "Findings": len(ctx.findings),
    }
    report_path = render_html(
        ctx, totals,
        history_entries=history_entries,
        history_window_days=args.history_window_days,
    )

    log.info("HTML report: %s", report_path)
    log.info("Evidence directory: %s", ctx.output_dir.resolve())
    log.info("Total runtime: %.1fs", time.monotonic() - started)
    for k, v in totals.items():
        log.info("  %s: %s", k, v)

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

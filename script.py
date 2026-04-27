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

STALE_DAYS_DEFAULT = 90
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
    stale_days: int
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


def get_json(ctx: AuditContext, path: str) -> dict:
    """Single resource GET."""
    resp = _veracode_get(ctx, f"{ctx.base_url}{path}")
    _raise_for_known_errors(resp)
    return resp.json()


def fetch_concurrent(
    ctx: AuditContext,
    items: list[Any],
    fetch_fn: Callable[[AuditContext, Any], dict],
    label: str = "items",
) -> list[dict | None]:
    """Run fetch_fn against many items concurrently. Preserves input order.
    Returns None for failed fetches so callers can decide fallback behavior."""
    results: list[dict | None] = [None] * len(items)
    if not items:
        return results

    log.info("Fetching %d %s concurrently (workers=%d)...", len(items), label, ctx.concurrency)

    with ThreadPoolExecutor(max_workers=ctx.concurrency) as pool:
        future_to_idx = {
            pool.submit(fetch_fn, ctx, item): idx
            for idx, item in enumerate(items)
        }
        completed = 0
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except requests.HTTPError as e:
                log.warning("  failed to fetch %s[%d]: %s", label, idx, e)
                results[idx] = None
            completed += 1
            if completed % 100 == 0:
                log.info("  %d/%d %s", completed, len(items), label)
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_role_name(name: str) -> str:
    return (name or "").lower().replace(" ", "").replace("_", "").replace("-", "")


def parse_last_login(raw: Any) -> dt.datetime | None:
    """Handle epoch milliseconds, ISO 8601, or missing values."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        try:
            return dt.datetime.fromtimestamp(float(raw) / 1000, tz=dt.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(raw, str):
        if raw.isdigit():
            try:
                return dt.datetime.fromtimestamp(int(raw) / 1000, tz=dt.timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        try:
            return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def detect_sod_conflicts(normalized_roles: set[str]) -> list[str]:
    return [label for pair, label in SOD_CONFLICT_PAIRS if pair <= normalized_roles]


def get_user_roles(user: dict) -> tuple[list[str], set[str]]:
    """Return (raw_role_names, normalized_role_set), computed once per user."""
    raw = [r.get("role_name", "") for r in user.get("roles") or []]
    return raw, {normalize_role_name(r) for r in raw}


def is_api_service_account(user: dict) -> bool:
    return any(
        p.get("permission_name") == "apiUser"
        for p in user.get("permissions") or []
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
        teams = [t.get("team_name") or t.get("team_id") for t in (u.get("teams") or [])]
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
            "teams": ", ".join(t.get("team_name", t.get("guid", "")) for t in app_teams),
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
# Check 4 - Privileged users and stale accounts
# ---------------------------------------------------------------------------

def check4_privileged_and_stale(ctx: AuditContext, users: list[dict]) -> None:
    privileged: list[dict] = []
    stale: list[dict] = []
    inactive_disabled: list[dict] = []
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=ctx.stale_days)

    for u in users:
        raw_roles, normalized = get_user_roles(u)
        is_privileged = bool(normalized & PRIVILEGED_ROLES)

        last_login_raw = (
            u.get("last_login")
            or (u.get("login_account") or {}).get("last_login")
        )
        last_login_dt = parse_last_login(last_login_raw)

        row = {
            "user_id": u.get("user_id"),
            "user_name": u.get("user_name"),
            "email": u.get("email_address"),
            "active": u.get("active"),
            "is_privileged": is_privileged,
            "roles": ", ".join(raw_roles),
            "last_login": last_login_raw or "never",
            "days_since_login": (now - last_login_dt).days if last_login_dt else "n/a",
        }

        if not u.get("active"):
            inactive_disabled.append(row)
            continue
        if is_privileged:
            privileged.append(row)
        if last_login_dt is None or last_login_dt < cutoff:
            stale.append(row)

    fields = ["user_id", "user_name", "email", "active", "is_privileged",
              "roles", "last_login", "days_since_login"]
    write_csv(ctx.output_dir / "04_privileged_users_active.csv", privileged, fields)
    write_csv(ctx.output_dir / "04_stale_accounts.csv", stale, fields)
    write_csv(ctx.output_dir / "04_disabled_accounts.csv", inactive_disabled, fields)

    if stale:
        sev = "High" if any(s["is_privileged"] for s in stale) else "Medium"
        ctx.add_finding(Finding(
            check="4. Privileged Users & Stale Accounts",
            control="Account Lifecycle",
            severity=sev,
            title=f"{len(stale)} active accounts without login in {ctx.stale_days}+ days",
            detail=(
                "Inactive accounts represent attack surface. "
                "Cross-check with HRIS to identify former employees and disable."
            ),
            evidence="04_stale_accounts.csv",
        ))

    ctx.add_finding(Finding(
        check="4. Privileged Users & Stale Accounts",
        control="Privileged Access Review",
        severity="Informational",
        title=f"{len(privileged)} active privileged users in tenant",
        detail="Validate against customer RACI matrix. Recommended cadence: quarterly.",
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
    rows: list[dict] = []
    saml_users = 0
    active = 0

    for u in users:
        login_type = u.get("login_account_type") or ""
        is_active = bool(u.get("active"))
        rows.append({
            "user_name": u.get("user_name"),
            "email": u.get("email_address"),
            "ip_restricted": u.get("ip_restricted", False),
            "login_type": login_type,
            "active": is_active,
        })
        if is_active:
            active += 1
            if "saml" in login_type.lower():
                saml_users += 1

    write_csv(
        ctx.output_dir / "06_account_hardening.csv",
        rows,
        ["user_name", "email", "ip_restricted", "login_type", "active"],
    )

    if active and (saml_users / active) < SAML_COVERAGE_THRESHOLD:
        ctx.add_finding(Finding(
            check="6. Account Hardening",
            control="Authentication Strength",
            severity="Medium",
            title=f"Only {saml_users}/{active} active users via SAML SSO",
            detail=(
                "Users with local authentication outside SAML break centralized "
                "identity control and hinder deprovisioning."
            ),
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
    """Load the previous snapshot keyed by user_id. Returns None if absent."""
    if not snapshot_path.exists():
        return None
    try:
        data = json.loads(snapshot_path.read_text(encoding="utf-8"))
        return data.get("users", {})
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Could not read previous snapshot: %s", e)
        return None


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

    # 3. Email collisions in CURRENT state: same email on multiple active UIDs
    email_to_uids: dict[str, list[str]] = {}
    for uid, u in current_by_id.items():
        if not u.get("active"):
            continue
        email = (u.get("email_address") or "").lower()
        if email:
            email_to_uids.setdefault(email, []).append(uid)
    for email, uids in email_to_uids.items():
        if len(uids) > 1:
            out["email_collisions"].append({
                "email": email,
                "uid_count": len(uids),
                "uids": ",".join(sorted(uids)),
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
    "field_changes": ("Medium", "Identity Integrity",
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
        "email_collisions": ["email", "uid_count", "uids"],
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
            "Same email address is held by two or more active UIDs in the "
            "current state. Often indicates duplicate accounts, IdP "
            "misconfiguration, or attempted impersonation. Investigate "
            "ownership and consolidate."
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
    "4": "Privileged users & stale accounts",
    "5": "Traceability",
    "6": "Account hardening",
    "7": "Identity drift detection",
}

CHECK_DESCRIPTIONS: dict[str, str] = {
    "1": "Verifies every user has an immutable UID distinct from email or username.",
    "2": "Reviews role distribution, administrator ratio, API service accounts, and segregation of duties.",
    "3": "Inventories teams and flags applications without team assignment.",
    "4": "Lists active privileged users and detects stale or inactive accounts.",
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

    head_html = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in row) + "</tr>"
        for row in rows
    )
    more = ""
    if total > len(rows):
        more = (
            f'<div class="more-note">'
            f'Showing first {len(rows)} of {total} rows. '
            f'See <code>{html.escape(csv_path.name)}</code> for the full list.'
            f'</div>'
        )
    return f'<table class="evidence"><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>{more}'


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


def render_html(ctx: AuditContext, totals: dict[str, int]) -> Path:
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
    table.evidence {{
      width: 100%; border-collapse: collapse; font-size: 12px;
      background: white; border-radius: 6px; overflow: hidden;
      margin-top: 8px; border: 1px solid rgba(0,0,0,0.08);
    }}
    table.evidence th {{
      background: #f5f6fa; font-weight: 500; text-align: left;
      padding: 6px 10px; color: #586069; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.3px;
      border-bottom: 1px solid #e1e4e8;
    }}
    table.evidence td {{
      padding: 6px 10px; border-bottom: 1px solid #f0f2f5;
      vertical-align: top; font-size: 12px;
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

    <div class="footer-note">
      Full evidence is in CSV files under the same output directory.
      For SIEM ingestion, use <code>findings.json</code>.
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

def fetch_tenant(
    ctx: AuditContext,
    skip_apps: bool,
) -> tuple[list[dict], list[dict], list[dict]]:
    log.info("Fetching users (detailed)...")
    users = get_paginated(
        ctx, "/api/authn/v2/users", "users",
        params={"detailed": "true"},
    )
    log.info("  -> %d users", len(users))

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
    check4_privileged_and_stale(ctx, users)
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
    p.add_argument("--stale-days", type=int, default=STALE_DAYS_DEFAULT,
                   help="Days without login to flag an account as stale")
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
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    if args.rate_limit > 250:
        log.warning(
            "rate-limit=%d exceeds Veracode documented cap of 250 req/min. "
            "Throttling errors are likely.", args.rate_limit,
        )

    ctx = AuditContext(
        base_url=REGIONS[args.region],
        output_dir=Path(args.output),
        stale_days=args.stale_days,
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

    totals = {
        "Total users": len(users),
        "Active users": sum(1 for u in users if u.get("active")),
        "Teams": len(teams),
        "Applications": len(applications),
        "Findings": len(ctx.findings),
    }
    report_path = render_html(ctx, totals)

    log.info("HTML report: %s", report_path)
    log.info("Evidence directory: %s", ctx.output_dir.resolve())
    log.info("Total runtime: %.1fs", time.monotonic() - started)
    for k, v in totals.items():
        log.info("  %s: %s", k, v)

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

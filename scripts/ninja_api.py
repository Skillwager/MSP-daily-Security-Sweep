#!/usr/bin/env python3
"""
NinjaRMM (NinjaOne) API Wrapper — MSP Fleet Management

OAuth 2.0 client credentials flow with optional user-context refresh tokens
for write operations (ticketing). Caches responses to reduce API calls.
Logs all requests to an audit trail.

Configuration:
    Set the following environment variables (or use macOS Keychain):
        NINJA_CLIENT_ID       — NinjaRMM OAuth client ID
        NINJA_CLIENT_SECRET   — NinjaRMM OAuth client secret
    Optional:
        NINJA_REGION          — API region (default: us2). Options: us2, eu, oc, ca, us
        OPENCLAW_WORKSPACE    — Base workspace directory (default: ~/.openclaw/workspace)
        NINJA_CACHE_DIR       — Cache directory (default: $OPENCLAW_WORKSPACE/cache/ninja)
        NINJA_AUDIT_LOG       — Audit log path (default: $NINJA_CACHE_DIR/api-audit.jsonl)
        NINJA_OAUTH_TOKENS    — Path to stored OAuth user tokens for write operations

    macOS Keychain support:
        If KEYCHAIN_PATH is set, secrets are read from that keychain.
        KEYCHAIN_PASSWORD must also be set to unlock it.
        Fallback: login keychain, then environment variables.

Usage:
    python3 ninja_api.py --test              # Test OAuth token retrieval
    python3 ninja_api.py --orgs              # List organizations
    python3 ninja_api.py --devices           # List all devices
    python3 ninja_api.py --devices --org ID  # List devices for org
    python3 ninja_api.py --device ID         # Get single device
    python3 ninja_api.py --alerts            # Get all active alerts
    python3 ninja_api.py --alerts-only       # Alerts check (for cron, exits quietly if none)
    python3 ninja_api.py --health            # Fleet health summary
    python3 ninja_api.py --os-status         # OS versions and pending reboots
    python3 ninja_api.py --full-scan         # Full scan: software + patches
    python3 ninja_api.py --tickets           # List all tickets
    python3 ninja_api.py --tickets-open      # List open/new tickets only
    python3 ninja_api.py --ticket ID         # Get single ticket with history
    python3 ninja_api.py --antivirus         # Antivirus/Bitdefender health
    python3 ninja_api.py --backups           # Backup health summary
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# CONFIG
# =============================================================================

WORKSPACE = Path(os.environ.get("OPENCLAW_WORKSPACE", str(Path.home() / ".openclaw" / "workspace")))
CACHE_DIR = Path(os.environ.get("NINJA_CACHE_DIR", str(WORKSPACE / "cache" / "ninja")))
CACHE_FILE = CACHE_DIR / "ninja-cache.json"
TOKEN_CACHE = CACHE_DIR / "ninja-token.json"
AUDIT_LOG = Path(os.environ.get("NINJA_AUDIT_LOG", str(CACHE_DIR / "api-audit.jsonl")))
OAUTH_TOKEN_FILE = Path(os.environ.get("NINJA_OAUTH_TOKENS", str(WORKSPACE / ".secrets" / "NINJA_OAUTH_TOKENS")))
OAUTH_TOKEN_CACHE = CACHE_DIR / "ninja-oauth-token.json"

NINJA_REGION = os.environ.get("NINJA_REGION", "us2")
BASE_URL = f"https://{NINJA_REGION}.ninjarmm.com"
TOKEN_URL = f"{BASE_URL}/ws/oauth/token"
API_BASE = f"{BASE_URL}/api/v2"

KEYCHAIN_PATH = os.environ.get("KEYCHAIN_PATH", "")
KEYCHAIN_PASSWORD = os.environ.get("KEYCHAIN_PASSWORD", "")

CACHE_TTL = {
    "organizations": 3600,
    "devices": 300,
    "device_detail": 300,
    "alerts": 120,
    "os_patches": 1800,
}

FULL_SCAN_ORG_IDS = json.loads(os.environ.get("NINJA_FULL_SCAN_ORGS", "[]"))


# =============================================================================
# SECRET RETRIEVAL
# =============================================================================


def read_secret(name: str) -> str:
    env_name = name.upper().replace("-", "_")
    val = os.environ.get(env_name)
    if val:
        return val

    if KEYCHAIN_PATH and KEYCHAIN_PASSWORD:
        try:
            import subprocess as _sp
            _sp.run(["security", "unlock-keychain", "-p", KEYCHAIN_PASSWORD, KEYCHAIN_PATH],
                    capture_output=True, timeout=5)
            r = _sp.run(["security", "find-generic-password", "-a", "openclaw",
                         "-s", env_name, "-w", KEYCHAIN_PATH],
                        capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass

    try:
        import subprocess as _sp
        r = _sp.run(["security", "find-generic-password", "-s", env_name, "-w"],
                    capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass

    print(f"[ERROR] Secret not found: {env_name} — set it as an environment variable or in your keychain",
          file=sys.stderr)
    sys.exit(1)


# =============================================================================
# AUDIT LOG
# =============================================================================


def audit_log(method: str, url: str, status: int, cached: bool = False):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "url": url,
        "status": status,
        "cached": cached,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# =============================================================================
# CACHE
# =============================================================================


def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_cache(cache: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2))


def get_cached(key: str, ttl: int) -> dict | None:
    cache = load_cache()
    entry = cache.get(key)
    if entry and (time.time() - entry.get("ts", 0)) < ttl:
        return entry.get("data")
    return None


def set_cached(key: str, data):
    cache = load_cache()
    cache[key] = {"ts": time.time(), "data": data}
    save_cache(cache)


# =============================================================================
# OAUTH — CLIENT CREDENTIALS (READ-ONLY)
# =============================================================================


def get_token() -> str:
    if TOKEN_CACHE.exists():
        try:
            token_data = json.loads(TOKEN_CACHE.read_text())
            if time.time() < token_data.get("expires_at", 0) - 60:
                return token_data["access_token"]
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    client_id = read_secret("ninja-client-id")
    client_secret = read_secret("ninja-client-secret")

    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "monitoring management",
    }).encode()

    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            audit_log("POST", TOKEN_URL, resp.status)
    except urllib.error.HTTPError as e:
        audit_log("POST", TOKEN_URL, e.code)
        print(f"[ERROR] Token request failed: {e.code} {e.reason}", file=sys.stderr)
        body = e.read().decode() if e.fp else ""
        if body:
            print(f"[ERROR] Response: {body[:500]}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        audit_log("POST", TOKEN_URL, 0)
        print(f"[ERROR] Token request failed: {e.reason}", file=sys.stderr)
        sys.exit(1)

    token_data = {
        "access_token": result["access_token"],
        "expires_at": time.time() + result.get("expires_in", 3600),
    }
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_CACHE.write_text(json.dumps(token_data))
    os.chmod(TOKEN_CACHE, 0o600)

    return result["access_token"]


# =============================================================================
# OAUTH — USER CONTEXT (WRITE OPERATIONS)
# =============================================================================


def get_user_token() -> str:
    if OAUTH_TOKEN_CACHE.exists():
        try:
            cached = json.loads(OAUTH_TOKEN_CACHE.read_text())
            if time.time() < cached.get("expires_at", 0) - 60:
                return cached["access_token"]
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    if not OAUTH_TOKEN_FILE.exists():
        print("[WARN] No OAuth user tokens found. Falling back to client_credentials (read-only)", file=sys.stderr)
        return get_token()

    try:
        stored = json.loads(OAUTH_TOKEN_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        print("[WARN] OAuth token file corrupted. Falling back to client_credentials.", file=sys.stderr)
        return get_token()

    refresh_token = stored.get("refresh_token")
    if not refresh_token:
        print("[WARN] No refresh token. Falling back to client_credentials.", file=sys.stderr)
        return get_token()

    client_id = read_secret("ninja-client-id")
    client_secret = read_secret("ninja-client-secret")

    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()

    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            audit_log("POST", TOKEN_URL + " (refresh)", resp.status)
    except urllib.error.HTTPError as e:
        audit_log("POST", TOKEN_URL + " (refresh)", e.code)
        body = e.read().decode()[:300] if e.fp else ""
        print(f"[ERROR] Token refresh failed: {e.code} -- {body}", file=sys.stderr)
        return get_token()

    if result.get("refresh_token"):
        stored["refresh_token"] = result["refresh_token"]
    stored["access_token"] = result["access_token"]
    stored["expires_in"] = result.get("expires_in", 3600)
    stored["scope"] = result.get("scope", stored.get("scope", ""))
    OAUTH_TOKEN_FILE.write_text(json.dumps(stored, indent=2))
    os.chmod(OAUTH_TOKEN_FILE, 0o600)

    cache_data = {
        "access_token": result["access_token"],
        "expires_at": time.time() + result.get("expires_in", 3600),
    }
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    OAUTH_TOKEN_CACHE.write_text(json.dumps(cache_data))
    os.chmod(OAUTH_TOKEN_CACHE, 0o600)

    return result["access_token"]


# =============================================================================
# API METHODS — WRITE (TICKETING)
# =============================================================================


def api_post_comment(ticket_id: int, body_text: str, public: bool = False) -> dict:
    token = get_user_token()
    url = f"{API_BASE}/ticketing/ticket/{ticket_id}/comment"

    boundary = "----NinjaAPIBoundary"
    parts = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="body"',
        "",
        body_text,
        f"--{boundary}",
        'Content-Disposition: form-data; name="type"',
        "",
        "COMMENT",
        f"--{boundary}",
        'Content-Disposition: form-data; name="publicEntry"',
        "",
        str(public).lower(),
        f"--{boundary}--",
    ]
    data = "\r\n".join(parts).encode()

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            audit_log("POST", url, resp.status)
            return json.loads(resp.read().decode()) if resp.read() else {"status": "ok"}
    except urllib.error.HTTPError as e:
        audit_log("POST", url, e.code)
        body = e.read().decode()[:300] if e.fp else ""
        print(f"[ERROR] Comment failed: {e.code} -- {body}", file=sys.stderr)
        return {"error": e.code, "message": body}


def api_update_ticket(ticket_id: int, updates: dict) -> dict:
    token = get_user_token()
    url = f"{API_BASE}/ticketing/ticket/{ticket_id}"
    data = json.dumps(updates).encode()

    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            audit_log("PUT", url, resp.status)
            result = resp.read().decode()
            return json.loads(result) if result else {"status": "ok"}
    except urllib.error.HTTPError as e:
        audit_log("PUT", url, e.code)
        body = e.read().decode()[:300] if e.fp else ""
        print(f"[ERROR] Ticket update failed: {e.code} -- {body}", file=sys.stderr)
        return {"error": e.code, "message": body}


# =============================================================================
# API METHODS — READ
# =============================================================================


def api_get(endpoint: str, cache_key: str = None, cache_ttl: int = 300) -> dict | list:
    if cache_key:
        cached = get_cached(cache_key, cache_ttl)
        if cached is not None:
            audit_log("GET", f"{API_BASE}{endpoint}", 200, cached=True)
            return cached

    token = get_token()
    url = f"{API_BASE}{endpoint}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            audit_log("GET", url, resp.status)
    except urllib.error.HTTPError as e:
        audit_log("GET", url, e.code)
        if e.code == 429:
            print("[WARN] Rate limited by NinjaRMM. Using cached data if available.", file=sys.stderr)
            if cache_key:
                cached = get_cached(cache_key, cache_ttl * 10)
                if cached is not None:
                    return cached
            print("[ERROR] No cached data available.", file=sys.stderr)
            sys.exit(1)
        print(f"[ERROR] API request failed: {e.code} {e.reason} -- {url}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        audit_log("GET", url, 0)
        print(f"[ERROR] API request failed: {e.reason} -- {url}", file=sys.stderr)
        sys.exit(1)

    if cache_key:
        set_cached(cache_key, result)

    return result


# =============================================================================
# DATA RETRIEVAL FUNCTIONS
# =============================================================================


def list_organizations() -> list:
    return api_get("/organizations", cache_key="organizations", cache_ttl=CACHE_TTL["organizations"])


def list_devices(org_id: int = None) -> list:
    endpoint = "/devices-detailed"
    if org_id:
        endpoint += f"?df=org={org_id}"
    key = f"devices_org_{org_id}" if org_id else "devices_all"
    return api_get(endpoint, cache_key=key, cache_ttl=CACHE_TTL["devices"])


def get_device(device_id: int) -> dict:
    return api_get(f"/device/{device_id}", cache_key=f"device_{device_id}", cache_ttl=CACHE_TTL["device_detail"])


def get_device_name_map() -> dict:
    devices = list_devices()
    if not isinstance(devices, list):
        devices = devices.get("results", devices.get("devices", []))
    return {
        d.get("id"): d.get("systemName", d.get("dnsName", d.get("name", f"Device {d.get('id')}")))
        for d in devices if d.get("id") is not None
    }


def get_alerts(device_id: int = None, severity: str = None, resolve_names: bool = True) -> list:
    endpoint = "/alerts"
    params = []
    if device_id:
        params.append(f"df=device_id={device_id}")
    if severity:
        params.append(f"severity={severity}")
    if params:
        endpoint += "?" + "&".join(params)
    key = f"alerts_device_{device_id}" if device_id else "alerts_all"
    alerts = api_get(endpoint, cache_key=key, cache_ttl=CACHE_TTL["alerts"])

    if resolve_names:
        if not isinstance(alerts, list):
            alert_list = alerts.get("results", alerts.get("alerts", []))
        else:
            alert_list = alerts

        needs_resolve = any(not a.get("deviceName") for a in alert_list)
        if needs_resolve and alert_list:
            name_map = get_device_name_map()
            for a in alert_list:
                if not a.get("deviceName"):
                    did = a.get("deviceId", a.get("id"))
                    a["deviceName"] = name_map.get(did, f"Device {did}")

    return alerts


def get_device_health() -> dict:
    devices = list_devices()
    if not isinstance(devices, list):
        devices = devices.get("results", devices.get("devices", []))

    total = len(devices)
    online = sum(1 for d in devices if not d.get("offline", True))
    offline = total - online

    os_counts = {}
    for d in devices:
        os_info = d.get("os", {})
        if isinstance(os_info, dict):
            os_name = os_info.get("name", "Unknown")
        else:
            os_name = str(os_info) if os_info else "Unknown"
        os_counts[os_name] = os_counts.get(os_name, 0) + 1

    alerts = get_alerts(resolve_names=True)
    if not isinstance(alerts, list):
        alerts = alerts.get("results", alerts.get("alerts", []))

    critical_alerts = [a for a in alerts if a.get("severity", "").upper() in ("CRITICAL", "MAJOR")]
    warning_alerts = [a for a in alerts if a.get("severity", "").upper() in ("WARNING", "MODERATE", "MINOR")]

    name_map = {d.get("id"): d.get("systemName", d.get("dnsName", "Unknown")) for d in devices}

    return {
        "total_devices": total,
        "online": online,
        "offline": offline,
        "os_breakdown": os_counts,
        "total_alerts": len(alerts),
        "critical_alerts": len(critical_alerts),
        "warning_alerts": len(warning_alerts),
        "alerts_detail": [
            {
                "id": a.get("id"),
                "deviceId": a.get("deviceId", a.get("id")),
                "device": a.get("deviceName", name_map.get(a.get("deviceId", a.get("id")), f"Device {a.get('deviceId', a.get('id'))}")),
                "severity": a.get("severity"),
                "message": a.get("message", a.get("subject", "")),
            }
            for a in critical_alerts[:20]
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_os_status() -> dict:
    devices = list_devices()
    if not isinstance(devices, list):
        devices = devices.get("results", devices.get("devices", []))

    needs_reboot = []
    os_versions = {}

    for d in devices:
        os_info = d.get("os", {})
        if isinstance(os_info, dict):
            os_name = os_info.get("name", "Unknown")
            os_ver = os_info.get("buildNumber", "")
            reboot_needed = os_info.get("needsReboot", False)
        else:
            os_name = str(os_info) if os_info else "Unknown"
            os_ver = ""
            reboot_needed = False

        key = f"{os_name} {os_ver}".strip()
        os_versions[key] = os_versions.get(key, 0) + 1

        if reboot_needed:
            needs_reboot.append({
                "name": d.get("systemName", d.get("dnsName", "Unknown")),
                "os": key,
                "org": d.get("organizationName", "Unknown"),
            })

    return {
        "os_versions": os_versions,
        "needs_reboot": needs_reboot,
        "reboot_count": len(needs_reboot),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# ANTIVIRUS / BITDEFENDER
# =============================================================================


def get_antivirus_status(page_size: int = 500) -> list:
    return api_get(f"/queries/antivirus-status?pageSize={page_size}",
                   cache_key="av_status", cache_ttl=600)


def get_antivirus_threats(page_size: int = 200) -> list:
    return api_get(f"/queries/antivirus-threats?pageSize={page_size}",
                   cache_key="av_threats", cache_ttl=600)


def get_antivirus_health() -> dict:
    av_data = get_antivirus_status()
    av_results = av_data.get("results", av_data) if isinstance(av_data, dict) else av_data
    if not isinstance(av_results, list):
        av_results = []

    threat_data = get_antivirus_threats()
    threats = threat_data.get("results", threat_data) if isinstance(threat_data, dict) else threat_data
    if not isinstance(threats, list):
        threats = []

    name_map = get_device_name_map()

    from collections import defaultdict
    by_device = defaultdict(list)
    for entry in av_results:
        did = entry.get("deviceId")
        hostname = name_map.get(did, f"Device-{did}")
        entry["_hostname"] = hostname
        by_device[hostname].append(entry)

    devices_summary = []
    issues = []
    bd_on = 0
    bd_off = 0
    bd_missing = 0

    for hostname in sorted(by_device.keys()):
        entries = by_device[hostname]
        bd = [e for e in entries if "Bitdefender" in e.get("productName", "")]
        wd = [e for e in entries if "Defender" in e.get("productName", "")]

        bd_state = bd[0]["productState"] if bd else "NOT_INSTALLED"
        bd_defs = bd[0]["definitionStatus"] if bd else "-"
        wd_state = wd[0]["productState"] if wd else "NOT_FOUND"

        if bd_state == "ON":
            bd_on += 1
        elif bd:
            bd_off += 1
        else:
            bd_missing += 1

        entry = {
            "device": hostname,
            "bitdefender_state": bd_state,
            "bitdefender_defs": bd_defs,
            "defender_state": wd_state,
        }
        devices_summary.append(entry)

        if bd and bd_state != "ON":
            issues.append(f"{hostname}: Bitdefender {bd_state}")
        if bd and bd_defs not in ("Up-to-Date", "-"):
            issues.append(f"{hostname}: Bitdefender definitions {bd_defs}")

    active_threats = []
    for t in threats:
        hostname = name_map.get(t.get("deviceId"), f"Device-{t.get('deviceId')}")
        active_threats.append({
            "device": hostname,
            "name": t.get("name", "Unknown"),
            "status": t.get("status", "Unknown"),
            "level": t.get("level", "Unknown"),
            "product": t.get("productCode", "Unknown"),
        })
        if t.get("status") == "Active":
            issues.append(f"{hostname}: Active threat -- {t.get('name', 'Unknown')} ({t.get('level', '?')})")

    return {
        "total_devices": len(by_device),
        "bitdefender_on": bd_on,
        "bitdefender_off": bd_off,
        "bitdefender_not_installed": bd_missing,
        "active_threats": active_threats,
        "threat_count": len([t for t in active_threats if t["status"] == "Active"]),
        "devices": devices_summary,
        "issues": issues,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# BACKUP
# =============================================================================


def get_backup_jobs(page_size: int = 200) -> list:
    return api_get(f"/backup/jobs?pageSize={page_size}",
                   cache_key="backup_jobs", cache_ttl=600)


def get_backup_health() -> dict:
    data = get_backup_jobs()
    jobs = data.get("results", data) if isinstance(data, dict) else data
    if not isinstance(jobs, list):
        jobs = []

    name_map = get_device_name_map()

    from collections import defaultdict

    by_device_dest = defaultdict(list)
    for j in jobs:
        hostname = name_map.get(j.get("deviceId"), f"Device-{j.get('deviceId')}")
        dest = j.get("destination", "UNKNOWN")
        by_device_dest[(hostname, dest)].append(j)

    devices_summary = []
    total_succeeded = 0
    total_failed = 0
    issues = []

    for (hostname, dest), djobs in sorted(by_device_dest.items()):
        latest = max(djobs, key=lambda x: x.get("jobStartTime", 0))
        succeeded = sum(1 for j in djobs if j["jobStatus"] == "COMPLETED")
        failed = sum(1 for j in djobs if j["jobStatus"] != "COMPLETED")
        total_succeeded += succeeded
        total_failed += failed

        hours_since = (time.time() - latest.get("jobStartTime", 0)) / 3600
        latest_actual = latest.get("totalActualStorageBytes", 0)
        latest_stored = latest.get("totalStoredBytes", 0)
        duration = (latest.get("jobEndTime", 0) - latest.get("jobStartTime", 0)) if latest.get("jobEndTime") else 0

        entry = {
            "device": hostname,
            "destination": dest,
            "total_jobs": len(djobs),
            "succeeded": succeeded,
            "failed": failed,
            "latest_status": latest["jobStatus"],
            "latest_time": datetime.fromtimestamp(latest["jobStartTime"]).strftime("%Y-%m-%d %H:%M"),
            "hours_since_last": round(hours_since, 1),
            "latest_actual_gb": round(latest_actual / 1e9, 1),
            "latest_stored_gb": round(latest_stored / 1e9, 1),
            "duration_min": round(duration / 60, 1),
        }
        devices_summary.append(entry)

        if failed > 0:
            for fj in djobs:
                if fj["jobStatus"] != "COMPLETED":
                    ft = datetime.fromtimestamp(fj["jobStartTime"]).strftime("%Y-%m-%d")
                    issues.append(f"{hostname} {dest} backup failed on {ft}")
        if hours_since > 36:
            issues.append(f"{hostname} {dest}: last backup {hours_since:.0f}h ago")
        if latest["jobStatus"] != "COMPLETED":
            issues.append(f"{hostname} {dest}: latest backup {latest['jobStatus']}")

    all_devices = set(hostname for hostname, _ in by_device_dest.keys())

    return {
        "protected_devices": len(all_devices),
        "total_jobs": len(jobs),
        "succeeded": total_succeeded,
        "failed": total_failed,
        "success_rate": round(total_succeeded / max(len(jobs), 1) * 100, 1),
        "devices": devices_summary,
        "issues": issues,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# TICKETING
# =============================================================================


def list_ticket_boards() -> list:
    return api_get("/ticketing/trigger/boards", cache_key="ticket_boards", cache_ttl=3600)


def get_ticket_statuses() -> list:
    return api_get("/ticketing/statuses", cache_key="ticket_statuses", cache_ttl=3600)


def run_ticket_board(board_id: int = 2) -> list:
    token = get_token()
    url = f"{API_BASE}/ticketing/trigger/board/{board_id}/run"
    body = json.dumps({}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            audit_log("POST", url, resp.status)
    except urllib.error.HTTPError as e:
        audit_log("POST", url, e.code)
        print(f"[ERROR] Board query failed: {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)

    return result.get("data", [])


def get_ticket(ticket_id: int) -> dict:
    return api_get(f"/ticketing/ticket/{ticket_id}", cache_key=f"ticket_{ticket_id}", cache_ttl=120)


def get_ticket_log(ticket_id: int) -> list:
    return api_get(f"/ticketing/ticket/{ticket_id}/log-entry", cache_key=f"ticket_log_{ticket_id}", cache_ttl=120)


def get_open_tickets() -> list:
    all_tickets = run_ticket_board(2)
    open_tickets = []
    for t in all_tickets:
        status = t.get("status", {})
        status_id = status.get("statusId", 0) if isinstance(status, dict) else 0
        if status_id not in (5000, 6000) and not t.get("deleted", False):
            open_tickets.append(t)

    if open_tickets:
        name_map = get_device_name_map()
        for t in open_tickets:
            node_id = t.get("nodeId")
            if node_id and not t.get("deviceName"):
                t["deviceName"] = name_map.get(node_id, f"Device {node_id}")

    return open_tickets


def get_all_tickets_enriched() -> list:
    all_tickets = run_ticket_board(2)
    name_map = get_device_name_map()
    for t in all_tickets:
        node_id = t.get("nodeId")
        if node_id and not t.get("deviceName"):
            t["deviceName"] = name_map.get(node_id, f"Device {node_id}")
    return all_tickets


# =============================================================================
# SOFTWARE & PATCHES
# =============================================================================


def get_device_software(device_id: int) -> list:
    return api_get(f"/device/{device_id}/software",
                   cache_key=f"software_{device_id}", cache_ttl=1800)


def get_device_os_patches(device_id: int) -> list:
    return api_get(f"/device/{device_id}/os-patches",
                   cache_key=f"patches_{device_id}", cache_ttl=1800)


def full_scan(org_ids: list = None) -> dict:
    if org_ids is None:
        org_ids = FULL_SCAN_ORG_IDS
    if not org_ids:
        print("[ERROR] No org IDs configured. Set NINJA_FULL_SCAN_ORGS='[2,3]' or pass --org.", file=sys.stderr)
        sys.exit(1)

    org_names = {}
    try:
        orgs = list_organizations()
        if not isinstance(orgs, list):
            orgs = orgs.get("results", orgs.get("organizations", []))
        for org in orgs:
            if isinstance(org, dict):
                org_names[org.get("id", 0)] = org.get("name", "Unknown")
    except Exception:
        pass

    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "organizations": {},
        "summary": {
            "total_devices": 0, "online": 0, "offline": 0,
            "total_software": 0, "total_patches_pending": 0, "errors": [],
        },
    }

    for org_id in org_ids:
        devices = list_devices(org_id=org_id)
        if not isinstance(devices, list):
            devices = devices.get("results", devices.get("devices", []))

        org_name = org_names.get(org_id, f"Org {org_id}")
        org_data = {"devices": [], "total": len(devices), "online": 0, "offline": 0}

        for dev in devices:
            dev_id = dev.get("id")
            dev_name = dev.get("systemName", dev.get("dnsName", "Unknown"))
            is_offline = dev.get("offline", True)

            dev_entry = {
                "id": dev_id, "name": dev_name, "offline": is_offline,
                "os": dev.get("os", {}),
                "software_count": 0, "patches_pending": 0,
                "software": [], "patches": [],
            }

            if is_offline:
                org_data["offline"] += 1
            else:
                org_data["online"] += 1

            try:
                time.sleep(0.1)
                sw = get_device_software(dev_id)
                if isinstance(sw, list):
                    dev_entry["software_count"] = len(sw)
                    dev_entry["software"] = [{"name": s.get("name", ""), "version": s.get("version", "")} for s in sw]
                    results["summary"]["total_software"] += len(sw)
            except Exception as e:
                results["summary"]["errors"].append(f"{dev_name}: software: {e}")

            try:
                time.sleep(0.1)
                patches = get_device_os_patches(dev_id)
                if isinstance(patches, list):
                    dev_entry["patches_pending"] = len(patches)
                    dev_entry["patches"] = [{"name": p.get("name", p.get("kbNumber", "")), "severity": p.get("severity", ""), "status": p.get("status", "")} for p in patches]
                    results["summary"]["total_patches_pending"] += len(patches)
            except Exception as e:
                results["summary"]["errors"].append(f"{dev_name}: patches: {e}")

            org_data["devices"].append(dev_entry)

        results["summary"]["total_devices"] += len(devices)
        results["summary"]["online"] += org_data["online"]
        results["summary"]["offline"] += org_data["offline"]
        results["organizations"][org_name] = org_data

    return results


# =============================================================================
# OUTPUT FORMATTING
# =============================================================================


def format_health_report(health: dict) -> str:
    lines = ["MSP Fleet Health -- NinjaRMM", ""]
    lines.append(f"Devices: {health['online']}/{health['total_devices']} online ({health['offline']} offline)")

    if health["os_breakdown"]:
        lines.append("")
        lines.append("OS Breakdown:")
        for os_name, count in sorted(health["os_breakdown"].items(), key=lambda x: -x[1]):
            lines.append(f"- {os_name}: {count}")

    lines.append("")
    if health["critical_alerts"] > 0:
        lines.append(f"[CRIT] {health['critical_alerts']} critical alert(s)")
        for a in health["alerts_detail"][:5]:
            lines.append(f"  - {a['device']}: {a['message'][:100]}")
    if health["warning_alerts"] > 0:
        lines.append(f"[WARN] {health['warning_alerts']} warning(s)")
    if health["total_alerts"] == 0:
        lines.append("[OK] No active alerts")

    return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description="NinjaRMM API Wrapper")
    parser.add_argument("--test", action="store_true", help="Test OAuth token retrieval")
    parser.add_argument("--orgs", action="store_true", help="List organizations")
    parser.add_argument("--devices", action="store_true", help="List devices")
    parser.add_argument("--org", type=int, help="Filter devices by org ID")
    parser.add_argument("--device", type=int, help="Get single device by ID")
    parser.add_argument("--alerts", action="store_true", help="Get active alerts")
    parser.add_argument("--alerts-only", action="store_true", help="Check alerts (quiet if none)")
    parser.add_argument("--health", action="store_true", help="Fleet health summary")
    parser.add_argument("--tickets", action="store_true", help="List all tickets")
    parser.add_argument("--tickets-open", action="store_true", help="List open/new tickets only")
    parser.add_argument("--ticket", type=int, help="Get single ticket by ID with full history")
    parser.add_argument("--ticket-boards", action="store_true", help="List ticket boards")
    parser.add_argument("--os-status", action="store_true", help="OS versions and reboot status")
    parser.add_argument("--backups", action="store_true", help="Backup health summary")
    parser.add_argument("--antivirus", action="store_true", help="Antivirus/Bitdefender health summary")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--full-scan", action="store_true", help="Full scan: software + patches")
    args = parser.parse_args()

    if args.test:
        print("Testing NinjaRMM OAuth token retrieval...")
        token = get_token()
        print(f"[OK] Token retrieved successfully (length: {len(token)})")
        return

    if args.orgs:
        orgs = list_organizations()
        if args.json:
            print(json.dumps(orgs, indent=2))
        else:
            if not isinstance(orgs, list):
                orgs = orgs.get("results", orgs.get("organizations", []))
            print(f"Organizations ({len(orgs)}):")
            for org in orgs:
                print(f"  - [{org.get('id')}] {org.get('name', 'Unknown')}")
        return

    if args.devices:
        devices = list_devices(org_id=args.org)
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            if not isinstance(devices, list):
                devices = devices.get("results", devices.get("devices", []))
            print(f"Devices ({len(devices)}):")
            for d in devices:
                status = "ONLINE" if d.get("online", d.get("status", {}).get("online", False)) else "OFFLINE"
                name = d.get("systemName", d.get("name", "Unknown"))
                org = d.get("organizationName", d.get("organization", {}).get("name", ""))
                print(f"  [{status}] {name} ({org})")
        return

    if args.device:
        device = get_device(args.device)
        print(json.dumps(device, indent=2))
        return

    if args.alerts or args.alerts_only:
        alerts = get_alerts()
        if not isinstance(alerts, list):
            alerts = alerts.get("results", alerts.get("alerts", []))

        if args.alerts_only:
            critical = [a for a in alerts if a.get("severity", "").upper() in ("CRITICAL", "MAJOR")]
            if not critical:
                return
            print(f"[CRIT] {len(critical)} critical NinjaRMM alert(s):")
            for a in critical[:10]:
                device_name = a.get("deviceName", a.get("device", {}).get("name", "Unknown"))
                msg = a.get("message", a.get("subject", ""))
                print(f"  - {device_name}: {msg[:150]}")
            return

        if args.json:
            print(json.dumps(alerts, indent=2))
        else:
            print(f"Active Alerts ({len(alerts)}):")
            for a in alerts:
                severity = a.get("severity", "Unknown").upper()
                device_name = a.get("deviceName", a.get("device", {}).get("name", "Unknown"))
                msg = a.get("message", a.get("subject", ""))
                print(f"  [{severity}] {device_name}: {msg[:100]}")
        return

    if args.health:
        health = get_device_health()
        if args.json:
            print(json.dumps(health, indent=2))
        else:
            print(format_health_report(health))
        return

    if args.os_status:
        os_data = get_os_status()
        if args.json:
            print(json.dumps(os_data, indent=2))
        else:
            print("OS Versions:")
            for ver, count in sorted(os_data["os_versions"].items(), key=lambda x: -x[1]):
                print(f"  - {ver}: {count}")
            if os_data["needs_reboot"]:
                print(f"\nDevices Needing Reboot ({os_data['reboot_count']}):")
                for d in os_data["needs_reboot"]:
                    print(f"  - {d['name']} ({d['org']}) -- {d['os']}")
            else:
                print("\nNo devices need rebooting.")
        return

    if args.antivirus:
        health = get_antivirus_health()
        if args.json:
            print(json.dumps(health, indent=2))
        else:
            print(f"Antivirus Health -- {health['total_devices']} devices scanned")
            print(f"  Bitdefender: {health['bitdefender_on']} ON | {health['bitdefender_off']} OFF | {health['bitdefender_not_installed']} not installed")
            print(f"  Active threats: {health['threat_count']}")
            if health["active_threats"]:
                print()
                for t in health["active_threats"]:
                    marker = "[!]" if t["status"] == "Active" else "[?]"
                    print(f"  {marker} {t['level']}: {t['name']}")
                    print(f"     Device: {t['device']} | Status: {t['status']} | Engine: {t['product']}")
            if health["issues"]:
                print()
                print("  Issues:")
                for issue in health["issues"]:
                    print(f"    [!] {issue}")
        return

    if args.backups:
        health = get_backup_health()
        if args.json:
            print(json.dumps(health, indent=2))
        else:
            print(f"Backup Health -- {health['protected_devices']} devices protected")
            print(f"  Total jobs: {health['total_jobs']} ({health['succeeded']} ok / {health['failed']} failed) -- {health['success_rate']}% success")
            print()
            for d in health["devices"]:
                dest_label = "CLOUD" if d["destination"] == "CLOUD" else d["destination"]
                status = "OK" if d["latest_status"] == "COMPLETED" else "FAIL"
                print(f"  [{dest_label}] {d['device']}")
                print(f"     Last: {d['latest_time']} [{status}] | {d['latest_actual_gb']}GB -> {d['latest_stored_gb']}GB | {d['duration_min']}min")
                if d["failed"] > 0:
                    print(f"     [!] {d['failed']} failed out of {d['total_jobs']} jobs")
            if health["issues"]:
                print()
                print("  Issues:")
                for issue in health["issues"]:
                    print(f"    [!] {issue}")
        return

    if args.ticket_boards:
        boards = list_ticket_boards()
        if args.json:
            print(json.dumps(boards, indent=2))
        else:
            print(f"Ticket Boards ({len(boards)}):")
            for b in boards:
                print(f"  Board {b['id']}: {b['name']} ({b.get('ticketCount', '?')} tickets)")
        return

    if args.tickets or args.tickets_open:
        if args.tickets_open:
            tickets = get_open_tickets()
            label = "Open/New"
        else:
            tickets = get_all_tickets_enriched()
            label = "All"

        if args.json:
            print(json.dumps(tickets, indent=2))
        else:
            print(f"{label} Tickets ({len(tickets)}):")
            for t in tickets:
                tid = t.get("id", "?")
                subject = t.get("subject", "No subject")[:80]
                status = t.get("status", {})
                status_name = status.get("displayName", "?") if isinstance(status, dict) else str(status)
                priority = t.get("priority", "?")
                org = t.get("organization", {})
                org_name = org.get("name", "Unknown") if isinstance(org, dict) else str(org) if org else "Unknown"
                device = t.get("deviceName", "--")
                source = t.get("source", "?")
                print(f"  #{tid} [{status_name}] [{priority}] {org_name}")
                print(f"    Subject: {subject}")
                if device != "--":
                    print(f"    Device: {device}")
                print(f"    Source: {source}")
                print()
        return

    if args.ticket:
        ticket = get_ticket(args.ticket)
        log = get_ticket_log(args.ticket)

        if args.json:
            print(json.dumps({"ticket": ticket, "log": log}, indent=2))
        else:
            name_map = get_device_name_map()
            node_id = ticket.get("nodeId")
            device_name = name_map.get(node_id, f"Device {node_id}") if node_id else "--"

            print(f"Ticket #{ticket.get('id')}: {ticket.get('subject')}")
            print(f"  Status: {ticket.get('status', {}).get('displayName', '?')}")
            print(f"  Priority: {ticket.get('priority', '?')} | Severity: {ticket.get('severity', '?')}")
            print(f"  Type: {ticket.get('type', '?')} | Source: {ticket.get('source', '?')}")
            print(f"  Device: {device_name} | Client: Org {ticket.get('clientId', '?')}")
            print(f"  Created: {datetime.fromtimestamp(ticket.get('createTime', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
            if ticket.get("tags"):
                print(f"  Tags: {', '.join(ticket['tags'])}")
            print()

            if isinstance(log, list) and log:
                print(f"  History ({len(log)} entries):")
                for entry in log:
                    etype = entry.get("type", "?")
                    ebody = entry.get("body", "")
                    etime = datetime.fromtimestamp(entry.get("createTime", 0), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
                    if ebody and len(ebody) > 200:
                        ebody = ebody[:200] + "..."
                    change = entry.get("changeDiff", {})
                    if change:
                        changes = ", ".join(f"{k}: {v.get('old','?')}->{v.get('new','?')}" for k, v in change.items())
                        print(f"    [{etime}] {etype}: {changes}")
                    elif ebody:
                        print(f"    [{etime}] {etype}: {ebody}")
                    else:
                        print(f"    [{etime}] {etype}")
        return

    if args.full_scan:
        print("Running full scan...", file=sys.stderr)
        scan = full_scan()
        scan_file = CACHE_DIR / "ninja-full-scan.json"
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        scan_file.write_text(json.dumps(scan, indent=2))
        if args.json:
            print(json.dumps(scan, indent=2))
        else:
            s = scan["summary"]
            print(f"Full Scan Complete")
            print(f"  Devices: {s['online']}/{s['total_devices']} online")
            print(f"  Software entries: {s['total_software']}")
            print(f"  Patches pending: {s['total_patches_pending']}")
            if s["errors"]:
                print(f"  Errors: {len(s['errors'])}")
                for e in s["errors"][:5]:
                    print(f"    - {e}")
            for org_name, org in scan["organizations"].items():
                print()
                print(f"  {org_name}: {org['online']}/{org['total']} online")
                patches_total = sum(d["patches_pending"] for d in org["devices"])
                if patches_total:
                    print(f"    Patches pending: {patches_total}")
            print()
            print(f"Saved to {scan_file}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

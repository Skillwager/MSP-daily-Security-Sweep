#!/usr/bin/env python3
"""
Bitdefender GravityZone Cloud API Wrapper — MSP Endpoint Security

JSON-RPC 2.0 over HTTPS. Caches responses to reduce API calls.
Logs all requests to audit trail.

Configuration:
    Set the following environment variables (or use macOS Keychain):
        GRAVITYZONE_API_KEY   — GravityZone API key (used as HTTP Basic username)
    Optional:
        OPENCLAW_WORKSPACE    — Base workspace directory (default: ~/.openclaw/workspace)
        GZ_CACHE_DIR          — Cache directory (default: $OPENCLAW_WORKSPACE/cache/gravityzone)
        GZ_AUDIT_LOG          — Audit log path (default: $GZ_CACHE_DIR/api-audit.jsonl)
        GZ_COMPANY_IDS        — JSON array of company objects, e.g.:
                                 '[{"id":"abc123","name":"Acme Corp"}]'

Usage:
    python3 gravityzone_api.py --test              # Test API connectivity
    python3 gravityzone_api.py --endpoints          # List all managed endpoints
    python3 gravityzone_api.py --endpoint ID        # Get endpoint details
    python3 gravityzone_api.py --health             # Fleet health summary
    python3 gravityzone_api.py --quarantine         # List quarantined items
    python3 gravityzone_api.py --outdated           # Endpoints with outdated signatures/agents
    python3 gravityzone_api.py --infected           # Endpoints with active malware
    python3 gravityzone_api.py --scan ID [--type N] # Launch scan (1=quick, 2=full)
    python3 gravityzone_api.py --isolate ID         # Isolate compromised endpoint
    python3 gravityzone_api.py --restore ID         # Restore endpoint from isolation
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# CONFIG
# =============================================================================

WORKSPACE = Path(os.environ.get("OPENCLAW_WORKSPACE", str(Path.home() / ".openclaw" / "workspace")))
CACHE_DIR = Path(os.environ.get("GZ_CACHE_DIR", str(WORKSPACE / "cache" / "gravityzone")))
CACHE_FILE = CACHE_DIR / "gravityzone-cache.json"
AUDIT_LOG = Path(os.environ.get("GZ_AUDIT_LOG", str(CACHE_DIR / "api-audit.jsonl")))

BASE_URL = "https://cloud.gravityzone.bitdefender.com/api"

KEYCHAIN_PATH = os.environ.get("KEYCHAIN_PATH", "")
KEYCHAIN_PASSWORD = os.environ.get("KEYCHAIN_PASSWORD", "")

CACHE_TTL = {
    "endpoints": 300,
    "endpoint_detail": 300,
    "quarantine": 120,
    "health": 300,
}

STATE_MAP = {0: "Unknown", 1: "Online", 2: "Offline", 3: "Suspended"}
LICENSE_MAP = {0: "Pending", 1: "Active", 2: "Expired", 6: "None"}

COMPANIES = json.loads(os.environ.get("GZ_COMPANY_IDS", "[]"))


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
            import subprocess
            subprocess.run(["security", "unlock-keychain", "-p", KEYCHAIN_PASSWORD, KEYCHAIN_PATH],
                           capture_output=True, timeout=5)
            r = subprocess.run(["security", "find-generic-password", "-a", "openclaw",
                                "-s", env_name, "-w", KEYCHAIN_PATH],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass

    try:
        import subprocess
        r = subprocess.run(["security", "find-generic-password", "-s", env_name, "-w"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass

    print(f"[ERROR] Secret not found: {env_name} -- set it as an environment variable or in your keychain",
          file=sys.stderr)
    sys.exit(1)


def get_auth_header() -> str:
    api_key = read_secret("gravityzone-api-key")
    return "Basic " + base64.b64encode((api_key + ":").encode()).decode()


# =============================================================================
# AUDIT LOG
# =============================================================================


def audit_log_entry(method: str, service: str, status: int, cached: bool = False):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "system": "gravityzone",
        "method": method,
        "service": service,
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


def get_cached(key: str, ttl: int):
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
# JSON-RPC CLIENT
# =============================================================================


def gz_call(service: str, method: str, params: dict | None = None, use_cache: bool = True,
            cache_key: str | None = None, cache_ttl: int = 300) -> dict:
    ck = cache_key or f"{service}:{method}"
    if use_cache:
        cached = get_cached(ck, cache_ttl)
        if cached is not None:
            audit_log_entry(method, service, 200, cached=True)
            return cached

    url = f"{BASE_URL}/v1.0/jsonrpc/{service}"
    payload = {
        "id": str(uuid.uuid4()),
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
    }
    data = json.dumps(payload).encode()

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", get_auth_header())

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            audit_log_entry(method, service, resp.status)
    except urllib.error.HTTPError as e:
        audit_log_entry(method, service, e.code)
        body = e.read().decode() if e.fp else ""
        if e.code == 401:
            print("[ERROR] Authentication failed. Check GRAVITYZONE_API_KEY.", file=sys.stderr)
        elif e.code == 429:
            retry = e.headers.get("Retry-After", "unknown")
            print(f"[ERROR] Rate limited. Retry after {retry}s", file=sys.stderr)
        else:
            print(f"[ERROR] HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[ERROR] Connection failed: {e.reason}", file=sys.stderr)
        sys.exit(1)

    if "error" in result:
        err = result["error"]
        print(f"[ERROR] API Error {err.get('code')}: {err.get('message')}", file=sys.stderr)
        if err.get("data"):
            print(f"  Details: {err['data']}", file=sys.stderr)
        sys.exit(1)

    response_data = result.get("result", {})
    if use_cache:
        set_cached(ck, response_data)
    return response_data


def gz_call_paginated(service: str, method: str, params: dict | None = None,
                      max_pages: int = 10) -> list:
    params = params or {}
    params.setdefault("perPage", 100)
    all_items = []

    for page in range(1, max_pages + 1):
        params["page"] = page
        result = gz_call(service, method, params, use_cache=False)
        items = result.get("items", [])
        all_items.extend(items)
        if page >= result.get("pagesCount", 1):
            break

    return all_items


# =============================================================================
# API METHODS
# =============================================================================


def list_endpoints(managed_only: bool = True) -> list:
    if not COMPANIES:
        print("[ERROR] No company IDs configured. Set GZ_COMPANY_IDS environment variable.", file=sys.stderr)
        sys.exit(1)

    cached = get_cached("endpoints_list", CACHE_TTL["endpoints"])
    if cached:
        return cached

    all_items = []
    for company in COMPANIES:
        params = {
            "parentId": company["id"],
            "perPage": 100,
            "filters": {"depth": {"allItemsRecursively": True}},
        }
        if managed_only:
            params["isManaged"] = True

        items = gz_call_paginated("network", "getEndpointsList", params)
        for item in items:
            item["_company"] = company["name"]
        all_items.extend(items)

    set_cached("endpoints_list", all_items)
    return all_items


def get_endpoint_details(endpoint_id: str) -> dict:
    ck = f"endpoint:{endpoint_id}"
    cached = get_cached(ck, CACHE_TTL["endpoint_detail"])
    if cached:
        return cached

    result = gz_call("network", "getManagedEndpointDetails",
                     {"endpointId": endpoint_id}, use_cache=False)
    set_cached(ck, result)
    return result


def get_quarantine_items() -> list:
    cached = get_cached("quarantine_list", CACHE_TTL["quarantine"])
    if cached:
        return cached

    items = gz_call_paginated("quarantine/computers", "getQuarantineItemsList")
    set_cached("quarantine_list", items)
    return items


def create_scan_task(endpoint_ids: list, scan_type: int = 1, name: str = None) -> dict:
    return gz_call("network", "createScanTask", {
        "targetIds": endpoint_ids,
        "type": scan_type,
        "name": name or f"API Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    }, use_cache=False)


def isolate_endpoint(endpoint_id: str) -> dict:
    return gz_call("incidents", "createIsolateEndpointTask",
                   {"endpointId": endpoint_id}, use_cache=False)


def restore_endpoint(endpoint_id: str) -> dict:
    return gz_call("incidents", "createRestoreEndpointFromIsolationTask",
                   {"endpointId": endpoint_id}, use_cache=False)


# =============================================================================
# ANALYSIS & REPORTING
# =============================================================================


def fleet_health() -> dict:
    endpoints = list_endpoints()
    if not endpoints:
        return {"status": "NO_DATA", "message": "No managed endpoints found"}

    details = []
    for ep in endpoints:
        try:
            d = get_endpoint_details(ep["id"])
            details.append(d)
        except SystemExit:
            details.append({"id": ep["id"], "name": ep.get("name", "?"), "_error": True})

    total = len(details)
    online = sum(1 for d in details if d.get("state") == 1)
    offline = sum(1 for d in details if d.get("state") == 2)
    errors = sum(1 for d in details if d.get("_error"))
    infected = [d for d in details if d.get("malwareStatus", {}).get("infected")]
    malware_detected = [d for d in details if d.get("malwareStatus", {}).get("detection")]
    sig_outdated = [d for d in details if d.get("agent", {}).get("signatureOutdated")]
    agent_outdated = [d for d in details if d.get("agent", {}).get("productOutdated")]
    unlicensed = [d for d in details if d.get("agent", {}).get("licensed") not in (1, None)]
    policy_drift = [d for d in details if d.get("policy", {}).get("applied") is False]

    if infected:
        status = "CRITICAL"
    elif sig_outdated or agent_outdated or malware_detected:
        status = "WARN"
    elif offline > total * 0.3:
        status = "WARN"
    else:
        status = "OK"

    return {
        "status": status,
        "summary": {"total": total, "online": online, "offline": offline, "errors": errors},
        "issues": {
            "infected": [{"id": d["id"], "name": d.get("name")} for d in infected],
            "malware_detected_24h": [{"id": d["id"], "name": d.get("name")} for d in malware_detected],
            "signatures_outdated": [{"id": d["id"], "name": d.get("name")} for d in sig_outdated],
            "agent_outdated": [{"id": d["id"], "name": d.get("name")} for d in agent_outdated],
            "unlicensed": [{"id": d["id"], "name": d.get("name"),
                           "license": LICENSE_MAP.get(d.get("agent", {}).get("licensed", -1), "?")}
                          for d in unlicensed],
            "policy_not_applied": [{"id": d["id"], "name": d.get("name"),
                                   "policy": d.get("policy", {}).get("name")}
                                  for d in policy_drift],
        },
        "quarantine_count": len(get_quarantine_items()),
        "details": details,
    }


def get_outdated_endpoints() -> list:
    endpoints = list_endpoints()
    outdated = []
    for ep in endpoints:
        try:
            d = get_endpoint_details(ep["id"])
            agent = d.get("agent", {})
            if agent.get("signatureOutdated") or agent.get("productOutdated"):
                outdated.append({
                    "id": d["id"], "name": d.get("name"),
                    "state": STATE_MAP.get(d.get("state"), "?"),
                    "signature_outdated": agent.get("signatureOutdated", False),
                    "agent_outdated": agent.get("productOutdated", False),
                    "last_update": agent.get("lastUpdate"),
                    "agent_version": agent.get("productVersion"),
                    "last_seen": d.get("lastSeen"),
                })
        except SystemExit:
            continue
    return outdated


def get_infected_endpoints() -> list:
    endpoints = list_endpoints()
    infected = []
    for ep in endpoints:
        try:
            d = get_endpoint_details(ep["id"])
            ms = d.get("malwareStatus", {})
            if ms.get("infected") or ms.get("detection"):
                infected.append({
                    "id": d["id"], "name": d.get("name"),
                    "state": STATE_MAP.get(d.get("state"), "?"),
                    "infected": ms.get("infected", False),
                    "detection_24h": ms.get("detection", False),
                    "ip": d.get("ip"), "os": d.get("operatingSystem"),
                    "last_seen": d.get("lastSeen"),
                })
        except SystemExit:
            continue
    return infected


# =============================================================================
# OUTPUT FORMATTING
# =============================================================================


def print_json(data):
    print(json.dumps(data, indent=2, default=str))


def print_health(health: dict):
    s = health["summary"]
    status = health["status"]
    issues = health["issues"]

    print(f"\n{'='*50}")
    print(f"  GravityZone Fleet Health: [{status}]")
    print(f"{'='*50}")
    print(f"  Endpoints: {s['total']} total | {s['online']} online | {s['offline']} offline")
    print(f"  Quarantine items: {health['quarantine_count']}")

    if issues["infected"]:
        print(f"\n  [CRITICAL] ACTIVE INFECTIONS ({len(issues['infected'])}):")
        for ep in issues["infected"]:
            print(f"    - {ep['name']} ({ep['id']})")

    if issues["malware_detected_24h"]:
        print(f"\n  [WARN] Malware detected in last 24h ({len(issues['malware_detected_24h'])}):")
        for ep in issues["malware_detected_24h"]:
            print(f"    - {ep['name']} ({ep['id']})")

    if issues["signatures_outdated"]:
        print(f"\n  [WARN] Outdated signatures ({len(issues['signatures_outdated'])}):")
        for ep in issues["signatures_outdated"]:
            print(f"    - {ep['name']} ({ep['id']})")

    if issues["agent_outdated"]:
        print(f"\n  [WARN] Outdated agent ({len(issues['agent_outdated'])}):")
        for ep in issues["agent_outdated"]:
            print(f"    - {ep['name']} ({ep['id']})")

    if issues["unlicensed"]:
        print(f"\n  [WARN] License issues ({len(issues['unlicensed'])}):")
        for ep in issues["unlicensed"]:
            print(f"    - {ep['name']} -- {ep['license']}")

    if issues["policy_not_applied"]:
        print(f"\n  [WARN] Policy not applied ({len(issues['policy_not_applied'])}):")
        for ep in issues["policy_not_applied"]:
            print(f"    - {ep['name']} -- policy: {ep['policy']}")

    if not any(issues.values()):
        print("\n  All endpoints healthy. No issues detected.")

    print(f"{'='*50}\n")


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description="GravityZone Cloud API Wrapper")
    parser.add_argument("--test", action="store_true", help="Test API connectivity")
    parser.add_argument("--endpoints", action="store_true", help="List managed endpoints")
    parser.add_argument("--endpoint", type=str, help="Get endpoint details by ID")
    parser.add_argument("--health", action="store_true", help="Fleet health summary")
    parser.add_argument("--quarantine", action="store_true", help="List quarantined items")
    parser.add_argument("--outdated", action="store_true", help="Show outdated endpoints")
    parser.add_argument("--infected", action="store_true", help="Show infected endpoints")
    parser.add_argument("--scan", type=str, help="Launch scan on endpoint ID")
    parser.add_argument("--type", type=int, default=1, help="Scan type: 1=quick, 2=full, 3=memory")
    parser.add_argument("--isolate", type=str, help="Isolate endpoint by ID")
    parser.add_argument("--restore", type=str, help="Restore isolated endpoint by ID")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.test:
        print("Testing GravityZone API connectivity...")
        try:
            eps = list_endpoints()
            print(f"[OK] Connected. {len(eps)} managed endpoints found.")
        except SystemExit:
            print("[FAIL] Could not connect to GravityZone API.")
            sys.exit(1)

    elif args.endpoints:
        eps = list_endpoints()
        if args.json:
            print_json(eps)
        else:
            print(f"\nManaged Endpoints ({len(eps)}):")
            print(f"{'Name':<28} {'Company':<22} {'IP':<16} {'OS':<20}")
            print("-" * 90)
            for ep in eps:
                print(f"{ep.get('name', '?'):<28} {ep.get('_company', '?')[:22]:<22} "
                      f"{ep.get('ip', '?'):<16} "
                      f"{ep.get('operatingSystemVersion', '?')[:20]:<20}")

    elif args.endpoint:
        d = get_endpoint_details(args.endpoint)
        if args.json:
            print_json(d)
        else:
            agent = d.get("agent", {})
            ms = d.get("malwareStatus", {})
            print(f"\nEndpoint: {d.get('name')}")
            print(f"  State: {STATE_MAP.get(d.get('state'), '?')}")
            print(f"  IP: {d.get('ip')}")
            print(f"  OS: {d.get('operatingSystem')}")
            print(f"  Last seen: {d.get('lastSeen')}")
            print(f"  Agent version: {agent.get('productVersion')}")
            print(f"  Signatures outdated: {agent.get('signatureOutdated')}")
            print(f"  Agent outdated: {agent.get('productOutdated')}")
            print(f"  License: {LICENSE_MAP.get(agent.get('licensed', -1), '?')}")
            print(f"  Malware detected (24h): {ms.get('detection')}")
            print(f"  Currently infected: {ms.get('infected')}")
            print(f"  Policy: {d.get('policy', {}).get('name')} (applied: {d.get('policy', {}).get('applied')})")
            modules = d.get("modules", {})
            enabled = [k for k, v in modules.items() if v]
            print(f"  Modules: {', '.join(enabled) if enabled else 'none'}")

    elif args.health:
        health = fleet_health()
        if args.json:
            output = {k: v for k, v in health.items() if k != "details"}
            print_json(output)
        else:
            print_health(health)

    elif args.quarantine:
        items = get_quarantine_items()
        if args.json:
            print_json(items)
        else:
            if not items:
                print("\nQuarantine is empty.")
            else:
                print(f"\nQuarantined Items ({len(items)}):")
                print(f"{'Threat':<35} {'Endpoint':<25} {'Date':<20} {'Status'}")
                print("-" * 100)
                status_map = {0: "Quarantined", 1: "Removing", 2: "Restoring",
                              3: "Remove failed", 4: "Restore failed"}
                for item in items:
                    print(f"{item.get('threatName', '?')[:35]:<35} "
                          f"{item.get('endpointName', '?')[:25]:<25} "
                          f"{item.get('quarantinedOn', '?')[:20]:<20} "
                          f"{status_map.get(item.get('actionStatus', -1), '?')}")

    elif args.outdated:
        outdated = get_outdated_endpoints()
        if args.json:
            print_json(outdated)
        else:
            if not outdated:
                print("\nAll endpoints are up to date.")
            else:
                print(f"\nOutdated Endpoints ({len(outdated)}):")
                for ep in outdated:
                    flags = []
                    if ep["signature_outdated"]:
                        flags.append("SIGNATURES")
                    if ep["agent_outdated"]:
                        flags.append("AGENT")
                    print(f"  {ep['name']} [{ep['state']}] -- outdated: {', '.join(flags)} "
                          f"(last update: {ep['last_update']}, ver: {ep['agent_version']})")

    elif args.infected:
        infected = get_infected_endpoints()
        if args.json:
            print_json(infected)
        else:
            if not infected:
                print("\nNo active infections detected.")
            else:
                print(f"\n[CRITICAL] Infected Endpoints ({len(infected)}):")
                for ep in infected:
                    flags = []
                    if ep["infected"]:
                        flags.append("ACTIVE INFECTION")
                    if ep["detection_24h"]:
                        flags.append("DETECTION 24H")
                    print(f"  {ep['name']} [{ep['state']}] -- {', '.join(flags)} "
                          f"(IP: {ep['ip']}, OS: {ep['os']})")

    elif args.scan:
        print(f"Launching {'quick' if args.type == 1 else 'full' if args.type == 2 else 'memory'} "
              f"scan on {args.scan}...")
        result = create_scan_task([args.scan], args.type)
        print(f"[OK] Scan task created: {result}")

    elif args.isolate:
        print(f"[!] Isolating endpoint {args.isolate} from the network...")
        result = isolate_endpoint(args.isolate)
        print(f"[OK] Isolation task created: {result}")

    elif args.restore:
        print(f"Restoring endpoint {args.restore} from isolation...")
        result = restore_endpoint(args.restore)
        print(f"[OK] Restore task created: {result}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

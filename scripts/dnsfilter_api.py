#!/usr/bin/env python3
"""DNSFilter API helper for MSP operations.

Configuration:
    Set the following environment variables (or use macOS Keychain):
        DNSFILTER_API_KEY     — DNSFilter API bearer token
    Optional:
        DEFAULT_ORG_ID        — Default organization ID for --categories/--domains

Usage:
    python3 dnsfilter_api.py --summary          # Quick summary (categories + top domains)
    python3 dnsfilter_api.py --summary --json   # JSON output
    python3 dnsfilter_api.py --categories       # Top categories by query count
    python3 dnsfilter_api.py --domains           # Top domains
    python3 dnsfilter_api.py --orgs              # List organizations
    python3 dnsfilter_api.py --days 7            # Look back N days (default: 1)
    python3 dnsfilter_api.py --lookup example.com         # Category lookup via API
    python3 dnsfilter_api.py --check-block example.com    # Check if domain is blocked
    python3 dnsfilter_api.py --policies                             # List policies
    python3 dnsfilter_api.py --allowlist --policy-id 12345          # Show current allowlist
    python3 dnsfilter_api.py --allowlist-add example.com --policy-id 12345 --note "Approved"
    python3 dnsfilter_api.py --allowlist-remove example.com --policy-id 12345
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta

# =============================================================================
# CONFIG
# =============================================================================

API_BASE = "https://api.dnsfilter.com/v1"
DNSFILTER_RESOLVERS = ["103.247.36.36", "103.247.37.37"]
DEFAULT_ORG_ID = os.environ.get("DEFAULT_ORG_ID", "")
KEYCHAIN_PATH = os.environ.get("KEYCHAIN_PATH", "")
KEYCHAIN_PASSWORD = os.environ.get("KEYCHAIN_PASSWORD", "")


# =============================================================================
# SECRET RETRIEVAL
# =============================================================================


def get_api_key():
    val = os.environ.get("DNSFILTER_API_KEY")
    if val:
        return val

    if KEYCHAIN_PATH and KEYCHAIN_PASSWORD:
        try:
            subprocess.run(["security", "unlock-keychain", "-p", KEYCHAIN_PASSWORD, KEYCHAIN_PATH],
                           capture_output=True, timeout=5)
            result = subprocess.run(
                ["security", "find-generic-password", "-a", "openclaw",
                 "-s", "DNSFILTER_API_KEY", "-w", KEYCHAIN_PATH],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", "DNSFILTER_API_KEY", "-w"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    print("Error: DNSFILTER_API_KEY not found -- set it as an environment variable or in your keychain",
          file=sys.stderr)
    sys.exit(1)


# =============================================================================
# HTTP HELPERS
# =============================================================================


def api_get(key, endpoint, params=None):
    import urllib.parse
    url = f"{API_BASE}/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        result = subprocess.run(
            ["curl", "-sf", "-H", f"Authorization: Bearer {key}", url],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"error": f"HTTP error (curl exit {result.returncode})"}
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}"}
    except Exception as e:
        return {"error": str(e)}


def api_post(key, endpoint, data=None):
    url = f"{API_BASE}/{endpoint}"
    body = json.dumps(data) if data else "{}"
    try:
        result = subprocess.run(
            ["curl", "-sf", "-X", "POST",
             "-H", f"Authorization: Bearer {key}",
             "-H", "Content-Type: application/json",
             "-d", body, url],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"error": f"HTTP error (curl exit {result.returncode})"}
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}"}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# ORGANIZATIONS & TRAFFIC REPORTS
# =============================================================================


def get_orgs(key):
    data = api_get(key, "organizations")
    orgs = []
    for org in data.get("data", []):
        attrs = org.get("attributes", {})
        nets = org.get("relationships", {}).get("networks", {}).get("data", [])
        orgs.append({
            "id": org["id"],
            "name": attrs.get("name"),
            "msp_id": attrs.get("managed_by_msp_id"),
            "canceled": attrs.get("canceled", False),
            "network_ids": [n["id"] for n in nets],
            "first_traffic": attrs.get("first_traffic_sent"),
        })
    return orgs


def get_categories(key, org_id, start, end):
    data = api_get(key, "traffic_reports/top_categories", {
        "organization_id": org_id, "start": start, "end": end
    })
    if "error" in data:
        return data
    meta = data.get("meta", {})
    values = data.get("data", {}).get("values", [])
    categories = []
    for v in values:
        categories.append({
            "name": v.get("category_name"),
            "queries": v.get("total", 0),
            "methods": v.get("methods_names", []),
        })
    return {
        "total_queries": meta.get("total_count", 0),
        "total_category_hits": meta.get("total_categories_sum", 0),
        "categories": categories,
    }


def get_top_domains(key, org_id, start, end, limit=15):
    data = api_get(key, "traffic_reports/top_domains", {
        "organization_id": org_id, "start": start, "end": end
    })
    if "error" in data:
        return data
    meta = data.get("meta", {})
    values = data.get("data", {}).get("values", [])
    domains = []
    for v in values[:limit]:
        domains.append({
            "domain": v.get("domain"),
            "queries": v.get("total", 0),
            "allowed_categories": v.get("allowed_names", []),
            "blocked_categories": v.get("blocked_names", []),
            "is_blocked": len(v.get("blocked", [])) > 0,
        })
    return {
        "total_unique_domains": meta.get("total_count", 0),
        "domains": domains,
    }


def build_summary(key, days=1):
    orgs = get_orgs(key)
    end = datetime.now().strftime("%Y-%m-%d")
    start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    results = []
    for org in orgs:
        if org["canceled"]:
            continue
        org_data = {"org": org["name"], "org_id": org["id"]}

        cats = get_categories(key, org["id"], start, end)
        if "error" not in cats:
            org_data["total_queries"] = cats["total_queries"]
            org_data["top_categories"] = cats["categories"][:10]
            suspicious = ["Malware", "Phishing", "Botnet", "Cryptomining",
                         "Command and Control", "Newly Observed", "DGA"]
            org_data["threats_detected"] = [
                c for c in cats["categories"]
                if any(s.lower() in c["name"].lower() for s in suspicious)
            ]
        else:
            org_data["categories_error"] = cats["error"]

        doms = get_top_domains(key, org["id"], start, end)
        if "error" not in doms:
            org_data["total_unique_domains"] = doms["total_unique_domains"]
            org_data["top_domains"] = doms["domains"][:10]
            org_data["blocked_domains"] = [d for d in doms["domains"] if d["is_blocked"]]
        else:
            org_data["domains_error"] = doms["error"]

        results.append(org_data)

    return {"period": f"{start} to {end}", "days": days, "organizations": results}


def print_summary(summary):
    print(f"DNSFilter Report ({summary['period']}, {summary['days']}d)")
    print("=" * 60)
    for org in summary["organizations"]:
        print(f"\n  {org['org']} (ID: {org['org_id']})")
        total = org.get("total_queries", "N/A")
        unique = org.get("total_unique_domains", "N/A")
        print(f"   Total Queries: {total:,}" if isinstance(total, int) else f"   Total Queries: {total}")
        print(f"   Unique Domains: {unique:,}" if isinstance(unique, int) else f"   Unique Domains: {unique}")

        threats = org.get("threats_detected", [])
        if threats:
            print(f"\n   THREATS DETECTED:")
            for t in threats:
                print(f"      {t['name']}: {t['queries']} queries")
        else:
            print(f"   No threat categories detected")

        blocked = org.get("blocked_domains", [])
        if blocked:
            print(f"\n   Blocked Domains:")
            for d in blocked:
                print(f"      {d['domain']}: {d['queries']} queries ({', '.join(d['blocked_categories'])})")

        cats = org.get("top_categories", [])
        if cats:
            print(f"\n   Top Categories:")
            for c in cats[:8]:
                pct = (c['queries'] / total * 100) if isinstance(total, int) and total > 0 else 0
                print(f"      {c['name']}: {c['queries']:,} ({pct:.1f}%)")

        doms = org.get("top_domains", [])
        if doms:
            print(f"\n   Top Domains:")
            for d in doms[:8]:
                status = "BLOCKED" if d["is_blocked"] else "ok"
                print(f"      [{status}] {d['domain']}: {d['queries']:,}")


# =============================================================================
# DOMAIN LOOKUP & BLOCK DETECTION
# =============================================================================


def get_all_categories(key):
    data = api_get(key, "categories")
    if "error" in data:
        return {}
    cat_map = {}
    for cat in data.get("data", []):
        attrs = cat.get("attributes", {})
        cat_map[str(cat["id"])] = {
            "name": attrs.get("name", "Unknown"),
            "security": attrs.get("security", False),
        }
    return cat_map


def lookup_domain(key, fqdn):
    data = api_get(key, "domains/user_lookup", {"fqdn": fqdn})
    if "error" in data:
        return {"error": data["error"], "domain": fqdn}

    cat_map = get_all_categories(key)
    domain_data = data.get("data", {})
    rels = domain_data.get("relationships", {})
    cat_ids = rels.get("categories", {}).get("data", [])

    categories = []
    is_security_threat = False
    for c in cat_ids:
        cid = str(c.get("id", ""))
        info = cat_map.get(cid, {"name": f"ID:{cid}", "security": False})
        categories.append(info["name"])
        if info["security"]:
            is_security_threat = True

    return {
        "domain": fqdn,
        "categories": categories,
        "category_ids": [c.get("id") for c in cat_ids],
        "is_security_threat": is_security_threat,
    }


def check_block(domain, api_key=None):
    result = {
        "domain": domain, "is_blocked": False, "block_type": None,
        "categories": [], "is_security_threat": False, "public_ips": [], "note": None,
    }

    if api_key:
        lookup = lookup_domain(api_key, domain)
        if "error" not in lookup:
            result["categories"] = lookup.get("categories", [])
            result["is_security_threat"] = lookup.get("is_security_threat", False)
            if lookup.get("is_security_threat"):
                result["is_blocked"] = True
                result["block_type"] = "security_threat_category"
                result["note"] = "Domain is categorized as a security threat by DNSFilter."

    try:
        r = subprocess.run(["dig", "+short", domain, "@1.1.1.1"],
                           capture_output=True, text=True, timeout=10)
        public_ips = [l.strip() for l in r.stdout.strip().split("\n")
                      if l.strip() and all(p.isdigit() for p in l.strip().split(".")) and l.count(".") == 3]
        result["public_ips"] = public_ips
    except Exception:
        pass

    if result["is_blocked"]:
        return result

    if api_key and result["categories"]:
        result["block_type"] = "none"

    return result


# =============================================================================
# POLICY & ALLOWLIST MANAGEMENT
# =============================================================================


def get_policies(key):
    data = api_get(key, "policies", {"include_global_policies": "true"})
    if "error" in data:
        return data
    policies = []
    for p in data.get("data", []):
        attrs = p.get("attributes", {})
        policies.append({
            "id": p["id"], "name": attrs.get("name", ""),
            "organization_id": attrs.get("organization_id"),
            "is_global": attrs.get("is_global_policy", False),
            "whitelist_domains": attrs.get("whitelist_domains", []),
            "blacklist_domains": attrs.get("blacklist_domains", []),
        })
    return {"policies": policies}


def get_policy_detail(key, policy_id):
    data = api_get(key, f"policies/{policy_id}")
    if "error" in data:
        return data
    p = data.get("data", {})
    attrs = p.get("attributes", {})
    return {
        "id": p.get("id"), "name": attrs.get("name", ""),
        "whitelist_domains": attrs.get("whitelist_domains", []),
        "blacklist_domains": attrs.get("blacklist_domains", []),
    }


def add_to_allowlist(key, policy_id, domain, note):
    data = api_post(key, f"policies/{policy_id}/add_whitelist_domain", {"domain": domain, "note": note})
    if "error" in data:
        return data
    wl = data.get("data", {}).get("attributes", {}).get("whitelist_domains", [])
    return {"success": domain in wl, "domain": domain, "policy_id": policy_id, "allowlist": wl}


def remove_from_allowlist(key, policy_id, domain, note):
    data = api_post(key, f"policies/{policy_id}/remove_whitelist_domain", {"domain": domain, "note": note})
    if "error" in data:
        return data
    wl = data.get("data", {}).get("attributes", {}).get("whitelist_domains", [])
    return {"success": domain not in wl, "domain": domain, "policy_id": policy_id, "allowlist": wl}


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description="DNSFilter API helper")
    parser.add_argument("--summary", action="store_true", help="Full summary report")
    parser.add_argument("--categories", action="store_true", help="Top categories")
    parser.add_argument("--domains", action="store_true", help="Top domains")
    parser.add_argument("--orgs", action="store_true", help="List organizations")
    parser.add_argument("--days", type=int, default=1, help="Look-back period in days")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--org-id", type=str, help="Specific org ID")
    parser.add_argument("--lookup", type=str, metavar="DOMAIN", help="Look up domain categories")
    parser.add_argument("--check-block", type=str, metavar="DOMAIN", help="Check if domain is blocked")
    parser.add_argument("--policies", action="store_true", help="List all policies")
    parser.add_argument("--allowlist", action="store_true", help="Show allowlist for a policy")
    parser.add_argument("--allowlist-add", type=str, metavar="DOMAIN", help="Add domain to allowlist")
    parser.add_argument("--allowlist-remove", type=str, metavar="DOMAIN", help="Remove domain from allowlist")
    parser.add_argument("--policy-id", type=str, help="Policy ID for allowlist operations")
    parser.add_argument("--note", type=str, default="", help="Note for allowlist add/remove")
    args = parser.parse_args()

    key = get_api_key()

    if args.check_block:
        result = check_block(args.check_block, api_key=key)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result["is_blocked"]:
                print(f"BLOCKED: {result['domain']} ({result['block_type']})")
                if result["categories"]:
                    print(f"  Categories: {', '.join(result['categories'])}")
            else:
                print(f"OK: {result['domain']} is NOT blocked")
        return

    if args.lookup:
        result = lookup_domain(key, args.lookup)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if "error" in result:
                print(f"ERROR: {result['error']}")
            else:
                print(f"Domain: {result['domain']}")
                print(f"Categories: {', '.join(result['categories']) or 'Uncategorized'}")
                if result["is_security_threat"]:
                    print(f"WARNING: Flagged as security threat")
        return

    if args.orgs:
        orgs = get_orgs(key)
        if args.json:
            print(json.dumps(orgs, indent=2))
        else:
            for o in orgs:
                print(f"{o['id']}: {o['name']} (MSP: {o['msp_id']}, Networks: {o['network_ids']})")
        return

    if args.policies:
        result = get_policies(key)
        if "error" in result:
            print(f"ERROR: {result['error']}", file=sys.stderr)
            sys.exit(1)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for p in result["policies"]:
                gl = " [GLOBAL]" if p["is_global"] else ""
                print(f"{p['id']}: {p['name']}{gl} (org: {p['organization_id']})")
        return

    if args.allowlist:
        if not args.policy_id:
            print("ERROR: --policy-id required", file=sys.stderr)
            sys.exit(1)
        result = get_policy_detail(key, args.policy_id)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            wl = result.get("whitelist_domains", [])
            print(f"Allowlist ({len(wl)} domains):")
            for d in sorted(wl):
                print(f"  {d}")
        return

    if args.allowlist_add:
        if not args.policy_id:
            print("ERROR: --policy-id required", file=sys.stderr)
            sys.exit(1)
        note = args.note or f"Added via API ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
        result = add_to_allowlist(key, args.policy_id, args.allowlist_add, note)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"OK: {args.allowlist_add} added" if result.get("success") else f"WARN: verify manually")
        return

    if args.allowlist_remove:
        if not args.policy_id:
            print("ERROR: --policy-id required", file=sys.stderr)
            sys.exit(1)
        note = args.note or f"Removed via API ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
        result = remove_from_allowlist(key, args.policy_id, args.allowlist_remove, note)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"OK: {args.allowlist_remove} removed" if result.get("success") else f"WARN: verify manually")
        return

    if args.categories:
        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d")
        org_id = args.org_id or DEFAULT_ORG_ID
        if not org_id:
            print("ERROR: --org-id required. Run --orgs to discover IDs.", file=sys.stderr)
            sys.exit(1)
        cats = get_categories(key, org_id, start, end)
        if args.json:
            print(json.dumps(cats, indent=2))
        else:
            for c in cats.get("categories", []):
                print(f"{c['name']}: {c['queries']}")
        return

    if args.domains:
        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d")
        org_id = args.org_id or DEFAULT_ORG_ID
        if not org_id:
            print("ERROR: --org-id required. Run --orgs to discover IDs.", file=sys.stderr)
            sys.exit(1)
        doms = get_top_domains(key, org_id, start, end)
        if args.json:
            print(json.dumps(doms, indent=2))
        else:
            for d in doms.get("domains", []):
                status = "BLOCKED" if d["is_blocked"] else "allowed"
                print(f"{d['domain']}: {d['queries']} ({status})")
        return

    summary = build_summary(key, args.days)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_summary(summary)


if __name__ == "__main__":
    main()

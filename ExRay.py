#!/usr/bin/env python3

import argparse
import requests
import sys
import urllib3
import socket
import re
from collections import Counter
import concurrent.futures  # for parallel DNS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------
# 1. EXCHANGE PATHS
# ---------------------------------------------------------------------
EXCHANGE_PATHS = [
    "/owa",
    "/owa/auth",
    "/exchange",      
    "/exchweb",       
    "/exchweb/bin",   
    "/public",
    "/ecp",
    "/exadmin",
    "/ecp/UsersGroups",
    "/ecp/Organization",
    "/ecp/Servers",
    "/ecp/RulesEditor/InboxRules.slab",
    "/ecp/PersonalSettings/GeneralSettings.slab",
    "/ecp/Reporting/RunReport.aspx",
    "/ecp/ExportImport.slab",
    "/ecp/diagnostics.aspx",
    "/ecp/hybrid",
    "/ecp/reportingwebservice.svc",
    "/autodiscover/autodiscover.xml",
    "/Autodiscover/Autodiscover.xml",
    "/autodiscover/Autodiscover.svc",
    "/ews/exchange.asmx",
    "/ews/odata",
    "/ews/mrsproxy.svc",
    "/ews/LegacyServices.svc",
    "/ews/PushNotifications",
    "/pushnotifications",
    "/oab",
    "/Microsoft-Server-ActiveSync",
    "/eas",
    "/MobileSync",
    "/MobileSyncService.svc",
    "/mapi",
    "/mapi/nspi",
    "/mapi/healthcheck",
    "/rpc",
    "/RpcProxy",
    "/PowerShell",
    "/PowerShell-liveid",
    "/unifiedmessaging/",
    "/unifiedmessaging/service.asmx",
    "/healthcheck",
    "/healthcheck.htm",
    "/exhealth",
    "/aspnet_client",
    "/reportingwebservice",
    "/customAddOns",
]

# ---------------------------------------------------------------------
# 2. SUBDOMAIN GENERATION
# ---------------------------------------------------------------------
BASE_SUBDOMAINS = [
    "owa", "mail", "exchange", "ex", "exch", "outlook", "webmail",
    "autodiscover", "server", "email", "intranet", "mx", "mobile",
    "activesync", "active-sync", "eas", "ecp", "ews"
]

NUMERIC_SHORT = ["1", "2", "3", "4"]
NUMERIC_ZERO  = ["01", "02", "03", "04"]
ENV_SUFFIXES  = ["dev", "test", "tst", "prd", "prod"]

def generate_subdomain_variants():
    result = set()
    for base in BASE_SUBDOMAINS:
        result.add(base)
        for n in NUMERIC_SHORT + NUMERIC_ZERO:
            result.add(base + n)
            result.add(base + '-' + n)
        for env in ENV_SUFFIXES:
            result.add(base + env)
            result.add(base + '-' + env)
        for n in NUMERIC_SHORT + NUMERIC_ZERO:
            for e in ENV_SUFFIXES:
                result.add(base + n + e)
                result.add(base + '-' + n + e)
                result.add(base + n + '-' + e)
                result.add(base + '-' + n + '-' + e)
    return sorted(result)

# ---------------------------------------------------------------------
# 3. O365 DETECTION
# ---------------------------------------------------------------------
O365_PATTERNS = [
    "outlook.com",
    "office365.com",
    "office.com",
    "microsoftonline.com",
    "live.com",
    "azureedge.net",
]

def is_o365_redirect(host_or_ip, scheme="http", timeout=3):
    url = f"{scheme}://{host_or_ip}"
    try:
        r = requests.head(url, verify=False, allow_redirects=False, timeout=timeout)
        if r.is_redirect or (300 <= r.status_code < 400):
            loc = (r.headers.get("Location") or "").lower()
            if any(s in loc for s in O365_PATTERNS):
                return True
        if r.status_code == 200 and not r.is_redirect:
            rg = requests.get(url, verify=False, timeout=timeout)
            if any(s in rg.url.lower() for s in O365_PATTERNS):
                return True
    except:
        pass
    return False

# ---------------------------------------------------------------------
# 4. SOCKET UTILS & DNS
# ---------------------------------------------------------------------
def check_port_open(hostname, port, timeout=2):
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except:
        return False

def dns_resolve_all(subdomain):
    """Returns a list of IP addresses for 'subdomain', or [] if it fails."""
    try:
        _, _, iplist = socket.gethostbyname_ex(subdomain)
        return iplist
    except:
        return []

def parse_target(raw_target, http_only=False, https_only=False):
    raw = raw_target.strip()
    if not raw:
        return []
    low = raw.lower()
    if low.startswith("http://") or low.startswith("https://"):
        if http_only and low.startswith("https://"):
            converted = "http://" + raw.split("://", 1)[1]
            return [converted]
        elif https_only and low.startswith("http://"):
            converted = "https://" + raw.split("://", 1)[1]
            return [converted]
        else:
            return [raw]
    else:
        if http_only:
            return [f"http://{raw}"]
        elif https_only:
            return [f"https://{raw}"]
        else:
            return [f"http://{raw}", f"https://{raw}"]

def extract_host_port(full_url):
    m = re.match(r'^(https?)://([^/]+)(.*)', full_url)
    if not m:
        return None, None, None
    scheme = m.group(1).lower()
    hp = m.group(2)
    if ':' in hp:
        h, pstr = hp.split(':', 1)
        port = int(pstr)
    else:
        h = hp
        port = 80 if scheme == 'http' else 443
    return scheme, h, port

# ---------------------------------------------------------------------
# 5. PATH ENUMERATION
# ---------------------------------------------------------------------
def check_paths(target, paths, timeout=10):
    results = []
    for p in paths:
        full_url = target.rstrip("/") + p
        try:
            r = requests.get(full_url, verify=False, timeout=timeout)
            results.append((p, r.status_code))
        except requests.exceptions.RequestException as e:
            results.append((p, f"ERROR: {str(e)}"))
    return results

# ---------------------------------------------------------------------
# 6. MAIN SCRIPT
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ExRay Web - Exchange enumerator w/ domain brute force, parallel DNS, & wildcard detection."
    )
    parser.add_argument("-t","--target", help="Single target, e.g. 'mail.example.com'.")
    parser.add_argument("-l","--list",   help="File with one target per line.")
    parser.add_argument("--domain",      help="Brute force subdomains for e.g. 'target.com'.")
    parser.add_argument("--dns-threads", type=int, default=100,
                        help="Number of parallel DNS lookups (default 100).")
    parser.add_argument("--http-only","-H",action="store_true", help="Only check http://")
    parser.add_argument("--https-only","-S",action="store_true",help="Only check https://")
    parser.add_argument("--no-preflight",action="store_true",
                        help="Skip port check (requires --http-only or --https-only).")
    parser.add_argument("-o","--output", help="Write results to file.")
    args = parser.parse_args()

    if not (args.target or args.list or args.domain):
        print("[!] Provide --target, --list, or --domain.")
        sys.exit(1)
    if args.http_only and args.https_only:
        print("[!] Cannot combine --http-only and --https-only.")
        sys.exit(1)
    if args.no_preflight and not (args.http_only or args.https_only):
        print("[!] --no-preflight requires --http-only or --https-only.")
        sys.exit(1)

    final_targets = set()

    # (A) Single target
    if args.target:
        exp = parse_target(args.target, args.http_only, args.https_only)
        final_targets.update(exp)

    # (B) List of targets
    if args.list:
        lines = []
        try:
            with open(args.list,"r",encoding="utf-8") as f:
                lines = [x.strip() for x in f if x.strip()]
        except Exception as e:
            print(f"[!] Error reading target list file: {e}")
            sys.exit(1)
        for line in lines:
            expanded = parse_target(line, args.http_only, args.https_only)
            final_targets.update(expanded)
        print(f'[+] Loaded {len(lines)} raw target(s) from "{args.list}".')

    # -----------------------------------------------------------------
    # (C) Domain-based subdomain brute force W/ PARALLEL DNS
    # -----------------------------------------------------------------
    discovered_targets = set()
    if args.domain:
        domain = args.domain.strip()
        print(f"\n[+] Performing subdomain brute force for domain: {domain}")
        print("[!] NOTE: With sub-50 ms or sub-10 ms DNS lookups + rapid NXDOMAIN, "
              "this might complete in ~3 min; otherwise 5–15+ min.\n")

        subs = generate_subdomain_variants()
        subdomains = [f"{s}.{domain}" for s in subs]
        total_subs = len(subdomains)
        progress_points = {10,20,30,40,50,60,70,80,90}

        # We'll store resolved IPs in a dict
        fqdn_to_ips = {}

        # Parallel DNS resolution using user-defined threads
        import concurrent.futures
        max_threads = args.dns_threads  # e.g. default=100, or user override
        completed_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_fqdn = {
                executor.submit(dns_resolve_all, fqdn): fqdn for fqdn in subdomains
            }
            for future in concurrent.futures.as_completed(future_to_fqdn):
                completed_count += 1
                fqdn = future_to_fqdn[future]
                # progress
                pct = int((completed_count/total_subs)*100)
                if pct in progress_points:
                    print(f"  ... {pct}% of subdomain brute force completed.")
                    progress_points.remove(pct)

                iplist = future.result()
                fqdn_to_ips[fqdn] = iplist

        # Now we have all DNS results in fqdn_to_ips
        discovered_count = 0
        for fqdn, iplist in sorted(fqdn_to_ips.items()):
            if not iplist:
                continue  # no IPs => skip

            # Check if subdomain is O365
            sub_urls = parse_target(fqdn, args.http_only, args.https_only)
            is_sub_o365 = False
            for surl in sub_urls:
                ssch, shost, _ = extract_host_port(surl)
                if is_o365_redirect(shost, scheme=ssch):
                    print(f"  [O365 detected] {fqdn} => skipping subdomain + IPs.")
                    is_sub_o365 = True
                    break
            if is_sub_o365:
                continue

            # Not O365 => keep
            discovered_count += 1
            for su in sub_urls:
                final_targets.add(su)
                discovered_targets.add(su)

            # Check each resolved IP
            for ip in iplist:
                ip_urls = parse_target(ip, args.http_only, args.https_only)
                skip_ip = False
                for iurl in ip_urls:
                    iu_sch, iu_host, _ = extract_host_port(iurl)
                    if is_o365_redirect(iu_host, scheme=iu_sch):
                        print(f"  [O365 detected] {ip} => skipping IP.")
                        skip_ip = True
                        break
                if not skip_ip:
                    for iurl in ip_urls:
                        final_targets.add(iurl)
                        discovered_targets.add(iurl)

            print(f"  Found {fqdn} -> {iplist}")

        print(f"[+] Subdomain brute force complete, discovered {discovered_count} subdomain(s) that resolved.")

    # -----------------------------------------------------------------
    # Summarize final endpoints
    # -----------------------------------------------------------------
    unique_targets = sorted(final_targets)
    print(f"\n[+] After expansion/deduplication, we have {len(unique_targets)} total endpoint(s) to check.\n")

    if args.domain and discovered_targets:
        print("=== Discovered Targets from Subdomain Brute Force ===")
        for d in sorted(discovered_targets):
            print(f"  {d}")
        print()

    # Separate out HTTP vs HTTPS
    http_list = []
    https_list = []
    for ut in unique_targets:
        sch, ho, po = extract_host_port(ut)
        if sch == "http":
            http_list.append(ut)
        else:
            https_list.append(ut)

    # Preflight checks
    if not args.no_preflight:
        print("Performing preflight checks (TCP port open)...")
        open_http, open_https = [], []

        for h_t in http_list:
            _, ho, po = extract_host_port(h_t)
            if check_port_open(ho, po, 2):
                open_http.append(h_t)
        for h_s in https_list:
            _, ho, po = extract_host_port(h_s)
            if check_port_open(ho, po, 2):
                open_https.append(h_s)

        print(f"  Total HTTP endpoints to test: {len(http_list)}")
        print(f"  Total HTTPS endpoints to test: {len(https_list)}")
        print(f"  Hosts listening on HTTP: {len(open_http)}")
        print(f"  Hosts listening on HTTPS: {len(open_https)}")

        print("\nNow checking each opened port for web services...\n")
        to_scan = open_http + open_https
    else:
        print("[!] Skipping preflight checks by user request.\n")
        to_scan = http_list + https_list

    per_target_summary = {}
    output_data = []

    # SCAN
    for tgt in to_scan:
        print(f"=== Checking target: {tgt} ===")
        results = check_paths(tgt, EXCHANGE_PATHS, timeout=10)
        per_target_summary[tgt] = results

        for (path, code) in results:
            print(f" {path} -> {code}")
            output_data.append(f"{tgt} | {path} | {code}")

        print()

    # Skipped hosts
    skipped = set(unique_targets) - set(to_scan)
    if skipped:
        print("=== Skipped Targets (Due to closed ports or other reason) ===")
        for st in sorted(skipped):
            print(f"  {st}")
        print()

    # -----------------------------------------------------------------
    # 7. Final Summaries w/ wildcard detection (80%)
    # -----------------------------------------------------------------
    all_valid_endpoints = []
    wildcard_threshold = 0.80

    print("\n=== Per-Target Summary of Identified (Potentially Valid) Endpoints ===")

    for tgt in sorted(per_target_summary.keys()):
        results = per_target_summary[tgt]
        if not results:
            print(f"\nTarget: {tgt}\n  No results (empty?).")
            continue

        # Gather only int codes
        int_codes = [c for (_, c) in results if isinstance(c,int)]
        if not int_codes:
            print(f"\nTarget: {tgt}\n  No valid HTTP codes (all errors?).")
            continue

        c = Counter(int_codes)
        (most_common_code, cnt_most_common) = c.most_common(1)[0]
        total_count = len(int_codes)

        # if most common code is >=80% => wildcard
        if (cnt_most_common / total_count) >= wildcard_threshold:
            print(f"\nTarget: {tgt}")
            pct_str = round((cnt_most_common / total_count)*100,2)
            print(f"  => {cnt_most_common} of {total_count} probed paths responded with HTTP {most_common_code} "
                  f"({pct_str}%).")
            print("     Possible wildcard/catch-all behavior.\n")
            continue

        # Otherwise, list interesting codes
        print(f"\nTarget: {tgt}")
        any_found = False
        interesting = [200,301,302,401,403]
        for (path, code) in results:
            if isinstance(code,int) and code in interesting:
                print(f"  Found: {path} (HTTP {code})")
                all_valid_endpoints.append((tgt,path,code))
                any_found = True

        if not any_found:
            print("  No interesting endpoints discovered (or all were diff. codes).")

    print("\n=== Final Overall Summary (All Targets Combined) ===")
    if all_valid_endpoints:
        for (tgt, path, code) in all_valid_endpoints:
            print(f"  {tgt} -> {path} (HTTP {code})")
    else:
        print("  No potentially valid endpoints found across all targets.")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                for line in output_data:
                    out_f.write(line + "\n")
            print(f"\n[+] Results have been written to: {args.output}")
        except Exception as e:
            print(f"[!] Error writing to {args.output}: {e}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
ExRay - Exchange enumerator w/ domain brute force, DNS concurrency, HTTP concurrency, & wildcard detection. (v1.0)
 - Distinguishes between --dns-threads (DNS concurrency) and --http-threads (HTTP concurrency).
 - Enhances wildcard detection: even if the majority are "wildcard" codes, outlier endpoints get listed.
 - Detects and records O365 endpoints, reporting them in final output and in the JSON dump.
 - Produces two output files if -o is given:
   1) <output>.txt  -> Plain line-based results
   2) <output>.json -> Structured JSON summary including O365-detected hosts.
"""

import argparse
import requests
import sys
import urllib3
import socket
import re
from collections import Counter, defaultdict
import concurrent.futures
import base64
import struct
import json

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
    """Check for typical O365/Outlook redirection patterns."""
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
    """Quickly test TCP connectivity."""
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
    """
    Normalizes a target input (which might be domain, IP, or full URL)
    to a list of possible URLs: http:// / https://
    """
    raw = raw_target.strip()
    if not raw:
        return []
    low = raw.lower()
    if low.startswith("http://") or low.startswith("https://"):
        # Already a URL
        if http_only and low.startswith("https://"):
            converted = "http://" + raw.split("://", 1)[1]
            return [converted]
        elif https_only and low.startswith("http://"):
            converted = "https://" + raw.split("://", 1)[1]
            return [converted]
        else:
            return [raw]
    else:
        # Add scheme
        if http_only:
            return [f"http://{raw}"]
        elif https_only:
            return [f"https://{raw}"]
        else:
            return [f"http://{raw}", f"https://{raw}"]

def extract_host_port(full_url):
    """Return (scheme, host, port)."""
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
# 5. SIMPLE OWA VERSION MAPPING
# ---------------------------------------------------------------------
OWA_EXCHANGE_VERSION_MAP = {
    # Exchange 2003
    "6.5.6944.0":    "Exchange 2003 RTM",
    "6.5.7638.1":    "Exchange 2003 SP1",
    "6.5.7838.0":    "Exchange 2003 SP2",

    # Exchange 2007
    "8.0.685.24":    "Exchange 2007 RTM",
    "8.1.240.5":     "Exchange 2007 SP1",
    "8.2.176.2":     "Exchange 2007 SP2",
    "8.3.83.6":      "Exchange 2007 SP3",

    # Exchange 2010
    "14.0.639.21":   "Exchange 2010 RTM",
    "14.1.218.15":   "Exchange 2010 SP1",
    "14.2.247.5":    "Exchange 2010 SP2",
    "14.3.123.4":    "Exchange 2010 SP3",

    # Exchange 2013 (15.0)
    "15.0.516.32":   "Exchange 2013 RTM (CU0)",
    "15.0.620.29":   "Exchange 2013 CU1",
    "15.0.847.32":   "Exchange 2013 SP1/CU4",

    # Exchange 2016 (15.1)
    "15.1.225.16":   "Exchange 2016 RTM (CU0)",
    "15.1.396.30":   "Exchange 2016 CU1",
    "15.1.2507.16":  "Exchange 2016 CU19 or CU20",
    "15.1.2507.44":  "Exchange 2016 (approx latest build?)",

    # Exchange 2019 (15.2)
    "15.2.221.12":   "Exchange 2019 RTM",
    "15.2.330.5":    "Exchange 2019 CU1",
    "15.2.397.3":    "Exchange 2019 CU2",
    "15.2.922.13":   "Exchange 2019 CU7 (approx)",
}

def map_owa_version(owa_version_str):
    """
    Given something like "15.1.2507.44", attempt a best-guess
    or known mapping to an Exchange build version.
    """
    if not owa_version_str:
        return None
    if owa_version_str in OWA_EXCHANGE_VERSION_MAP:
        return OWA_EXCHANGE_VERSION_MAP[owa_version_str]
    # fallback: partial matches
    for known_ver, exch_desc in OWA_EXCHANGE_VERSION_MAP.items():
        if owa_version_str.startswith(known_ver[:4]):
            return f"{exch_desc} (approx)"
    return None

# ---------------------------------------------------------------------
# 6. NTLM TYPE2 BLOB PARSING
# ---------------------------------------------------------------------
def parse_ntlm_type2_blob(blob_b64):
    """
    Parse an NTLM Type 2 challenge Base64 string.
    Return a dict with discovered fields (domain, etc.).
    This is a minimal parse; real NTLM has more info in AV pairs.
    """
    try:
        raw = base64.b64decode(blob_b64)
        if not (raw.startswith(b"NTLMSSP\0\x02") and len(raw) > 32):
            return {}
        # Domain length at offset 12-13, offset at 16-19
        domain_len = struct.unpack("<H", raw[12:14])[0]
        domain_off = struct.unpack("<I", raw[16:20])[0]
        domain_str = ""
        if domain_off + domain_len <= len(raw):
            domain_str = raw[domain_off: domain_off + domain_len].decode("utf-16-le", errors="ignore").strip()
        return {"ntlm_domain": domain_str}
    except:
        return {}

# ---------------------------------------------------------------------
# 7. GLOBAL STORAGE FOR EXTRACTED INFO
# ---------------------------------------------------------------------
INTERESTING_HEADERS = [
    "Server",
    "X-OWA-Version",
    "X-FEServer",
    "X-Powered-By",
    "X-AspNet-Version",
]

# We'll store results per host here:
extracted_info = {
    "hosts": {},  # host -> { "headers": [...], "ntlm_domains": set(), "basic_http_exposed": bool }
}

# New: Global set for O365 detected hosts
o365_detected = set()

# ---------------------------------------------------------------------
# 8. PATH ENUMERATION + HEADER ANALYSIS (With Threading)
# ---------------------------------------------------------------------
def check_paths(target, paths, timeout=10, do_auth=True, http_threads=5):
    """
    For each path, send a GET request (in parallel) and gather:
      - status_code
      - interesting headers
      - if 'WWW-Authenticate' includes NTLM and do_auth=True, try a dummy NTLM handshake
      - detect if Basic auth is offered over plain HTTP
    Returns a list of (path, status_code, headers_dict, ntlm_info, basic_http_exposed)
    """
    def worker(p):
        full_url = target.rstrip("/") + p
        scheme, _, _ = extract_host_port(full_url)
        try:
            r = requests.get(full_url, verify=False, timeout=timeout)
            sc = r.status_code
            headers_lower = {k.lower(): v for k, v in r.headers.items()}

            found_headers = {}
            for h in INTERESTING_HEADERS:
                h_lower = h.lower()
                if h_lower in headers_lower:
                    found_headers[h] = headers_lower[h_lower]

            ntlm_info = {}
            basic_http_exposed = False

            if "www-authenticate" in headers_lower:
                auth_parts = [x.strip() for x in headers_lower["www-authenticate"].split(",")]
                possible_lines = []
                for idx, val in enumerate(auth_parts):
                    upval = val.upper()
                    if upval.startswith("NTLM") or upval.startswith("BASIC") or upval.startswith("NEGOTIATE"):
                        if idx+1 < len(auth_parts) and re.match(r'^[A-Za-z0-9+/=]+$', auth_parts[idx+1]):
                            possible_lines.append(val + " " + auth_parts[idx+1])
                        else:
                            possible_lines.append(val)
                    else:
                        possible_lines.append(val)

                for line in possible_lines:
                    if line.upper().startswith("BASIC") and scheme == "http":
                        basic_http_exposed = True

                ntlm_present = any(line.upper().startswith("NTLM") for line in possible_lines)
                if ntlm_present and do_auth:
                    type1_msg = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
                    r2 = requests.get(full_url,
                                      headers={"Authorization": f"NTLM {type1_msg}"},
                                      verify=False, timeout=timeout)
                    www_auth_2 = r2.headers.get("WWW-Authenticate", "")
                    if "NTLM " in www_auth_2:
                        matches = re.findall(r"NTLM\s+([A-Za-z0-9+/=]+)", www_auth_2)
                        if matches:
                            type2_b64 = matches[0]
                            parsed = parse_ntlm_type2_blob(type2_b64)
                            ntlm_info.update(parsed)

            return (p, sc, found_headers, ntlm_info, basic_http_exposed)
        except requests.exceptions.RequestException as e:
            return (p, f"ERROR: {str(e)}", {}, {}, False)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=http_threads) as executor:
        future_map = {executor.submit(worker, p): p for p in paths}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            results.append(res)
    return results

# ---------------------------------------------------------------------
# 9. HELPER: chunk_list for printing
# ---------------------------------------------------------------------
def chunk_list(items, n=4):
    """Yield successive n-sized chunks from items."""
    for i in range(0, len(items), n):
        yield items[i:i+n]

# ---------------------------------------------------------------------
# 10. MAIN SCRIPT
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ExRay Web - Exchange enumerator with domain brute force, DNS concurrency, HTTP concurrency, wildcard detection, and O365 reporting. (v1.0)"
    )
    parser.add_argument("-t", "--target", help="Single target, e.g. 'mail.example.com'.")
    parser.add_argument("-l", "--list", help="File with one target per line.")
    parser.add_argument("--domain", help="Brute force subdomains for e.g. 'target.com'.")
    parser.add_argument("--dns-threads", type=int, default=100,
                        help="Number of parallel DNS lookups (default=100).")
    parser.add_argument("--http-threads", type=int, default=5,
                        help="Number of parallel HTTP requests (per target) for path enumeration (default=5).")
    parser.add_argument("--http-only", "-H", action="store_true", help="Only check http://")
    parser.add_argument("--https-only", "-S", action="store_true", help="Only check https://")
    parser.add_argument("--no-preflight", action="store_true",
                        help="Skip port check (requires --http-only or --https-only).")
    parser.add_argument("--no-auth", action="store_true",
                        help="Do NOT attempt dummy NTLM authentication if server responds with NTLM.")
    parser.add_argument("-o", "--output", help="Base filename for output (without file extension).")
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

    # (B) Multiple targets from file
    if args.list:
        lines = []
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                lines = [x.strip() for x in f if x.strip()]
        except Exception as e:
            print(f"[!] Error reading target list file: {e}")
            sys.exit(1)
        for line in lines:
            expanded = parse_target(line, args.http_only, args.https_only)
            final_targets.update(expanded)
        print(f'[+] Loaded {len(lines)} raw target(s) from "{args.list}".')

    # -----------------------------------------------------------------
    # (C) Domain-based subdomain brute force with parallel DNS
    # -----------------------------------------------------------------
    discovered_targets = set()
    if args.domain:
        domain = args.domain.strip()
        print(f"\n[+] Performing subdomain brute force for domain: {domain}")
        subs = generate_subdomain_variants()
        subdomains = [f"{s}.{domain}" for s in subs]
        total_subs = len(subdomains)
        progress_points = {10, 20, 30, 40, 50, 60, 70, 80, 90}

        fqdn_to_ips = {}
        max_dns_threads = args.dns_threads
        print(f"[!] DNS concurrency: using {max_dns_threads} parallel DNS threads.")

        # New: Set for O365 detected hosts
        global o365_detected
        o365_detected = set()

        completed_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_dns_threads) as executor:
            future_to_fqdn = {executor.submit(dns_resolve_all, fqdn): fqdn for fqdn in subdomains}
            for future in concurrent.futures.as_completed(future_to_fqdn):
                completed_count += 1
                fqdn = future_to_fqdn[future]
                pct = int((completed_count / total_subs) * 100)
                if pct in progress_points:
                    print(f"  ... {pct}% of subdomain brute force completed.")
                    progress_points.remove(pct)
                iplist = future.result()
                fqdn_to_ips[fqdn] = iplist

        discovered_count = 0
        for fqdn, iplist in sorted(fqdn_to_ips.items()):
            if not iplist:
                continue  # no IPs => skip

            # Check if subdomain is O365; if so, record it and skip further processing
            sub_urls = parse_target(fqdn, args.http_only, args.https_only)
            is_sub_o365 = False
            for surl in sub_urls:
                ssch, shost, _ = extract_host_port(surl)
                if is_o365_redirect(shost, scheme=ssch):
                    print(f"  [O365 detected] {fqdn} => skipping subdomain + IPs.")
                    is_sub_o365 = True
                    o365_detected.add(fqdn)
                    break
            if is_sub_o365:
                continue

            discovered_count += 1
            for su in sub_urls:
                final_targets.add(su)
                discovered_targets.add(su)

            for ip in iplist:
                ip_urls = parse_target(ip, args.http_only, args.https_only)
                skip_ip = False
                for iurl in ip_urls:
                    iu_sch, iu_host, _ = extract_host_port(iurl)
                    if is_o365_redirect(iu_host, scheme=iu_sch):
                        print(f"  [O365 detected] {ip} => skipping IP.")
                        skip_ip = True
                        o365_detected.add(ip)
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

    # Separate HTTP vs HTTPS targets
    http_list = []
    https_list = []
    for ut in unique_targets:
        sch, _, _ = extract_host_port(ut)
        if sch == "http":
            http_list.append(ut)
        else:
            https_list.append(ut)

    # Preflight checks (if not skipped)
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

    # SCAN each target
    for tgt in to_scan:
        print(f"=== Checking target: {tgt} ===")
        do_auth = not args.no_auth
        results = check_paths(tgt, EXCHANGE_PATHS, timeout=10, do_auth=do_auth, http_threads=args.http_threads)
        per_target_summary[tgt] = results
        for (path, code, found_headers, ntlm_info, basic_http_exposed) in results:
            print(f" {path} -> {code}")
            cstr = str(code) if isinstance(code, int) else code
            output_data.append(f"{tgt} | {path} | {cstr}")
            if tgt not in extracted_info["hosts"]:
                extracted_info["hosts"][tgt] = {"headers": [], "ntlm_domains": set(), "basic_http_exposed": False}
            if found_headers:
                extracted_info["hosts"][tgt]["headers"].append(found_headers)
            if ntlm_info.get("ntlm_domain"):
                extracted_info["hosts"][tgt]["ntlm_domains"].add(ntlm_info["ntlm_domain"])
            if basic_http_exposed:
                extracted_info["hosts"][tgt]["basic_http_exposed"] = True
        print()

    skipped = set(unique_targets) - set(to_scan)
    if skipped:
        print("=== Skipped Targets (Due to closed ports or other reason) ===")
        for st in sorted(skipped):
            print(f"  {st}")
        print()

    # -----------------------------------------------------------------
    # Final Summary: Per-Target Endpoints and Wildcard Detection
    # -----------------------------------------------------------------
    all_valid_endpoints = []
    wildcard_threshold = 0.80
    interesting_codes = [200, 301, 302, 401, 403]

    print("\n=== Per-Target Summary of Identified (Potentially Valid) Endpoints ===")
    for tgt in sorted(per_target_summary.keys()):
        results = per_target_summary[tgt]
        if not results:
            print(f"\nTarget: {tgt}\n  No results (empty?).")
            continue
        int_codes = [c for (_, c, _, _, _) in results if isinstance(c, int)]
        if not int_codes:
            print(f"\nTarget: {tgt}\n  No valid HTTP codes (all errors?).")
            continue
        c = Counter(int_codes)
        most_common_code, cnt_most_common = c.most_common(1)[0]
        total_count = len(int_codes)
        ratio = cnt_most_common / total_count
        print(f"\nTarget: {tgt}")
        if ratio >= wildcard_threshold:
            pct_str = round(ratio * 100, 2)
            print(f"  => {cnt_most_common} of {total_count} probed paths responded with HTTP {most_common_code} ({pct_str}%). Possible wildcard/catch-all behavior.")
            outliers = [(p, code) for (p, code, _, _, _) in results if isinstance(code, int) and code != most_common_code and code in interesting_codes]
            if outliers:
                print("  However, these path(s) returned a different interesting code:")
                for (p, code) in outliers:
                    print(f"    {p} -> {code}")
                    all_valid_endpoints.append((tgt, p, code))
            else:
                print("  No outlier paths returned a different interesting code.")
        else:
            any_found = False
            for (path, code, _, _, _) in results:
                if isinstance(code, int) and code in interesting_codes:
                    print(f"  Found: {path} (HTTP {code})")
                    all_valid_endpoints.append((tgt, path, code))
                    any_found = True
            if not any_found:
                print("  No interesting endpoints discovered (or all were different codes).")

    print("\n=== Final Overall Summary (All Targets Combined) ===")
    if all_valid_endpoints:
        for (tgt, path, code) in all_valid_endpoints:
            print(f"  {tgt} -> {path} (HTTP {code})")
    else:
        print("  No potentially valid endpoints found across all targets.")

    # -----------------------------------------------------------------
    # Consolidated Summary: Headers, NTLM Domains, Basic Auth & O365 Detection
    # -----------------------------------------------------------------
    print("\n=== Consolidated Summary of Discovered Header Values, NTLM Domains, Basic HTTP Exposure, and O365 Detection ===")
    header_presence = defaultdict(lambda: defaultdict(set))
    ntlm_presence = defaultdict(set)
    basic_http_hosts = set()

    for tgt, info in extracted_info["hosts"].items():
        if info["basic_http_exposed"]:
            basic_http_hosts.add(tgt)
        for hdr_dict in info["headers"]:
            for hdr_name, hdr_val in hdr_dict.items():
                if hdr_name.lower() == "x-owa-version":
                    mapped = map_owa_version(hdr_val)
                    if mapped:
                        hdr_val = f"{hdr_val} (Mapped: {mapped})"
                header_presence[hdr_name][hdr_val].add(tgt)
        for dmn in info["ntlm_domains"]:
            if dmn.strip():
                ntlm_presence[dmn].add(tgt)

    if header_presence:
        print("\n--- Headers Found Across All Hosts ---")
        for hdr_name in sorted(header_presence.keys()):
            print(f"\n  [Header: {hdr_name}]")
            for val, hosts_set in header_presence[hdr_name].items():
                hosts_list = sorted(hosts_set)
                total_hosts = len(hosts_list)
                print(f"    Value: '{val}' (Found on {total_hosts} host{'s' if total_hosts>1 else ''}):")
                for chunk in chunk_list(hosts_list, 4):
                    print("      " + ", ".join(chunk))
    else:
        print("\nNo interesting headers discovered across any hosts.")

    if ntlm_presence:
        print("\n--- NTLM Domains Discovered (Type2 Challenge) ---")
        for dmn, hosts_set in ntlm_presence.items():
            hosts_list = sorted(hosts_set)
            total_hosts = len(hosts_list)
            print(f"  Domain: {dmn} (Found on {total_hosts} host{'s' if total_hosts>1 else ''}):")
            for chunk in chunk_list(hosts_list, 4):
                print("    " + ", ".join(chunk))
    else:
        print("\nNo NTLM domains discovered.")

    if basic_http_hosts:
        print("\n--- Hosts Offering BASIC Auth Over Plain HTTP (Insecure) ---")
        for chunk in chunk_list(sorted(basic_http_hosts), 4):
            print("  " + ", ".join(chunk))
    else:
        print("\nNo hosts were found offering Basic auth over plain HTTP.")

    if o365_detected:
        print("\n--- O365 Detected Hosts ---")
        o365_list = sorted(o365_detected)
        print(f"  Detected on {len(o365_list)} host{'s' if len(o365_list)>1 else ''}:")
        for chunk in chunk_list(o365_list, 4):
            print("  " + ", ".join(chunk))
    else:
        print("\nNo O365 hosts detected.")

    print("\nDone. (v1.0)\n")

    # -----------------------------------------------------------------
    # Write Output Files (if requested)
    # -----------------------------------------------------------------
    if args.output:
        text_filename = f"{args.output}.txt"
        json_filename = f"{args.output}.json"
        try:
            with open(text_filename, "w", encoding="utf-8") as out_f:
                for line in output_data:
                    out_f.write(line + "\n")
            print(f"[+] Plain results written to: {text_filename}")
        except Exception as e:
            print(f"[!] Error writing to {text_filename}: {e}")
        valid_endpoints_list = []
        for (tgt, path, code) in all_valid_endpoints:
            valid_endpoints_list.append({"target": tgt, "path": path, "code": code})
        headers_list = []
        for hdr_name in sorted(header_presence.keys()):
            for val, hosts_set in header_presence[hdr_name].items():
                headers_list.append({"header": hdr_name, "value": val, "count": len(hosts_set), "hosts": sorted(hosts_set)})
        ntlm_list = []
        for dmn, hosts_set in ntlm_presence.items():
            ntlm_list.append({"domain": dmn, "count": len(hosts_set), "hosts": sorted(hosts_set)})
        basic_http_exposed_list = sorted(basic_http_hosts)
        o365_detected_list = sorted(o365_detected)
        json_data = {
            "valid_endpoints": valid_endpoints_list,
            "headers": headers_list,
            "ntlm_domains": ntlm_list,
            "basic_http_exposure": basic_http_exposed_list,
            "o365_detected": o365_detected_list
        }
        try:
            with open(json_filename, "w", encoding="utf-8") as out_f:
                json.dump(json_data, out_f, indent=2)
            print(f"[+] JSON summary written to: {json_filename}")
        except Exception as e:
            print(f"[!] Error writing to {json_filename}: {e}")

if __name__ == "__main__":
    main()

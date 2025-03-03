# ExRay – A Comprehensive Exchange Web Enumeration Script

**ExRay** is a Python-based tool for discovering and enumerating Microsoft Exchange endpoints. It uses subdomain brute forcing, parallel DNS resolution, port preflight checks, and wildcard detection to provide thorough coverage of on-prem and hybrid Exchange setups.

---

## Features

1. **Automated Subdomain Discovery**  
   - Generates typical Exchange-related names (`owa`, `mail`, `autodiscover`, etc.) with numeric/environment suffixes.  
   - Runs DNS resolution **in parallel** to speed up large-scale scans.  

2. **Office 365 Detection**  
   - Skips subdomains that redirect to O365 (e.g., `*.outlook.com`, `*.office365.com`).  

3. **Optional Port Preflight**  
   - Checks if HTTP/HTTPS ports are actually open before enumerating.  

4. **Exchange Path Enumeration**  
   - Scans a wide range of known Exchange endpoints (OWA, ECP, EWS, MAPI, etc.).  

5. **Wildcard Response Detection**  
   - If 80% or more of the paths return the same status code (e.g., `HTTP 200`), flags it as a catch-all and skips listing every path.  

6. **Clear Summaries**  
   - Organized final output showing interesting endpoints (HTTP 200, 301, 302, 401, 403) or wildcard warnings.  

---

## Installation

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/0xB455/ExRay.git
   cd ExRay
   ```

2. **Install Dependencies**  
   - **Python 3** is required.  
   - Install needed libraries (such as `requests`):  
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Script**  
   ```bash
   python3 ExRay.py --help
   ```

---

## Usage

Below are some examples demonstrating how to run **ExRay** against `example.com`.

### 1. Subdomain Discovery
```bash
python3 ExRay.py --domain example.com
```
- Brute forces typical Exchange subdomains (e.g., `owa.example.com`, `mail01.example.com`), checks DNS in parallel (default 100 threads), and enumerates discovered hosts.

### 2. Custom DNS Threads
```bash
python3 ExRay.py --domain example.com --dns-threads 50
```
- Runs subdomain DNS lookups with **50** concurrent threads instead of the default **100**.

### 3. Single Target
```bash
python3 ExRay.py --target mail.example.com
```
- Checks both HTTP/HTTPS for `mail.example.com`, enumerates known Exchange endpoints, prints interesting results.

### 4. Multiple Targets from a File
```bash
python3 ExRay.py --list targets.txt
```
Where `targets.txt` might contain:
```
mail.example.com
owa.example.com
192.168.1.10
```

### 5. Skipping Port Checks
```bash
python3 ExRay.py --domain example.com --no-preflight --https-only
```
- Directly enumerates `https://...` paths without verifying port 443 is open first.

### 6. Write All Results to a File
```bash
python3 ExRay.py --domain example.com --output results.txt
```
- Logs every path request and status code to `results.txt`.

---

## Output Highlights

1. **Subdomain Enumeration**  
   - Shows how many subdomains resolved.  
   - Skips O365 endpoints if detected.

2. **Port Preflight**  
   - Reports how many hosts are listening on HTTP/HTTPS.  
   - Skips closed hosts.

3. **Enumeration**  
   - For each open host, checks dozens of Exchange endpoints, prints status codes.

4. **Wildcard Detection**  
   - If 80%+ of paths share the same status code, flags it with a line like:
     ```
     => 40 of 50 probed paths responded with HTTP 200 (80%).
        Possible wildcard/catch-all behavior.
     ```

5. **Final Summaries**  
   - Lists interesting endpoints (HTTP 200, 301, 302, 401, 403 by default).

---

## License

This project is licensed under the [MIT License](LICENSE).

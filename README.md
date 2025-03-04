# ExRay v1.0 – A Comprehensive Exchange Web Enumeration Script

**ExRay** is a Python-based tool for discovering and enumerating Microsoft Exchange endpoints (on-premise, hybrid, or partially migrated). It uses subdomain brute forcing, parallel DNS resolution, parallel HTTP requests, port preflight checks, NTLM handshake attempts, and wildcard detection to provide thorough coverage of Exchange services.

---

## Features

1. **Automated Subdomain Discovery**  
   - Generates typical Exchange-related hostnames (`owa`, `mail`, `autodiscover`, etc.) with numeric/environment suffixes.  
   - Resolves DNS **in parallel** (default `--dns-threads 100`) for fast scanning of large domains.  
   - Automatically **skips** subdomains that redirect to Office 365 (e.g., `*.outlook.com`, `*.office365.com`).

2. **Port Preflight (Optional)**  
   - Quickly checks if HTTP/HTTPS ports are open before doing in-depth enumeration.  
   - Can be **disabled** via `--no-preflight`, in which case the script tries all hosts/ports directly.

3. **Parallel HTTP Requests**  
   - Use `--http-threads` (default **5**) to control how many HTTP requests run **in parallel** per target. This speeds up the path enumeration on each host.

4. **Exchange Path Enumeration**  
   - Scans a wide range of known Exchange endpoints (OWA, ECP, EWS, MAPI, Autodiscover, etc.).  
   - Captures **interesting** headers like `Server`, `X-OWA-Version`, `X-FEServer`, etc.  
   - Decodes OWA build numbers to map probable **Exchange version** (e.g., Exchange 2013/2016/2019 or older).  

5. **NTLM Authentication Check**  
   - If `WWW-Authenticate: NTLM` is present, ExRay sends a **dummy Type 1** NTLM message to retrieve the **Type 2** challenge.  
   - Attempts to parse out the **NTLM domain** name from that challenge.  
   - Can be **skipped** using `--no-auth` if you don’t want to attempt NTLM handshakes.

6. **Detection of Basic Auth over HTTP**  
   - If the server offers `WWW-Authenticate: Basic` **on plain HTTP**, ExRay **warns** in the final summary.  

7. **Wildcard Response Detection**  
   - If 80%+ of enumerated paths return the same status code, ExRay flags it as **possible catch-all**.  
   - **Outlier** paths with “interesting” status codes (`200, 301, 302, 401, 403`) are **still** shown, even if the majority are a single code (e.g., `503`).

8. **Comprehensive Output**  
   - **Console Summaries**:  
     - Subdomain resolution results  
     - O365 detection/skip  
     - Wildcard detection warnings  
     - “Interesting” endpoints (HTTP 200/301/302/401/403)  
   - **File-Based Output** (when using `-o output`):  
     - **`output.txt`**: A plain-text line-by-line dump (`<host> | <path> | <status>`) for each request.  
     - **`output.json`**: A structured JSON containing:  
       - **valid_endpoints** (list of discovered interesting endpoints)  
       - **headers** (unique header values + which hosts sent them)  
       - **ntlm_domains** (NTLM Type2 domain info + which hosts exposed it)  
       - **basic_http_exposure** (hosts offering Basic auth over HTTP)  

---

## Installation

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/0xB455/ExRay.git
   cd ExRay
   ```

2. **Install Dependencies**  
   - **Python 3** is required.  
   - Install needed Python libraries (e.g., `requests`):
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Script**  
   ```bash
   python3 ExRay.py --help
   ```

---

## Usage Examples

Below are some typical ways to run **ExRay**:

1. **Subdomain Discovery**  
   ```bash
   python3 ExRay.py --domain example.com
   ```
   - Enumerates typical Exchange subdomains (`owa`, `mail01`, `autodiscover`, etc.).  
   - Checks DNS in parallel (`--dns-threads 100` by default).  
   - Automatically enumerates discovered hosts on HTTP/HTTPS.

2. **Customize DNS and HTTP Threads**  
   ```bash
   python3 ExRay.py --domain example.com --dns-threads 50 --http-threads 8
   ```
   - Uses **50** threads for DNS resolution and **8** threads per target for HTTP path scanning.

3. **Single Target**  
   ```bash
   python3 ExRay.py --target mail.example.com
   ```
   - Probes `http://mail.example.com` and `https://mail.example.com` with all known Exchange paths.

4. **Multiple Targets from File**  
   ```bash
   python3 ExRay.py --list targets.txt
   ```
   - Each line in `targets.txt` can be an IP, a hostname, or a full URL (e.g., `https://mail.example.com`).

5. **Port Preflight & Skipping**  
   ```bash
   python3 ExRay.py --domain example.com --no-preflight --https-only
   ```
   - Ignores port-check logic, enumerates everything as `https://...`.

6. **NTLM Handshake Skipping**  
   ```bash
   python3 ExRay.py --target mail.example.com --no-auth
   ```
   - Does **not** send a dummy NTLM request if `WWW-Authenticate: NTLM` is encountered.

7. **Generating Output Files**  
   ```bash
   python3 ExRay.py --domain example.com -o results
   ```
   - Writes line-based results to `results.txt` and JSON summary to `results.json`.

---

## Output Highlights

1. **Subdomain Enumeration**  
   - Shows how many subdomains resolved.  
   - Skips or flags O365-based hosts.

2. **Port Preflight** (optional)  
   - Reports how many hosts are open on HTTP/HTTPS.  
   - Ignores closed ports if `--no-preflight` is not specified.

3. **Path Enumeration**  
   - Sends **parallel** HTTP requests against known Exchange endpoints.  
   - Prints status codes for each path.  
   - Attempts a **dummy NTLM handshake** to discover internal domain (unless `--no-auth`).

4. **Wildcard Detection**  
   - If ≥80% share the same code, warns of possible catch-all.  
   - **Still** shows any outliers if they return an “interesting” code (200, 301, 302, 401, 403).

5. **Final Summaries**  
   - **Per-Target** summary of interesting endpoints.  
   - **Consolidated** summary of:  
     - **Headers** (e.g., `X-OWA-Version`, `X-FEServer`)  
     - **NTLM domains** discovered  
     - **Hosts** offering Basic Auth over HTTP (insecure)  

6. **File Exports**  
   - **`<output>.txt`**: Plain text lines of `<host> | <path> | <code>`.  
   - **`<output>.json`**: Structured JSON with full details on discovered endpoints, headers, NTLM domains, and insecure Basic.

---

## License

This project is licensed under the [MIT License](LICENSE). Feel free to modify and extend it for your own engagements.

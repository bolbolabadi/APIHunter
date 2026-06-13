#!/usr/bin/env python3
"""
APIHunter - API Reconnaissance & Route Fuzzing Tool
Phase 1: Discover Swagger/OpenAPI docs, Postman collections, GraphQL, etc.
Phase 2: Fuzz routes using discovered specs + built-in wordlists.

DISCLAIMER: This tool is intended for authorized security testing only.
Always obtain explicit permission before scanning any target you do not own.
"""

import argparse
import asyncio
import json
import random
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

# ──────────────────────────── COLORS ────────────────────────────

class C:
    GRN = "\033[92m"
    YEL = "\033[93m"
    RED = "\033[91m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    BOLD = "\033[1m"
    RST = "\033[0m"

# ──────────────────────────── CONFIG ────────────────────────────

TIMEOUT = ClientTimeout(total=15)
CONCURRENCY = 30
DEFAULT_HEADERS = {
    "User-Agent": "APIHunter/1.0 (Security Research)",
    "Accept": "application/json,*/*",
}
# Mutable headers updated by CLI -H flags
HEADERS = dict(DEFAULT_HEADERS)
# Populated from user-agents.txt when --random-agent is used
USER_AGENTS = []
RANDOM_AGENT = False

# Exclusion list for JS files (skip common libraries)
JS_EXCLUSION_LIST = {"jquery", "google-analytics", "gpt.js", "react", "vue", "angular",
                     "lodash", "moment", "bootstrap", "fontawesome", "analytics"}

WORDLISTS_DIR = "wordlists"

# Common route patterns to generate dynamically
ROUTE_PATTERNS = [
    "api/{ver}/{path}", "api/{path}", "v1/{path}", "v2/{path}", "v3/{path}",
    "rest/{path}", "service/{path}", "{path}", "internal/{path}",
    "admin/{path}", "public/{path}", "mobile/{path}", "web/{path}",
]

# ──────────────────────────── UTILS ────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def load_txt_files_from_dir(dir_path: Path) -> set:
    """Load all lines from all .txt files in a directory."""
    items = set()
    if not dir_path.exists():
        return items
    for fpath in dir_path.glob("*.txt"):
        try:
            with open(fpath, "r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.add(line)
        except Exception:
            pass
    return items


def load_wordlists(base_dir: Path) -> set:
    """Load route fuzzing wordlists from wordlists/routes/*.txt"""
    routes_dir = base_dir / WORDLISTS_DIR / "routes"
    routes = load_txt_files_from_dir(routes_dir)
    # Normalize: strip leading slashes
    return {r.lstrip("/") for r in routes if r}


def load_discovery_paths(base_dir: Path) -> list:
    """Load doc discovery paths from wordlists/docs/*.txt"""
    docs_dir = base_dir / WORDLISTS_DIR / "docs"
    paths = load_txt_files_from_dir(docs_dir)
    # Normalize: ensure leading slash
    return sorted({"/" + p.lstrip("/") for p in paths if p})


def load_user_agents(base_dir: Path) -> list:
    """Load user-agents.txt lines."""
    fpath = base_dir / "user-agents.txt"
    agents = []
    if not fpath.exists():
        return agents
    try:
        with open(fpath, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    agents.append(line)
    except Exception:
        pass
    return agents


def extract_routes_from_openapi(text: str) -> set:
    """Naive regex-based route extraction from JSON/YAML OpenAPI text."""
    routes = set()
    pattern = re.compile(r'"(/[^"{}\[\]]+)"\s*:', re.IGNORECASE)
    for m in pattern.finditer(text):
        r = m.group(1).strip()
        if " " not in r:
            routes.add(r.lstrip("/"))
    return routes


def extract_routes_from_jsmap(text: str) -> set:
    """Extract potential routes from a JS source-map JSON or JS bundle text."""
    routes = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not valid JSON; try regex on raw text anyway
        data = None

    if isinstance(data, dict):
        # Extract from sources array (webpack:///src/api/user.js -> api/user)
        for src in data.get("sources", []):
            # remove webpack:///, ng:///, etc.
            clean = re.sub(r'^\w+://+', '', src)
            # grab path segments that look like api/service/file
            parts = clean.split('/')
            for i in range(len(parts) - 1):
                if parts[i] in ("api", "rest", "services", "service", "v1", "v2", "v3"):
                    candidate = '/'.join(parts[i:]).replace('.js', '').replace('.ts', '')
                    routes.add(candidate.lstrip('/'))
            # Also grab anything with api/ in the path
            if "api/" in clean or "service/" in clean:
                cand = clean.split('api/')[-1].split('service/')[-1].replace('.js', '').replace('.ts', '')
                if cand:
                    routes.add(cand.lstrip('/'))

        # sourcesContent may contain fetch/axios calls with URLs
        for content in data.get("sourcesContent", []):
            if not isinstance(content, str):
                continue
            # Look for string literals that look like routes
            for m in re.finditer(r'["\'](/[a-zA-Z0-9_/-]+)["\']', content):
                r = m.group(1).strip()
                if len(r) > 2 and " " not in r:
                    routes.add(r.lstrip('/'))
            # Look for template literals e.g. `/api/v1/${id}`
            for m in re.finditer(r'`(/[a-zA-Z0-9_/${}-]+)`', content):
                r = m.group(1).strip()
                routes.add(r.lstrip('/').replace('${', '').replace('}', ''))

    # Fallback regex for raw text / non-JSON
    raw = text if data is None else json.dumps(data)
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_/-]+)["\']', raw):
        r = m.group(1).strip()
        if len(r) > 2 and " " not in r:
            routes.add(r.lstrip('/'))

    return routes


def extract_sourcemap_url(text: str, base_url: str) -> str | None:
    """Extract sourceMappingURL from a JS file and resolve to absolute URL."""
    m = re.search(r'//#\s*sourceMappingURL=([^\s\n]+)', text)
    if m:
        url = m.group(1).strip()
        if url.startswith('http'):
            return url
        return urllib.parse.urljoin(base_url + '/', url.lstrip('/'))
    return None


# LinkFinder / BurpJSLinkFinder inspired regex
_LINKFINDER_RE = re.compile(
    r"""
    (?:"|')                               # Start delimiter
    (
      ((?:[a-zA-Z]{1,10}://|//)          # scheme or //
      [^"'/]{1,}\.
      [a-zA-Z]{2,}[^"']{0,})              # domain + path

      |

      ((?:/|\.\./|\./)                    # Start with /, ../, ./
      [^"'><,;| *()(%$^/\\\[\]]
      [^"'><,;|()]{1,})                   # Rest

      |

      ([a-zA-Z0-9_\-/]{1,}/              # Relative endpoint with /
      [a-zA-Z0-9_\-/]{1,}
      \.(?:[a-zA-Z]{1,4}|action)          # extension
      (?:[\?|#][^"|']{0,}|))              # query/fragment

      |

      ([a-zA-Z0-9_\-/]{1,}/              # REST API (no extension) with /
      [a-zA-Z0-9_\-/]{3,}                # 3+ chars
      (?:[\?|#][^"|']{0,}|))             # query/fragment

      |

      ([a-zA-Z0-9_\-]{1,}                # filename
      \.(?:php|asp|aspx|jsp|json|
           action|html|js|txt|xml)
      (?:[\?|#][^"|']{0,}|))             # query/fragment
    )
    (?:"|')                               # End delimiter
    """,
    re.VERBOSE,
)

# Additional patterns for modern frameworks
_EXTRA_JS_PATTERNS = [
    # fetch("/api/users"), axios.get('/api/users'), $.ajax({url: '/api/users'})
    re.compile(r'(?:fetch|axios\.\w+|\.ajax)\s*\(\s*["\'](/[a-zA-Z0-9_/$\-{}]+)["\']'),
    # route: '/api/users', path: '/api/users', url: '/api/users'
    re.compile(r'(?:route|path|url)\s*[:=]\s*["\'](/[a-zA-Z0-9_/$\-{}]+)["\']'),
    # React/Vue Router: { path: '/users' }
    re.compile(r'\bpath\s*:\s*["\'](/[a-zA-Z0-9_/$\-{}]+)["\']'),
    # template literals: `/api/v1/${id}`
    re.compile(r'`(/[a-zA-Z0-9_/${}\-]+)`'),
    # webpack chunk names / dynamic imports
    re.compile(r'import\s*\(\s*["\'](/[a-zA-Z0-9_/$\-{}]+)["\']\s*\)'),
]


def extract_routes_from_js_linkfinder(text: str) -> set:
    """Extract endpoints from raw JS using LinkFinder regex + modern framework patterns."""
    routes = set()
    for m in _LINKFINDER_RE.finditer(text):
        link = m.group(1)
        if not link:
            continue
        # Skip if it's a full external URL (not our target)
        if re.match(r'^[a-zA-Z]{1,10}://', link):
            # Keep only if it looks like an API endpoint on same domain
            parsed = urllib.parse.urlparse(link)
            if parsed.path and parsed.path.startswith('/'):
                link = parsed.path
            else:
                continue
        # Normalize
        if link.startswith('/'):
            link = link[1:]
        # Skip empty or too short
        if len(link) < 2:
            continue
        # Skip common false positives
        if any(link.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf', '.eot']):
            continue
        # Clean query/fragment
        link = link.split('?')[0].split('#')[0]
        routes.add(link)

    # Extra modern framework patterns
    for pat in _EXTRA_JS_PATTERNS:
        for m in pat.finditer(text):
            link = m.group(1)
            if not link:
                continue
            link = link.replace('${', '').replace('}', '')
            if link.startswith('/'):
                link = link[1:]
            if len(link) >= 2:
                routes.add(link)

    return routes


def is_js_excluded(url: str) -> bool:
    """Check if a JS URL should be excluded (common libraries)."""
    url_lower = url.lower()
    return any(exc in url_lower for exc in JS_EXCLUSION_LIST)


# ──────────────────────────── NETWORK ────────────────────────────

async def fetch(session: aiohttp.ClientSession, url: str) -> tuple:
    req_headers = dict(HEADERS)
    if RANDOM_AGENT and USER_AGENTS:
        req_headers["User-Agent"] = random.choice(USER_AGENTS)
    try:
        async with session.get(url, headers=req_headers, allow_redirects=False) as resp:
            body = await resp.text()
            return resp.status, len(body), body
    except asyncio.TimeoutError:
        return -1, 0, ""
    except Exception:
        return -2, 0, ""


async def probe_paths(session, base_url, paths, semaphore, results, kind="doc"):
    # Calibrate soft-404 first
    calib = await _calibrate_soft404(session, base_url)
    calib_counter = Counter(calib)
    most_common = calib_counter.most_common(1)
    catch_all_status = catch_all_length = None
    if most_common and most_common[0][1] >= 2:
        catch_all_status, catch_all_length = most_common[0][0][0], most_common[0][0][1]
        print(f"  {C.YEL}[~]{C.RST} Detected catch-all behavior: {catch_all_status} / {catch_all_length}b (soft-404 calibration)")

    tasks = []
    for p in paths:
        url = f"{base_url}{p}"
        tasks.append((p, url))

    async def one(path, url):
        async with semaphore:
            status, length, body = await fetch(session, url)
            return path, status, length, body

    coros = [one(p, u) for p, u in tasks]
    raw_hits = []
    for fut in asyncio.as_completed(coros):
        path, status, length, body = await fut
        if status in (200, 201, 401, 403, 405):
            # Heuristic: skip 403s that look like WAF blocks (very short)
            if status == 403 and length < 50:
                continue
            # Filter exact catch-all matches
            if catch_all_status is not None and status == catch_all_status and length == catch_all_length:
                continue
            raw_hits.append((path, status, length, body))

    # Additional soft-404 suppression: if many hits share identical (status, length), treat as noise
    combo_counts = Counter((status, length) for _, status, length, _ in raw_hits)
    total_hits = len(raw_hits)
    noisy_threshold = max(5, len(paths) // 200, total_hits // 10)

    # Aggressive fallback: if >80% of hits are identical, it's definitely a catch-all
    if total_hits > 0:
        most_common_combo, most_common_count = combo_counts.most_common(1)[0]
        if most_common_count / total_hits >= 0.8:
            noisy_threshold = min(noisy_threshold, most_common_count)
            print(f"  {C.YEL}[~]{C.RST} Aggressive catch-all detected: {most_common_count}/{total_hits} hits are {most_common_combo[0]}/{most_common_combo[1]}b")

    suppressed = 0
    for path, status, length, body in raw_hits:
        if combo_counts[(status, length)] >= noisy_threshold:
            suppressed += 1
            continue
        results.append({
            "url": f"{base_url}{path}",
            "status": status,
            "length": length,
            "kind": kind,
            "body_preview": body[:200].replace("\n", " "),
        })
        color = C.GRN if status in (200, 201) else C.YEL if status in (401, 403) else C.BLU
        print(f"  {color}[+]{C.RST} [{color}{status}{C.RST}] {base_url}{path} ({length}b)")

    if suppressed:
        print(f"  {C.YEL}[~]{C.RST} Suppressed {suppressed} likely false-positive hits (identical status+length)")


async def _calibrate_soft404(session, base_url, count=3):
    """Probe random non-existent paths to detect catch-all pages."""
    import uuid
    fingerprints = []
    for _ in range(count):
        noise = str(uuid.uuid4())
        url = f"{base_url}/{noise}"
        status, length, body = await fetch(session, url)
        fingerprints.append((status, length, body[:200]))
    return fingerprints


async def fuzz_routes(session, base_url, routes, semaphore, results):
    # ─── Calibrate soft-404 fingerprints ───
    calib = await _calibrate_soft404(session, base_url)
    calib_counter = Counter(calib)
    most_common = calib_counter.most_common(1)
    catch_all_status = catch_all_length = None
    if most_common and most_common[0][1] >= 2:
        catch_all_status, catch_all_length = most_common[0][0][0], most_common[0][0][1]
        print(f"  {C.YEL}[~]{C.RST} Detected catch-all behavior: {catch_all_status} / {catch_all_length}b (soft-404 calibration)")

    async def one(route):
        async with semaphore:
            url = f"{base_url}/{route}"
            status, length, body = await fetch(session, url)
            if status in (200, 201, 401, 403, 405, 500):
                if status == 403 and length < 50:
                    return None
                # Filter exact catch-all matches immediately
                if catch_all_status is not None and status == catch_all_status and length == catch_all_length:
                    return None
                return {
                    "url": url,
                    "status": status,
                    "length": length,
                    "route": route,
                }
            return None

    coros = [one(r) for r in routes]
    raw_hits = []
    for fut in asyncio.as_completed(coros):
        res = await fut
        if res:
            raw_hits.append(res)

    # ─── Soft-404 / noise suppression ───
    # Group hits by (status, length). If a group is huge it's likely a WAF/default page.
    combo_counts = Counter((h["status"], h["length"]) for h in raw_hits)
    total_hits = len(raw_hits)
    # Dynamic threshold: if >10% of all hits share the same (status, length), it's noise
    noisy_threshold = max(5, len(routes) // 200, total_hits // 10)

    # Aggressive fallback: if >80% of hits are identical, it's definitely a catch-all
    if total_hits > 0:
        most_common_combo, most_common_count = combo_counts.most_common(1)[0]
        if most_common_count / total_hits >= 0.8:
            noisy_threshold = min(noisy_threshold, most_common_count)
            print(f"  {C.YEL}[~]{C.RST} Aggressive catch-all detected: {most_common_count}/{total_hits} hits are {most_common_combo[0]}/{most_common_combo[1]}b")

    suppressed = 0
    results_before = len(results)
    for h in raw_hits:
        key = (h["status"], h["length"])
        if combo_counts[key] >= noisy_threshold:
            # Any response (including 200) with identical (status, length) is likely a soft-404 / catch-all
            suppressed += 1
            continue
        results.append(h)

    if suppressed:
        print(f"  {C.YEL}[~]{C.RST} Suppressed {suppressed} likely false-positive hits (identical status+length)")

    # ─── Print survivors ───
    for h in results[results_before:]:
        s = h["status"]
        color = C.GRN if s in (200, 201) else C.YEL if s in (401, 403) else C.BLU if s == 405 else C.RED
        print(f"  {color}[FUZZ]{C.RST} [{color}{s}{C.RST}] {h['url']} ({h['length']}b)")

    return len(results) - results_before


# ──────────────────────────── MAIN ────────────────────────────

async def scan_target(session, base_url: str, script_dir: Path, semaphore, args):
    """Scan a single target. Returns (results_list, discovered_routes_set)."""
    all_results = []
    discovered_routes = set()

    # ─── Phase 1: Discovery ───
    if args.mode in ("all", "docs"):
        discovery_paths = load_discovery_paths(script_dir)
        if not discovery_paths:
            print(f"{C.YEL}[!]{C.RST} No discovery paths loaded from {WORDLISTS_DIR}/docs/")
        else:
            print(f"{C.CYN}[*]{C.RST} Phase 1: Discovering docs on {C.BOLD}{base_url}{C.RST} ({len(discovery_paths)} paths)")
            await probe_paths(session, base_url, discovery_paths, semaphore, all_results, kind="doc")

        # Parse discovered OpenAPI/Swagger bodies for routes
        for item in all_results:
            if item["kind"] != "doc":
                continue
            url = item["url"]
            if any(x in url.lower() for x in ["swagger", "openapi", "api-docs"]):
                _, _, full_body = await fetch(session, url)
                extracted = extract_routes_from_openapi(full_body)
                if extracted:
                    print(f"  {C.CYN}[PARSE]{C.RST} Extracted {C.BOLD}{len(extracted)}{C.RST} routes from {url}")
                    discovered_routes.update(extracted)

        # Also look for sourceMappingURL references inside discovered JS files
        extra_maps = []
        for item in all_results:
            url = item["url"]
            if url.endswith(".js"):
                if is_js_excluded(url):
                    print(f"  {C.YEL}[~]{C.RST} Skipped excluded JS: {url}")
                    continue
                _, _, js_body = await fetch(session, url)
                map_url = extract_sourcemap_url(js_body, base_url)
                if map_url:
                    extra_maps.append(map_url)

        for map_url in set(extra_maps):
            _, _, map_body = await fetch(session, map_url)
            if len(map_body) > 50:
                all_results.append({
                    "url": map_url,
                    "status": 200,
                    "length": len(map_body),
                    "kind": "jsmap",
                    "body_preview": map_body[:200].replace("\n", " "),
                })
                print(f"  {C.MAG}[+]{C.RST} [{C.MAG}200{C.RST}] {map_url} (from sourceMappingURL)")

        # Parse .js.map entries
        for item in all_results:
            url = item["url"]
            if url.endswith(".js.map"):
                _, _, full_body = await fetch(session, url)
                extracted = extract_routes_from_jsmap(full_body)
                if extracted:
                    print(f"  {C.CYN}[PARSE]{C.RST} Extracted {C.BOLD}{len(extracted)}{C.RST} routes from JS map {url}")
                    discovered_routes.update(extracted)

        # Parse raw JS files with LinkFinder-style regex
        for item in all_results:
            url = item["url"]
            if not url.endswith(".js") or is_js_excluded(url):
                continue
            _, _, js_body = await fetch(session, url)
            extracted = extract_routes_from_js_linkfinder(js_body)
            if extracted:
                print(f"  {C.CYN}[PARSE]{C.RST} LinkFinder extracted {C.BOLD}{len(extracted)}{C.RST} routes from {url}")
                discovered_routes.update(extracted)

    # ─── Phase 2: Fuzzing ───
    if args.mode in ("all", "routes"):
        print(f"{C.CYN}[*]{C.RST} Phase 2: Loading wordlists...")
        wordlist_routes = load_wordlists(script_dir)
        print(f"  Loaded {C.BOLD}{len(wordlist_routes)}{C.RST} route candidates from wordlists")

        # Expand with generated patterns
        print("  Generating route permutations...")
        expanded = set()
        versions = ["v1", "v2", "v3", "v4", "1", "2", "3"]
        for r in list(wordlist_routes)[:args.max_routes]:
            expanded.add(r)
            for pat in ["api/{path}", "api/{ver}/{path}", "{ver}/{path}", "rest/{path}", "internal/{path}"]:
                for ver in versions:
                    expanded.add(pat.replace("{ver}", ver).replace("{path}", r))
            if not r.endswith("s"):
                expanded.add(r + "s")

        all_routes = list(wordlist_routes | discovered_routes | expanded)
        all_routes = sorted(set(all_routes))[:args.max_routes]
        print(f"  Total unique routes to fuzz: {C.BOLD}{len(all_routes)}{C.RST}")

        print(f"{C.CYN}[*]{C.RST} Phase 2: Fuzzing {C.BOLD}{base_url}{C.RST} ...")
        found_count = await fuzz_routes(session, base_url, all_routes, semaphore, all_results)
        print(f"{C.CYN}[*]{C.RST} Fuzzing complete. Found {C.BOLD}{found_count}{C.RST} potential endpoints.")

    return all_results, discovered_routes


async def main():
    parser = argparse.ArgumentParser(description="APIHunter - Discover & Fuzz API routes")
    parser.add_argument("target", nargs="?", help="Target base URL or domain")
    parser.add_argument("-f", "--file", help="File with multiple targets (one per line)")
    parser.add_argument("-m", "--mode", choices=["all", "docs", "routes"], default="all",
                        help="Run mode: all (default), docs, or routes")
    parser.add_argument("-o", "--output", default="apihunter_results.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=CONCURRENCY, help="Concurrent requests")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header, e.g. -H 'Cookie: id=1' (repeatable)")
    parser.add_argument("--random-agent", action="store_true",
                        help="Rotate User-Agent from user-agents.txt on each request")
    parser.add_argument("--max-routes", type=int, default=50000, help="Max routes to fuzz")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable SSL certificate verification")
    args = parser.parse_args()

    # Validate target input
    if not args.target and not args.file:
        parser.error("Either provide a target or use -f/--file")
    if args.target and args.file:
        parser.error("Cannot use both target positional arg and -f/--file")

    # Gather targets
    targets = []
    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            parser.error(f"File not found: {args.file}")
        with open(fpath, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(normalize_url(line))
        if not targets:
            parser.error(f"No valid targets found in {args.file}")
    else:
        targets = [normalize_url(args.target)]

    # Apply custom headers
    for h in args.header:
        if ':' in h:
            key, val = h.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key and val:
                HEADERS[key] = val
            else:
                print(f"{C.YEL}[!]{C.RST} Invalid header format (expected 'Key: Value'): {h}")
        else:
            print(f"{C.YEL}[!]{C.RST} Invalid header format (expected 'Key: Value'): {h}")

    global RANDOM_AGENT, USER_AGENTS
    script_dir = Path(__file__).parent.resolve()
    if args.random_agent:
        USER_AGENTS = load_user_agents(script_dir)
        if USER_AGENTS:
            RANDOM_AGENT = True
            print(f"{C.CYN}[*]{C.RST} Loaded {len(USER_AGENTS)} user-agents for rotation")
        else:
            print(f"{C.YEL}[!]{C.RST} user-agents.txt not found, falling back to default UA")
    semaphore = asyncio.Semaphore(args.threads)

    connector = TCPConnector(ssl=not args.insecure, limit=100)
    async with aiohttp.ClientSession(
        connector=connector, timeout=TIMEOUT
    ) as session:
        for base_url in targets:
            print(f"\n{'='*60}")
            print(f"{C.CYN}{C.BOLD}  TARGET: {base_url}{C.RST}")
            print(f"{'='*60}")

            all_results, discovered_routes = await scan_target(
                session, base_url, script_dir, semaphore, args
            )

            # ─── Save results ───
            output = {
                "target": base_url,
                "results": all_results,
                "discovered_from_specs": sorted(discovered_routes),
            }
            # If multiple targets, prefix output filename with sanitized target
            out_name = args.output
            if len(targets) > 1:
                safe_target = base_url.replace("://", "_").replace("/", "_").replace(":", "_")
                out_name = f"{safe_target}_{args.output}"
            out_path = Path(out_name)
            with open(out_path, "w") as fh:
                json.dump(output, fh, indent=2, ensure_ascii=False)
            print(f"{C.CYN}[*]{C.RST} Results saved to {C.BOLD}{out_path}{C.RST}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)

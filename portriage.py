#!/usr/bin/env python3
"""
PorTriage — Scan. Rank. Fix first.
----------------------------------
Port scanner that finds open services with nmap, matches them against live
CVE and exploit data, and ranks what to fix first.

CVE Sources  : NIST NVD API v2  (full CVE database, free)
               OSV.dev API      (Google's open vuln database, free)
               Vulners API      (software/version lookups, needs a free API key)
Threat intel : CISA KEV catalog (CVEs known to be exploited in the wild, free)
               FIRST EPSS API   (probability of exploitation in the next 30 days, free)
Exploit DB   : searchsploit     (Exploit-DB offline mirror)
Reports      : terminal, JSON, CSV, self-contained HTML
Requires     : nmap, python-nmap, requests
               searchsploit  →  sudo apt install exploitdb
Install deps : pip install python-nmap requests
"""

import os
import sys
import csv
import html
import math
import shlex
import shutil
import socket
import subprocess
import ipaddress
import json
import re
import textwrap
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "2.0"

# ── Windows console support ───────────────────────────────────────────────────
if os.name == "nt":
    os.system("")  # enables ANSI escape processing in the Windows console
try:
    sys.stdout.reconfigure(errors="replace")  # don't crash on ✓ ⚡ ═ in non-UTF-8 consoles
except (AttributeError, ValueError):
    pass

UNICODE = (sys.stdout.encoding or "").lower().replace("-", "").startswith("utf")

# ── Dependency check ──────────────────────────────────────────────────────────
def check_deps():
    missing = []
    try:
        import nmap  # noqa: F401
    except ImportError:
        missing.append("python-nmap  →  pip install python-nmap")
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests     →  pip install requests")
    if not shutil.which("nmap"):
        missing.append("nmap         →  https://nmap.org/download.html  /  "
                       "sudo apt install nmap  /  brew install nmap")
    if missing:
        print("\n[!] Missing dependencies:\n")
        for m in missing:
            print(f"    {m}")
        sys.exit(1)

check_deps()

import nmap      # noqa: E402
import requests  # noqa: E402

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    DIM     = "\033[2m"

    @classmethod
    def disable(cls):
        for name in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "MAGENTA",
                     "WHITE", "BG_RED", "BOLD", "RESET", "DIM"):
            setattr(cls, name, "")

def red(t):     return f"{C.RED}{t}{C.RESET}"
def green(t):   return f"{C.GREEN}{t}{C.RESET}"
def yellow(t):  return f"{C.YELLOW}{t}{C.RESET}"
def blue(t):    return f"{C.BLUE}{t}{C.RESET}"
def cyan(t):    return f"{C.CYAN}{t}{C.RESET}"
def magenta(t): return f"{C.MAGENTA}{t}{C.RESET}"
def bold(t):    return f"{C.BOLD}{t}{C.RESET}"
def dim(t):     return f"{C.DIM}{t}{C.RESET}"
def alert(t):   return f"{C.BG_RED}{C.WHITE}{C.BOLD}{t}{C.RESET}"

def fit(text: str, width: int) -> str:
    """Truncate *text* to *width* characters, marking the cut with '…'."""
    return text if len(text) <= width else text[:max(0, width - 1)] + "…"

def pad(text: str, width: int, colour=lambda t: t) -> str:
    """Left-align *text* to *width* visible characters, then colour it.
    (Padding after colouring would count the invisible ANSI codes.)"""
    text = fit(text, width)
    return colour(text) + " " * max(0, width - len(text))

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
SEV_RANK   = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}

def sev_colour(sev: str) -> str:
    return {
        "CRITICAL": red(bold(sev)),
        "HIGH":     red(sev),
        "MEDIUM":   yellow(sev),
        "LOW":      green(sev),
        "NONE":     dim(sev),
        "UNKNOWN":  dim(sev),
    }.get(sev.upper(), sev)

def normalize_severity(sev) -> str:
    """Map the vocabularies of different advisories onto CRITICAL…LOW."""
    s = str(sev or "").upper()
    s = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW"}.get(s, s)
    return s if s in SEVERITIES else "UNKNOWN"

def cvss_to_severity(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL"
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        if s >  0.0: return "LOW"
        return "NONE"
    except (TypeError, ValueError):
        return "UNKNOWN"

def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string
    (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' → 9.8)."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac  = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr  = {"N": 0.85, "L": 0.68 if changed else 0.62,
               "H": 0.5 if changed else 0.27}[m["PR"]]
        ui  = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except (KeyError, ValueError):
        return None

    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if changed else 1) * (impact + exploitability)

    # CVSS v3.1 "Roundup": smallest number with one decimal place >= input
    n = round(min(raw, 10) * 100000)
    return n / 100000 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10

def clean_version(version: str) -> str:
    """nmap versions often carry distro suffixes ('8.9p1 Ubuntu 3ubuntu0.10');
    the upstream version is the first token."""
    return version.split()[0] if version else ""

def short_desc(desc: str, limit: int = 500) -> str:
    desc = " ".join(desc.split())
    return desc[:limit] + ("…" if len(desc) > limit else "")

def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60:02d}s"

def term_width() -> int:
    return min(max(shutil.get_terminal_size((100, 24)).columns - 2, 72), 118)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSOLE STATUS LINE
# ══════════════════════════════════════════════════════════════════════════════

_print_lock = threading.Lock()

class Status:
    """A single animated status line (spinner + elapsed time) for long steps.
    Only drawn on an interactive terminal; log() prints above it."""
    def __init__(self):
        self.enabled = sys.stdout.isatty()
        self._frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UNICODE else "|/-\\"
        self._text   = ""
        self._t0     = 0.0
        self._halt   = threading.Event()
        self._thread = None

    @property
    def active(self) -> bool:
        return self._thread is not None

    def start(self, text: str):
        self._text, self._t0 = text, time.monotonic()
        if self.enabled and not self._thread:
            self._halt.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def update(self, text: str):
        self._text = text

    def stop(self):
        if self._thread:
            self._halt.set()
            self._thread.join()
            self._thread = None
            with _print_lock:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()

    def _run(self):
        i = 0
        while not self._halt.wait(0.1):
            elapsed = fmt_duration(time.monotonic() - self._t0)
            text    = fit(self._text, shutil.get_terminal_size((100, 24)).columns - 14)
            with _print_lock:
                sys.stdout.write(f"\r\033[K  {cyan(self._frames[i % len(self._frames)])} "
                                 f"{text}  {dim(elapsed)}")
                sys.stdout.flush()
            i += 1

status = Status()

def log(msg: str = ""):
    """Thread-safe print that doesn't collide with the status line."""
    with _print_lock:
        if status.active:
            sys.stdout.write("\r\033[K")
        print(msg, flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP, CACHING & RATE LIMITING
# ══════════════════════════════════════════════════════════════════════════════

# Set on Ctrl+C: workers stop waiting on rate limits and skip remaining lookups.
STOP = threading.Event()

USER_AGENT = f"portriage/{__version__}"
_tls = threading.local()

def http() -> requests.Session:
    """One keep-alive session per worker thread (reuses TLS connections)."""
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        s.headers["User-Agent"] = USER_AGENT
        _tls.session = s
    return s

def default_cache_path() -> Path:
    base = (os.environ.get("XDG_CACHE_HOME") or os.environ.get("LOCALAPPDATA")
            or Path.home() / ".cache")
    return Path(base) / "portriage" / "cache.json"

class DiskCache:
    """JSON-file cache for API answers, so repeated services and re-scans don't
    hit the (slow, rate-limited) APIs again. Disabled when *path* is None."""
    def __init__(self, path: Path | None = None, ttl_hours: float = 24):
        self.path  = path
        self.ttl   = ttl_hours * 3600
        self.hits  = 0
        self._lock = threading.Lock()
        self._data: dict = {}
        self._dirty = False
        if path and path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._data = {}

    def get(self, key: str):
        if not self.path:
            return None
        with self._lock:
            entry = self._data.get(key)
            if entry and time.time() - entry["t"] < self.ttl:
                self.hits += 1
                return entry["v"]
        return None

    def set(self, key: str, value):
        if not self.path:
            return
        with self._lock:
            self._data[key] = {"t": time.time(), "v": value}
            self._dirty = True

    def save(self):
        if not self.path or not self._dirty:
            return
        with self._lock:
            now  = time.time()
            data = {k: e for k, e in self._data.items() if now - e["t"] < self.ttl}
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                os.replace(tmp, self.path)
                self._dirty = False
            except OSError as e:
                log(dim(f"  [cache] could not save {self.path}: {e}"))

cache = DiskCache()  # replaced in main()

def cached(key: str, fetch):
    """Return the cached value for *key*, or call *fetch()* and cache its
    result. *fetch* returns None on failure, which is never cached."""
    hit = cache.get(key)
    if hit is not None:
        return hit
    value = fetch()
    if value is not None:
        cache.set(key, value)
    return value

class RateLimiter:
    """Thread-safe sliding-window limiter shared by all workers: at most
    *calls* requests in any *period* seconds."""
    def __init__(self):
        self._lock = threading.Lock()
        self._sent: deque[float] = deque()

    def wait(self, calls: int, period: float) -> bool:
        """Block until a request may be sent. False if the scan was aborted."""
        with self._lock:
            while True:
                now = time.monotonic()
                while self._sent and now - self._sent[0] >= period:
                    self._sent.popleft()
                if len(self._sent) < calls:
                    self._sent.append(now)
                    return True
                if STOP.wait(period - (now - self._sent[0])):
                    return False

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE CVE SOURCES
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. NIST NVD — CPE / keyword search ────────────────────────────────────────
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_nvd_limiter = RateLimiter()

def _nvd_get(params: dict, nvd_key: str = "", label: str = "query") -> list[dict] | None:
    """GET the NVD CVE API, respecting its rate limits.
    Public limit: 5 requests / 30 s; with an API key: 50 requests / 30 s.
    Returns parsed results ([] if NVD doesn't know the CPE/query), or None on error."""
    key = "nvd:" + json.dumps(params, sort_keys=True)
    hit = cache.get(key)
    if hit is not None:
        return hit

    headers = {"apiKey": nvd_key} if nvd_key else {}
    calls   = 50 if nvd_key else 5
    for attempt in range(2):
        if not _nvd_limiter.wait(calls, 32):
            return None
        try:
            r = http().get(NVD_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as e:
            log(dim(f"  [NVD] {label} error: {e}"))
            return None
        if r.status_code == 200:
            try:
                results = _parse_nvd_response(r.json())
            except ValueError:
                log(dim(f"  [NVD] {label}: invalid JSON response"))
                return None
            cache.set(key, results)
            return results
        if r.status_code == 404:  # NVD doesn't know this CPE/query
            cache.set(key, [])
            return []
        if r.status_code in (403, 429, 503) and attempt == 0:
            log(yellow(f"  [NVD] Rate limited (HTTP {r.status_code}) — waiting 30 s "
                       "(use --nvd-key for higher limits)"))
            if STOP.wait(30):
                return None
            continue
        log(dim(f"  [NVD] {label} failed: HTTP {r.status_code}"))
        return None
    return None

def nvd_search_by_keyword(keyword: str, nvd_key: str = "", max_results: int = 200) -> list[dict]:
    """Search NVD descriptions by keyword (e.g. 'OpenSSH 8.9p1')."""
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    return _nvd_get(params, nvd_key, "keyword search") or []

def nvd_search_by_cpe(cpe: str, nvd_key: str = "", max_results: int = 2000) -> list[dict]:
    """Search NVD by CPE 2.3 string — most precise method.
    Tries an exact dictionary match (cpeName) first, then a match against the
    CVEs' own applicability criteria (virtualMatchString), which also works for
    versions that aren't in the CPE dictionary, e.g. OpenSSH '8.9p1'.
    2000 is NVD's page maximum, so one request returns every match."""
    for param in ("cpeName", "virtualMatchString"):
        results = _nvd_get({param: cpe, "resultsPerPage": max_results},
                           nvd_key, "CPE search")
        if results:
            return results
    return []

def _parse_nvd_response(data: dict) -> list[dict]:
    results = []
    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        desc   = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description."
        )
        metrics        = cve.get("metrics", {})
        score, vector  = "N/A", "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m      = metrics[key][0]
                score  = m["cvssData"].get("baseScore", "N/A")
                vector = m["cvssData"].get("vectorString", "N/A")
                break
        results.append({
            "source":      "NVD",
            "cve":         cve_id,
            "severity":    cvss_to_severity(score),
            "cvss":        score,
            "vector":      vector,
            "published":   cve.get("published", "")[:10],
            "description": short_desc(desc),
        })
    return results

# ── 2. OSV.dev — Google Open Source Vulnerability DB ──────────────────────────
# Network daemons appear in OSV mainly through Linux-distro advisories
# (Debian, Ubuntu, Alpine, …), which use the distro package name.
OSV_PACKAGE_NAMES = {
    "apache httpd": "apache2",
    "isc bind":     "bind9",
    "http_server":  "apache2",  # CPE product names
    "bind":         "bind9",
}

def osv_search(product: str, version: str, max_results: int = 15, cpe: str = "") -> list[dict]:
    """Query OSV across all ecosystems for this package name + version.
    Distro advisories for the same CVE are merged, scored from their CVSS v3
    vector, and the highest-scoring *max_results* are returned.
    nmap product names are often descriptive ('Redis key-value store'), so the
    CPE's product field ('redis') is preferred as the package name."""
    p        = product.lower().strip()
    cpe_prod = cpe.split(":")[4] if cpe.startswith("cpe:2.3:a:") else ""
    cpe_prod = "" if cpe_prod == "*" else cpe_prod
    name     = (OSV_PACKAGE_NAMES.get(p) or OSV_PACKAGE_NAMES.get(cpe_prod)
                or cpe_prod or p)

    def fetch():
        try:
            r = http().post("https://api.osv.dev/v1/query",
                            json={"package": {"name": name}, "version": version},
                            timeout=20)
            if r.status_code != 200:
                log(dim(f"  [OSV] HTTP {r.status_code}"))
                return None
            return r.json().get("vulns", [])
        except (requests.RequestException, ValueError) as e:
            log(dim(f"  [OSV] Error: {e}"))
            return None

    vulns = cached(f"osv:{name}:{version}", fetch) or []

    by_cve: dict[str, dict] = {}
    for v in vulns:
        # Some advisories (e.g. Azure Linux "AZL-…") only name the CVE at the
        # start of their summary: "CVE-2023-28531 affecting package openssh …"
        ids    = [v.get("id", "")] + v.get("aliases", []) + v.get("upstream", [])
        cve_id = next((m.group(0) for i in ids if (m := re.search(r"CVE-\d{4}-\d+", i))),
                      None)
        if not cve_id:
            m      = re.match(r"CVE-\d{4}-\d+", v.get("summary", ""))
            cve_id = m.group(0) if m else v.get("id", "N/A")
        vector = next((s["score"] for s in v.get("severity", [])
                       if s.get("type") == "CVSS_V3"), "")
        score  = cvss3_base_score(vector) if vector else None
        prev   = by_cve.get(cve_id)
        if prev and (score is None or (prev["cvss"] != "N/A" and prev["cvss"] >= score)):
            continue
        desc = v.get("summary") or v.get("details") or "No description."
        by_cve[cve_id] = {
            "source":      "OSV",
            "cve":         cve_id,
            "severity":    cvss_to_severity(score) if score is not None
                           else normalize_severity(v.get("database_specific", {}).get("severity")),
            "cvss":        score if score is not None else "N/A",
            "vector":      vector or "N/A",
            "published":   v.get("published", "")[:10],
            "description": short_desc(desc),
        }

    results = sorted(by_cve.values(), key=_cvss_sort_key, reverse=True)
    return results[:max_results]

# ── 3. Vulners API — software/version search (free API key required) ──────────
def vulners_search(software: str, version: str, api_key: str) -> list[dict]:
    """Vulners has a huge exploit/CVE index. Anonymous requests are blocked
    (HTTP 403), so this needs a free API key from https://vulners.com/."""
    url    = "https://vulners.com/api/v3/burp/software/"
    params = {"software": software, "version": version, "type": "software",
              "apiKey": api_key}

    def fetch():
        try:
            r = http().get(url, params=params, timeout=15)
            if r.status_code != 200:
                log(dim(f"  [Vulners] HTTP {r.status_code}"))
                return None
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            log(dim(f"  [Vulners] Error: {e}"))
            return None
        if data.get("result") != "OK":
            log(dim(f"  [Vulners] {data.get('data', {}).get('error', 'query failed')}"))
            return None
        return data.get("data", {}).get("search", [])[:15]

    results = []
    for item in cached(f"vulners:{software}:{version}", fetch) or []:
        src        = item.get("_source", {})
        cvss_score = src.get("cvss", {}).get("score", "N/A")
        cvelist    = src.get("cvelist") or []
        results.append({
            "source":      "Vulners",
            "cve":         cvelist[0] if cvelist else src.get("id", "N/A"),
            "vulners_id":  src.get("id", "N/A"),
            "severity":    cvss_to_severity(cvss_score),
            "cvss":        cvss_score,
            "vector":      src.get("cvss", {}).get("vector", "N/A"),
            "published":   src.get("published", "")[:10],
            "description": short_desc(src.get("description", "")),
        })
    return results

def _cvss_sort_key(v: dict) -> float:
    try:
        return float(v["cvss"])
    except (TypeError, ValueError):
        return 0.0

def priority_key(v: dict) -> tuple:
    """Fix-first order: known-exploited, then CVSS, then exploit probability."""
    return (bool(v.get("kev")), _cvss_sort_key(v), v.get("epss") or 0.0)

def vuln_url(v: dict) -> str:
    vid = v.get("cve", "")
    if vid.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vid}"
    if v.get("source") == "OSV":
        return f"https://osv.dev/vulnerability/{vid}"
    if v.get("source") == "Vulners":
        return f"https://vulners.com/search?query={v.get('vulners_id', vid)}"
    return ""

# ══════════════════════════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE — CISA KEV & FIRST EPSS
# ══════════════════════════════════════════════════════════════════════════════

KEV_URL  = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"

def load_kev() -> dict[str, dict]:
    """CISA's Known Exploited Vulnerabilities catalog: CVEs attackers are
    actively using. Returns {CVE-ID: {added, ransomware, name}}."""
    def fetch():
        try:
            r = http().get(KEV_URL, timeout=30)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            log(dim(f"  [KEV] Could not load the CISA catalog: {e}"))
            return None
        return {
            v["cveID"]: {
                "added":      v.get("dateAdded", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
                "name":       v.get("vulnerabilityName", ""),
            }
            for v in data.get("vulnerabilities", []) if v.get("cveID")
        }
    return cached("kev", fetch) or {}

def epss_lookup(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """FIRST EPSS: probability (0-1) that a CVE is exploited in the next
    30 days, and its percentile. Batched, 50 CVEs per request."""
    out:  dict[str, tuple[float, float]] = {}
    todo: list[str] = []
    for cve_id in dict.fromkeys(cve_ids):
        hit = cache.get(f"epss:{cve_id}")
        if hit is None:
            todo.append(cve_id)
        elif hit:
            out[cve_id] = (hit[0], hit[1])

    for i in range(0, len(todo), 50):
        if STOP.is_set():
            break
        batch = todo[i:i + 50]
        try:
            r = http().get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=20)
            r.raise_for_status()
            rows = r.json().get("data", [])
        except (requests.RequestException, ValueError) as e:
            log(dim(f"  [EPSS] Error: {e}"))
            break
        found = {row["cve"]: [float(row["epss"]), float(row["percentile"])]
                 for row in rows if "cve" in row}
        for cve_id in batch:
            score = found.get(cve_id, [])  # [] = EPSS has no score for it
            cache.set(f"epss:{cve_id}", score)
            if score:
                out[cve_id] = (score[0], score[1])
    return out

# ══════════════════════════════════════════════════════════════════════════════
#  SEARCHSPLOIT INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def searchsploit_available() -> bool:
    return shutil.which("searchsploit") is not None

def run_searchsploit(query: str) -> list[dict]:
    """
    Run searchsploit (Exploit-DB offline mirror) and return parsed results.
    Install: sudo apt install exploitdb
    """
    if not searchsploit_available():
        return []

    def fetch():
        try:
            result = subprocess.run(
                [shutil.which("searchsploit"), "--json", query],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, subprocess.SubprocessError, OSError) as e:
            log(dim(f"  [searchsploit] Error: {e}"))
            return None
        exploits = []
        for item in data.get("RESULTS_EXPLOIT", []):
            # Newer searchsploit has an "EDB-ID" field; otherwise the ID is
            # the file name, e.g. /usr/share/exploitdb/exploits/linux/remote/45233.py
            edb_id = str(item.get("EDB-ID") or "")
            if not edb_id:
                edb_match = re.search(r"(\d+)(?:\.\w+)?$", item.get("Path", ""))
                edb_id    = edb_match.group(1) if edb_match else "N/A"
            exploits.append({
                "title":  item.get("Title", "Unknown"),
                "path":   item.get("Path", ""),
                "type":   item.get("Type", ""),
                "edb_id": edb_id,
                "url":    f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id != "N/A" else "",
            })
        return exploits

    return cached(f"searchsploit:{query}", fetch) or []

def build_searchsploit_queries(product: str, version: str) -> list[str]:
    """Build targeted searchsploit queries from nmap product/version data."""
    queries = []
    version = clean_version(version)
    if product and version:
        queries.append(f"{product} {version}")
        parts = version.split(".")
        if len(parts) >= 2:
            queries.append(f"{product} {parts[0]}.{parts[1]}")
    elif product:
        queries.append(product)
    return list(dict.fromkeys(queries))  # de-duplicate, keep order

# ══════════════════════════════════════════════════════════════════════════════
#  SMART CPE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

# Matched as whole words, in this order — specific names before generic ones
# (so "Apache Tomcat" is Tomcat, not Apache httpd).
CPE_MAP = {
    "tomcat":          ("apache",          "tomcat"),
    "apache httpd":    ("apache",          "http_server"),
    "apache":          ("apache",          "http_server"),
    "nginx":           ("nginx",           "nginx"),
    "openssh":         ("openbsd",         "openssh"),
    "microsoft iis":   ("microsoft",       "internet_information_services"),
    "iis":             ("microsoft",       "internet_information_services"),
    "vsftpd":          ("vsftpd_project",  "vsftpd"),
    "proftpd":         ("proftpd",         "proftpd"),
    "mysql":           ("oracle",          "mysql"),
    "mariadb":         ("mariadb",         "mariadb"),
    "postgresql":      ("postgresql",      "postgresql"),
    "redis":           ("redis",           "redis"),
    "samba":           ("samba",           "samba"),
    "exim":            ("exim",            "exim"),
    "postfix":         ("postfix",         "postfix"),
    "sendmail":        ("sendmail",        "sendmail"),
    "php":             ("php",             "php"),
    "python":          ("python",          "python"),
    "ruby":            ("ruby-lang",       "ruby"),
    "wordpress":       ("wordpress",       "wordpress"),
    "drupal":          ("drupal",          "drupal"),
    "joomla":          ("joomla",          "joomla"),
    "jenkins":         ("jenkins",         "jenkins"),
    "docker":          ("docker",          "docker"),
    "openssh server":  ("openbsd",         "openssh"),
    "lighttpd":        ("lighttpd",        "lighttpd"),
    "mongodb":         ("mongodb",         "mongodb"),
    "elasticsearch":   ("elastic",         "elasticsearch"),
    "memcached":       ("memcached",       "memcached"),
    "rabbitmq":        ("pivotal_software","rabbitmq"),
    "dovecot":         ("dovecot",         "dovecot"),
    "pure-ftpd":       ("pureftpd",        "pure-ftpd"),
    "openssl":         ("openssl",         "openssl"),
    "haproxy":         ("haproxy",         "haproxy"),
    "squid":           ("squid-cache",     "squid"),
    "bind":            ("isc",             "bind"),
    "dnsmasq":         ("thekelleys",      "dnsmasq"),
    "grafana":         ("grafana",         "grafana"),
    "gitlab":          ("gitlab",          "gitlab"),
    "jetty":           ("eclipse",         "jetty"),
    "node.js":         ("nodejs",          "node.js"),
    "couchdb":         ("apache",          "couchdb"),
    "minio":           ("minio",           "minio"),
}

def _cpe23(part: str, vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:{part}:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"

def build_cpe(product: str, version: str) -> str | None:
    p = product.lower().strip()
    for key, (vendor, prod) in CPE_MAP.items():
        if re.search(rf"(?<![\w-]){re.escape(key)}(?![\w-])", p):
            return _cpe23("a", vendor, prod, clean_version(version))
    return None

def normalize_cpe(raw_cpe: str, product: str, version: str) -> str:
    """Turn nmap's CPE into the CPE 2.3 format the NVD API requires.
    nmap reports CPE 2.2 URIs ('cpe:/a:openbsd:openssh:8.9p1'), which NVD
    rejects with HTTP 404, and python-nmap keeps only the *last* CPE of a
    service, which is sometimes the OS ('cpe:/o:linux:linux_kernel')."""
    if raw_cpe.startswith("cpe:/"):
        fields = raw_cpe[len("cpe:/"):].split(":")
        if fields[0] == "a" and len(fields) >= 3:
            v = fields[3] if len(fields) > 3 and fields[3] else clean_version(version)
            return _cpe23("a", fields[1], fields[2], v)
    elif raw_cpe.startswith("cpe:2.3:a:"):
        return raw_cpe
    return build_cpe(product, version) or ""

def cpe_has_version(cpe: str) -> bool:
    fields = cpe.split(":")
    return len(fields) > 5 and fields[5] not in ("", "*", "-")

# ══════════════════════════════════════════════════════════════════════════════
#  PER-SERVICE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class LookupOptions:
    nvd_key:          str  = ""
    vulners_key:      str  = ""
    use_osv:          bool = True
    use_searchsploit: bool = True

def service_signature(port: dict) -> tuple:
    """Ports with the same signature get identical lookup results, so each
    distinct service is only looked up once per scan."""
    return (port.get("product", "").lower(),
            clean_version(port.get("version_raw", "")),
            port.get("cpe", ""))

def lookup_service(port_data: dict, opts: LookupOptions) -> tuple[list, list, bool]:
    """Query all CVE sources + searchsploit for one service.
    Returns (vulns, exploits, complete) — complete is False if aborted."""
    product = port_data.get("product", "")
    version = clean_version(port_data.get("version_raw", ""))
    cpe     = port_data.get("cpe", "")

    vulns: list[dict] = []
    seen:  set[str]   = set()

    def add(results):
        for r in results:
            if r["cve"] not in seen:
                seen.add(r["cve"])
                vulns.append(r)

    # ── NVD lookup ─────────────────────────────────────────────────────────
    # A CPE without a version would match every CVE the product ever had,
    # so only use it when it is version-specific; otherwise fall back to
    # a keyword search.
    if cpe and cpe_has_version(cpe):
        add(nvd_search_by_cpe(cpe, nvd_key=opts.nvd_key))
    if not vulns and product and version and not STOP.is_set():
        add(nvd_search_by_keyword(f"{product} {version}", nvd_key=opts.nvd_key))

    # ── OSV lookup ─────────────────────────────────────────────────────────
    if opts.use_osv and product and version and not STOP.is_set():
        add(osv_search(product, version, cpe=cpe))

    # ── Vulners lookup ─────────────────────────────────────────────────────
    if opts.vulners_key and product and version and not STOP.is_set():
        add(vulners_search(product, version, api_key=opts.vulners_key))

    # ── SearchSploit ───────────────────────────────────────────────────────
    # (a missing searchsploit is reported once at startup)
    exploits = []
    if opts.use_searchsploit and searchsploit_available():
        seen_titles = set()
        for q in build_searchsploit_queries(product, version):
            if STOP.is_set():
                break
            for exp in run_searchsploit(q):
                if exp["title"] not in seen_titles:
                    seen_titles.add(exp["title"])
                    exploits.append(exp)

    return vulns, exploits, not STOP.is_set()

# Backwards-compatible single-port entry point
def analyse_port(port_data: dict, nvd_key: str = "", vulners_key: str = "",
                 use_osv: bool = True, skip_searchsploit: bool = False) -> dict:
    vulns, exploits, _ = lookup_service(
        port_data, LookupOptions(nvd_key, vulners_key, use_osv, not skip_searchsploit))
    vulns.sort(key=priority_key, reverse=True)
    port_data["live_vulns"] = vulns
    port_data["exploits"]   = exploits
    port_data["checked"]    = True
    return port_data

# ══════════════════════════════════════════════════════════════════════════════
#  NMAP SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def build_nmap_args(timing: int = 4, top_ports: int = 0, os_detect: bool = False,
                    extra: str = "") -> str:
    args = ["-sV", "--version-intensity", "7", "--open", f"-T{timing}"]
    if top_ports:
        args += ["--top-ports", str(top_ports)]
    if os_detect:
        args.append("-O")
    if extra:
        args += shlex.split(extra)
    return " ".join(shlex.quote(a) for a in args)

def _host_sort_key(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)

def scan(target: str, port_range: str | None = "1-1024",
         arguments: str = "-sV --version-intensity 7") -> dict:
    nm = nmap.PortScanner()
    print(f"\n{bold('[ nmap scan ]')} target={cyan(target)}  "
          f"ports={cyan(port_range or 'nmap --top-ports')}")
    print(dim(f"  nmap {arguments}" + (f" -p {port_range}" if port_range else "")))

    started = time.monotonic()
    status.start(f"nmap scanning {target}")
    try:
        nm.scan(hosts=target, ports=port_range, arguments=arguments)
    except nmap.PortScannerError as exc:
        status.stop()
        print(red(f"[!] nmap error: {str(exc).strip()}"))
        print(yellow("    → Options like -O and SYN/UDP scans need root: try sudo "
                     "(or an Administrator terminal on Windows)."))
        sys.exit(1)
    finally:
        status.stop()
    elapsed = time.monotonic() - started

    results = {
        "scanner":    f"PorTriage {__version__}",
        "target":     target,
        "ports":      port_range or "",
        "nmap_args":  arguments,
        "scan_time":  datetime.now().isoformat(timespec="seconds"),
        "durations":  {"nmap": round(elapsed, 1)},
        "hosts":      [],
    }

    for host in sorted(nm.all_hosts(), key=_host_sort_key):
        h = nm[host]
        os_matches = [{"name": m.get("name", ""), "accuracy": m.get("accuracy", "")}
                      for m in h.get("osmatch", [])[:3]]
        host_info = {
            "ip":       host,
            "hostname": h.hostname() or "N/A",
            "state":    h.state(),
            "mac":      h.get("addresses", {}).get("mac", ""),
            "vendor":   next(iter(h.get("vendor", {}).values()), ""),
            "os":       os_matches,
            "ports":    [],
        }
        for proto in h.all_protocols():
            for port in sorted(h[proto].keys()):
                p = h[proto][port]
                if p["state"] != "open":
                    continue
                service   = p.get("name",    "unknown")
                product   = p.get("product", "")
                version   = p.get("version", "")
                extrainfo = p.get("extrainfo","")
                cpe       = normalize_cpe(p.get("cpe", ""), product, version)

                display_version = " ".join(filter(None, [product, version, extrainfo]))
                host_info["ports"].append({
                    "port":        port,
                    "proto":       proto,
                    "state":       p["state"],
                    "service":     service,
                    "product":     product,
                    "version_raw": version,
                    "version":     display_version or "unknown",
                    "cpe":         cpe,
                    "checked":     False,
                    "live_vulns":  [],
                    "exploits":    [],
                })
        results["hosts"].append(host_info)

    n_ports = sum(len(h["ports"]) for h in results["hosts"])
    print(f"  {green('✓')} nmap finished in {bold(fmt_duration(elapsed))} — "
          f"{bold(str(len(results['hosts'])))} host(s) up, "
          f"{bold(str(n_ports))} open port(s)")
    return results

# ══════════════════════════════════════════════════════════════════════════════
#  CVE ENRICHMENT PASS
# ══════════════════════════════════════════════════════════════════════════════

def enrich_results(results: dict, opts: LookupOptions | None = None, workers: int = 4,
                   use_kev: bool = True, use_epss: bool = True,
                   min_severity: str = "") -> bool:
    """Look up every distinct service once (in parallel), copy the findings
    to all ports running it, then add KEV/EPSS intel. Returns False if the
    user interrupted, in which case unfinished ports stay 'checked': False."""
    opts      = opts or LookupOptions()
    all_ports = [p for h in results["hosts"] for p in h["ports"]]
    if not all_ports:
        return True

    groups: dict[tuple, list[dict]] = {}
    for p in all_ports:
        groups.setdefault(service_signature(p), []).append(p)
    host_of = {id(p): h["ip"] for h in results["hosts"] for p in h["ports"]}

    sources = [cyan("NVD")]
    if opts.use_osv:
        sources.append(cyan("OSV"))
    if opts.vulners_key:
        sources.append(cyan("Vulners"))
    if use_kev:
        sources.append(red("CISA KEV"))
    if use_epss:
        sources.append(yellow("EPSS"))
    if opts.use_searchsploit and searchsploit_available():
        sources.append(magenta("SearchSploit"))
    print(f"\n{bold('[ CVE Enrichment ]')} {' · '.join(sources)}")
    print(dim(f"  {len(all_ports)} open port(s) → {len(groups)} distinct service(s) "
              f"· {workers} worker(s)"))
    if not opts.nvd_key:
        print(dim("  NVD allows 5 requests / 30 s without an API key — large scans "
                  "can take a while (use --nvd-key or NVD_API_KEY to speed it up)"))
    print()

    started  = time.monotonic()
    kev      = {}
    complete = True
    done     = 0
    total    = len(groups)
    width    = len(str(total))

    if use_kev:
        status.start("loading CISA Known Exploited Vulnerabilities catalog")
        kev = load_kev()
        status.stop()

    def report(port: dict, vulns: list, exploits: list):
        ports = groups[service_signature(port)]
        name  = f"{port['product']} {clean_version(port['version_raw'])}".strip() \
                or port["service"]
        where = ", ".join(sorted({f"{p['port']}/{p['proto']}" for p in ports}))
        hosts = len({host_of[id(p)] for p in ports})
        parts = []
        if vulns:
            crit = sum(v["severity"] == "CRITICAL" for v in vulns)
            parts.append(red(f"{len(vulns)} CVEs") + (f" ({crit} critical)" if crit else ""))
            n_kev = sum(v["cve"] in kev for v in vulns)
            if n_kev:
                parts.append(alert(f" {n_kev} KEV "))
        if exploits:
            parts.append(magenta(f"⚡ {len(exploits)} exploits"))
        findings = " · ".join(parts) if parts else green("no known CVEs")
        counter  = dim(f"[{done:>{width}}/{total}]")
        log(f"  {counter} {pad(name, 30, cyan)} {findings}  "
            + dim(f"← {fit(where, 24)}" + (f" on {hosts} hosts" if hosts > 1 else "")))
        status.update(f"looking up services… {done}/{total} done")

    status.start(f"looking up services… 0/{total} done")
    executor = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {executor.submit(lookup_service, ports[0], opts): sig
                   for sig, ports in groups.items()}
        for f in as_completed(futures):
            ports = groups[futures[f]]
            try:
                vulns, exploits, ok = f.result()
            except Exception as e:
                log(red(f"  [!] Enrichment error: {e}"))
                continue
            for p in ports:
                p["live_vulns"] = [dict(v) for v in vulns]
                p["exploits"]   = list(exploits)
                p["checked"]    = ok
            done += 1
            report(ports[0], vulns, exploits)
    except KeyboardInterrupt:
        STOP.set()
        complete = False
        status.stop()
        log(yellow("\n  [!] Interrupted — finishing in-flight lookups, "
                   "then showing partial results…"))
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        status.stop()

    # ── Threat intel: KEV flags + EPSS scores ──────────────────────────────
    all_vulns = [v for p in all_ports for v in p["live_vulns"]]
    epss = {}
    if use_epss and all_vulns and not STOP.is_set():
        status.start("fetching EPSS exploit-probability scores")
        epss = epss_lookup([v["cve"] for v in all_vulns if v["cve"].startswith("CVE-")])
        status.stop()
    for v in all_vulns:
        if v["cve"] in kev:
            v["kev"] = True
            v["kev_added"] = kev[v["cve"]]["added"]
            v["kev_ransomware"] = kev[v["cve"]]["ransomware"]
        if v["cve"] in epss:
            v["epss"], v["epss_percentile"] = epss[v["cve"]]

    # ── Sort & filter ──────────────────────────────────────────────────────
    threshold = SEV_RANK.get(min_severity.upper(), 0) if min_severity else 0
    for p in all_ports:
        if threshold:  # KEV-listed CVEs are always kept: they're being exploited
            p["live_vulns"] = [v for v in p["live_vulns"]
                               if v.get("kev") or SEV_RANK.get(v["severity"], 0) >= threshold]
        p["live_vulns"].sort(key=priority_key, reverse=True)

    elapsed = time.monotonic() - started
    results.setdefault("durations", {})["enrichment"] = round(elapsed, 1)
    hits = f", {cache.hits} answer(s) from cache" if cache.hits else ""
    print(f"\n  {green('✓')} enrichment finished in {bold(fmt_duration(elapsed))}{dim(hits)}")
    return complete

# ══════════════════════════════════════════════════════════════════════════════
#  REPORT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def host_risk(host: dict) -> str:
    vulns = [v for p in host["ports"] for v in p["live_vulns"]]
    if any(v.get("kev") for v in vulns):
        return "CRITICAL"
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if any(v["severity"] == sev for v in vulns):
            return sev
    return "NONE"

def report_stats(results: dict) -> dict:
    """Totals across all hosts, counting each CVE / exploit once."""
    unique:   dict[str, dict]      = {}
    where:    dict[str, list[str]] = {}
    exploits: set[str]             = set()
    ports = 0
    for h in results["hosts"]:
        for p in h["ports"]:
            ports += 1
            for v in p["live_vulns"]:
                unique.setdefault(v["cve"], v)
                where.setdefault(v["cve"], []).append(f"{h['ip']}:{p['port']}")
            exploits.update(e["edb_id"] + e["title"] for e in p["exploits"])
    return {
        "hosts":    len(results["hosts"]),
        "ports":    ports,
        "cves":     len(unique),
        "severity": Counter(v["severity"] for v in unique.values()),
        "kev":      sum(1 for v in unique.values() if v.get("kev")),
        "exploits": len(exploits),
        "top":      sorted(unique.values(), key=priority_key, reverse=True),
        "where":    where,
    }

def fmt_cvss(v: dict) -> str:
    try:
        return f"{float(v['cvss']):.1f}"
    except (TypeError, ValueError, KeyError):
        return "–"

def fmt_epss(e: float) -> str:
    return f"{e * 100:.1f}%" if e < 0.1 else f"{e * 100:.0f}%"

# ══════════════════════════════════════════════════════════════════════════════
#  PRETTY PRINTER
# ══════════════════════════════════════════════════════════════════════════════

def _wrap(text: str, width: int, indent: int, max_lines: int = 2) -> list[str]:
    lines = textwrap.wrap(text, width - indent) or [""]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = fit(lines[-1] + " …", width - indent)
    return [" " * indent + line for line in lines]

def print_results(results: dict, max_cves: int = 10, max_exploits: int = 10):
    W     = term_width()
    stats = report_stats(results)
    took  = sum(results.get("durations", {}).values())

    print("\n" + "═" * W)
    print(bold(f"  SCAN REPORT  ·  {results['target']}  ·  {results['scan_time']}"))
    print(dim(f"  {stats['hosts']} host(s) up · {stats['ports']} open port(s)"
              + (f" · completed in {fmt_duration(took)}" if took else "")))
    print("═" * W)

    if not results["hosts"]:
        print(yellow("  No hosts responded."))
        print(dim("  Tip: hosts that block ping look down — add --nmap-args \"-Pn\"."))
        return

    ver_w    = max(24, W - 58)
    enriched = results.get("enriched", True)
    for host in results["hosts"]:
        risk = host_risk(host)
        name = f"  ({host['hostname']})" if host["hostname"] != "N/A" else ""
        print(f"\n  {bold(cyan('●'))} {bold(cyan(host['ip']))}{name}  "
              f"[{green(host['state']) if host['state'] == 'up' else host['state']}]"
              + (f"   risk: {sev_colour(risk)}" if risk != "NONE" else ""))
        extra = []
        if host.get("os"):
            best = host["os"][0]
            extra.append(f"OS: {best['name']} ({best['accuracy']}%)")
        if host.get("mac"):
            extra.append(f"MAC: {host['mac']}" + (f" ({host['vendor']})" if host.get("vendor") else ""))
        if extra:
            print(dim("    " + "   ".join(extra)))
        print("─" * W)

        open_ports = host["ports"]
        if not open_ports:
            print("  No open ports found.")
            continue

        vulns     = [v for p in open_ports for v in p["live_vulns"]]
        n_crit    = sum(v["severity"] == "CRITICAL" for v in vulns)
        n_kev     = sum(1 for v in vulns if v.get("kev"))
        n_exploit = sum(len(p["exploits"]) for p in open_ports)
        cve_txt   = (red if vulns else green)(str(len(vulns)))
        if n_crit or n_kev:
            cve_txt += dim(f"  ({n_crit} critical, {n_kev} known-exploited)")
        print(f"  Open ports : {bold(str(len(open_ports)))}")
        if enriched:
            print(f"  CVEs       : {cve_txt}")
            print(f"  Exploits   : {(magenta if n_exploit else green)(str(n_exploit))}")
        print()

        # ── Port overview table ────────────────────────────────────────────
        print("  " + bold(pad("PORT", 11) + "  " + pad("SERVICE", 14) + "  "
                          + pad("VERSION", ver_w) + "  FINDINGS"))
        for p in open_ports:
            if not enriched:
                tag = dim("–")
            elif not p.get("checked", True):
                tag = dim("not checked")
            elif p["live_vulns"]:
                top = p["live_vulns"][0]
                tag = f"{sev_colour(top['severity'])} · {len(p['live_vulns'])} CVEs"
                if any(v.get("kev") for v in p["live_vulns"]):
                    tag += " " + alert(" KEV ")
            else:
                tag = green("✓ clean")
            if p["exploits"]:
                tag += "  " + magenta(f"⚡ {len(p['exploits'])}")
            print(f"  {pad(str(p['port']) + '/' + p['proto'], 11, bold)}  "
                  f"{pad(p['service'], 14, cyan)}  {pad(p['version'], ver_w)}  {tag}")

        # ── Per-port details ───────────────────────────────────────────────
        for p in open_ports:
            if not p["live_vulns"] and not p["exploits"]:
                continue
            print(f"\n  {bold('▸ ' + str(p['port']) + '/' + p['proto'])}  "
                  f"{cyan(p['service'])}  {p['version']}")
            if p["cpe"]:
                print(f"    {dim('CPE ' + p['cpe'])}")

            for v in p["live_vulns"][:max_cves]:
                tags = []
                if v.get("kev"):
                    tags.append(alert(" KEV ") + (red(" ransomware") if v.get("kev_ransomware") else ""))
                if v.get("epss") is not None:
                    e = v["epss"]
                    tags.append((yellow if e >= 0.1 else dim)(f"EPSS {fmt_epss(e)}"))
                tags.append(dim(f"[{v['source']}]"))
                print(f"\n    {pad(v['severity'], 8, sev_colour)}  {pad(fmt_cvss(v), 4, bold)}  "
                      f"{pad(v['cve'], 20, yellow)}  {'  '.join(tags)}")
                for line in _wrap(v["description"], W, 20):
                    print(dim(line))
                meta = [m for m in (v.get("published") and f"Published {v['published']}",
                                    vuln_url(v)) if m]
                if meta:
                    print(" " * 20 + dim(" · ".join(meta)))
            remaining = len(p["live_vulns"]) - max_cves
            if remaining > 0:
                print(f"\n    {dim(f'… +{remaining} more CVEs  (use --max-cves N or --html to see all)')}")

            if p["exploits"]:
                print(f"\n    {magenta(bold('[ Exploit-DB ]'))}")
                for exp in p["exploits"][:max_exploits]:
                    print(f"    {magenta('⚡')} {pad('EDB-' + exp['edb_id'], 10, bold)} "
                          f"{pad(exp['type'], 8, dim)} {fit(exp['title'], W - 26)}")
                    if exp.get("url"):
                        print(" " * 26 + dim(exp["url"]))
                remaining = len(p["exploits"]) - max_exploits
                if remaining > 0:
                    print(f"    {dim(f'… +{remaining} more exploits')}")

    # ── Global summary ─────────────────────────────────────────────────────
    print("\n" + "═" * W)
    print(bold("  SUMMARY"))
    print(f"  Hosts up {bold(str(stats['hosts']))}  ·  open ports {bold(str(stats['ports']))}  ·  "
          f"unique CVEs {bold(str(stats['cves']))}  ·  "
          f"known-exploited {(red if stats['kev'] else green)(bold(str(stats['kev'])))}  ·  "
          f"public exploits {(magenta if stats['exploits'] else green)(bold(str(stats['exploits'])))}")

    sev_count = stats["severity"]
    if sev_count:
        print()
        biggest = max(sev_count.values())
        bar_w   = max(10, min(40, W - 30))
        block   = "█" if UNICODE else "#"
        for sev in SEVERITIES:
            if sev in sev_count:
                n   = sev_count[sev]
                bar = block * max(1, round(n / biggest * bar_w))
                colour = {"CRITICAL": red, "HIGH": red, "MEDIUM": yellow,
                          "LOW": green}.get(sev, dim)
                print(f"    {pad(sev, 9, sev_colour)} {colour(bar)} {n}")

    if stats["top"]:
        print(f"\n  {bold('Fix first:')}")
        for i, v in enumerate(stats["top"][:5], 1):
            hosts = stats["where"][v["cve"]]
            loc   = hosts[0] + (dim(f" +{len(hosts) - 1} more") if len(hosts) > 1 else "")
            tag   = " " + alert(" KEV ") if v.get("kev") else ""
            epss  = dim(f" EPSS {fmt_epss(v['epss'])}") if v.get("epss") is not None else ""
            print(f"   {i}. {pad(v['cve'], 18, yellow)} {pad(v['severity'], 8, sev_colour)} "
                  f"{pad(fmt_cvss(v), 4, bold)}{tag}{epss}  {dim('on')} {loc}")

    if stats["exploits"]:
        print(f"\n  {red('→ Public exploit code exists for some services — patch them first!')}")
    if not enriched:
        print(dim("  CVE lookups were skipped (--no-cve)."))
    elif not sev_count and not stats["exploits"]:
        unchecked = any(not p.get("checked", True) for h in results["hosts"] for p in h["ports"])
        print(yellow("  Some services were not checked (scan interrupted).") if unchecked
              else green("  No known CVEs or public exploits detected."))
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  EXPORTS — JSON, CSV, HTML
# ══════════════════════════════════════════════════════════════════════════════

def save_json(results: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(green(f"  [+] JSON report saved → {path}"))

CSV_FIELDS = ["host", "hostname", "port", "proto", "service", "version", "finding",
              "id", "severity", "cvss", "epss", "kev", "source", "published", "title", "url"]

def save_csv(results: dict, path: str):
    """One row per finding (CVE or exploit); ports without findings get one
    'open-port' row, so the CSV doubles as a service inventory."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for h in results["hosts"]:
            for p in h["ports"]:
                base = {"host": h["ip"], "hostname": h["hostname"], "port": p["port"],
                        "proto": p["proto"], "service": p["service"], "version": p["version"]}
                for v in p["live_vulns"]:
                    w.writerow({**base, "finding": "cve", "id": v["cve"],
                                "severity": v["severity"], "cvss": v["cvss"],
                                "epss": v.get("epss", ""), "kev": "yes" if v.get("kev") else "",
                                "source": v["source"], "published": v.get("published", ""),
                                "title": v["description"], "url": vuln_url(v)})
                for e in p["exploits"]:
                    w.writerow({**base, "finding": "exploit", "id": f"EDB-{e['edb_id']}",
                                "source": "Exploit-DB", "title": e["title"], "url": e["url"]})
                if not p["live_vulns"] and not p["exploits"]:
                    w.writerow({**base, "finding": "open-port"})
    print(green(f"  [+] CSV report saved  → {path}"))

HTML_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#677084;--line:#e3e6ec;
--crit:#b4232c;--high:#e0592a;--med:#c99a06;--low:#2f9e5b;--unk:#8a90a0;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e6e9ef;
--muted:#9aa3b5;--line:#272d39;--accent:#6ea0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}
main{max-width:1150px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:0}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.meta{color:var(--muted);margin:0 0 24px;font-size:14px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:26px;line-height:1.2}.card span{color:var(--muted);font-size:13px}
.sevbar{display:flex;height:12px;border-radius:6px;overflow:hidden;margin:4px 0 8px;background:var(--line)}
.legend{display:flex;flex-wrap:wrap;gap:14px;color:var(--muted);font-size:13px;margin-bottom:28px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}
.LOW{background:var(--low)}.NONE,.UNKNOWN{background:var(--unk)}
.pill{display:inline-block;color:#fff;border-radius:999px;padding:1px 9px;font-size:12px;
font-weight:600;letter-spacing:.02em;white-space:nowrap}
.kev{background:#7f1d1d;color:#fff}.exp{background:#7c3aed}.ok{background:var(--low)}
.host{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:18px 0}
.host header{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:4px}
.sub{color:var(--muted);font-size:13px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em;border-bottom:1px solid var(--line);padding:8px 8px}
td{border-bottom:1px solid var(--line);padding:8px;vertical-align:top}
.wrap{overflow-x:auto}
details{border:1px solid var(--line);border-radius:10px;margin:10px 0;background:var(--bg)}
summary{cursor:pointer;padding:10px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
details>div{padding:0 14px 12px}
.desc{color:var(--muted);font-size:13px}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 8px}
.toolbar input,.toolbar select,.toolbar button{font:inherit;padding:7px 10px;border-radius:8px;
border:1px solid var(--line);background:var(--card);color:var(--fg)}
.toolbar input{flex:1;min-width:200px}
footer{color:var(--muted);font-size:12px;margin-top:40px}
"""

HTML_JS = """
const q=document.getElementById('q'),sev=document.getElementById('sev');
const rank={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,NONE:0,UNKNOWN:0};
function filter(){const t=q.value.toLowerCase(),m=+sev.value;
document.querySelectorAll('tr.cve').forEach(r=>{const ok=(!t||r.textContent.toLowerCase().includes(t))
&&(rank[r.dataset.sev]>=m||r.dataset.kev==='1');r.style.display=ok?'':'none'});}
q.addEventListener('input',filter);sev.addEventListener('change',filter);
document.getElementById('toggle').addEventListener('click',e=>{const ds=document.querySelectorAll('details');
const open=![...ds].every(d=>d.open);ds.forEach(d=>d.open=open);e.target.textContent=open?'Collapse all':'Expand all';});
"""

def save_html(results: dict, path: str):
    """Self-contained HTML report (no external assets), light & dark mode."""
    e     = lambda t: html.escape(str(t))  # noqa: E731
    stats = report_stats(results)
    out   = []

    def pill(sev: str) -> str:
        return f'<span class="pill {e(sev)}">{e(sev)}</span>'

    took = sum(results.get("durations", {}).values())
    out.append(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PorTriage report — {e(results['target'])}</title><style>{HTML_CSS}</style></head>
<body><main><h1>PorTriage report</h1>
<p class="meta">Target <b>{e(results['target'])}</b> · {e(results['scan_time'])}
{f' · completed in {e(fmt_duration(took))}' if took else ''} ·
<span class="mono">nmap {e(results.get('nmap_args', ''))}{' -p ' + e(results['ports']) if results.get('ports') else ''}</span></p>""")

    cards = [("Hosts up", stats["hosts"]), ("Open ports", stats["ports"]),
             ("Unique CVEs", stats["cves"]),
             ("Critical", stats["severity"].get("CRITICAL", 0)),
             ("Known exploited (KEV)", stats["kev"]), ("Public exploits", stats["exploits"])]
    out.append('<div class="cards">' + "".join(
        f'<div class="card"><b>{n}</b><span>{e(label)}</span></div>' for label, n in cards)
        + "</div>")

    if stats["cves"]:
        out.append('<div class="sevbar">' + "".join(
            f'<div class="{s}" style="width:{stats["severity"][s] / stats["cves"] * 100:.2f}%"'
            f' title="{s}: {stats["severity"][s]}"></div>'
            for s in SEVERITIES if stats["severity"].get(s)) + "</div>")
        out.append('<div class="legend">' + "".join(
            f'<span><i class="{s}"></i>{s.title()} {stats["severity"][s]}</span>'
            for s in SEVERITIES if stats["severity"].get(s)) + "</div>")
        out.append("""<div class="toolbar"><input id="q" placeholder="Filter CVEs (ID, text, product)…">
<select id="sev"><option value="0">All severities</option><option value="1">Low +</option>
<option value="2">Medium +</option><option value="3">High +</option><option value="4">Critical</option>
</select><button id="toggle" type="button">Expand all</button></div>""")

    if not results["hosts"]:
        out.append('<p class="sub">No hosts responded.</p>')

    for h in results["hosts"]:
        risk = host_risk(h)
        sub  = []
        if h.get("os"):
            sub.append(f"OS: {e(h['os'][0]['name'])} ({e(h['os'][0]['accuracy'])}%)")
        if h.get("mac"):
            sub.append(f"MAC: {e(h['mac'])} {e(h.get('vendor', ''))}")
        sub.append(f"{len(h['ports'])} open port(s)")
        out.append(f"""<section class="host"><header><h2>{e(h['ip'])}</h2>
<span class="sub" style="margin:0">{e(h['hostname']) if h['hostname'] != 'N/A' else ''}</span>
{pill(risk) if risk != 'NONE' else '<span class="pill ok">no known CVEs</span>'}</header>
<p class="sub">{' · '.join(sub)}</p>""")

        if h["ports"]:
            out.append('<div class="wrap"><table><tr><th>Port</th><th>Service</th>'
                       '<th>Version</th><th>Findings</th></tr>')
            for p in h["ports"]:
                tags = []
                if p["live_vulns"]:
                    tags.append(pill(p["live_vulns"][0]["severity"])
                                + f' {len(p["live_vulns"])} CVEs')
                    if any(v.get("kev") for v in p["live_vulns"]):
                        tags.append('<span class="pill kev">KEV</span>')
                elif not results.get("enriched", True):
                    tags.append('<span class="desc">–</span>')
                elif not p.get("checked", True):
                    tags.append('<span class="desc">not checked</span>')
                else:
                    tags.append('<span class="pill ok">clean</span>')
                if p["exploits"]:
                    tags.append(f'<span class="pill exp">{len(p["exploits"])} exploits</span>')
                out.append(f'<tr><td class="mono">{p["port"]}/{e(p["proto"])}</td>'
                           f'<td>{e(p["service"])}</td><td>{e(p["version"])}</td>'
                           f'<td>{" ".join(tags)}</td></tr>')
            out.append("</table></div>")

        for p in h["ports"]:
            if not p["live_vulns"] and not p["exploits"]:
                continue
            out.append(f'<details><summary><b class="mono">{p["port"]}/{e(p["proto"])}</b> '
                       f'{e(p["service"])} — {e(p["version"])}'
                       + (f' {pill(p["live_vulns"][0]["severity"])}' if p["live_vulns"] else "")
                       + "</summary><div>")
            if p["cpe"]:
                out.append(f'<p class="sub mono">{e(p["cpe"])}</p>')
            if p["live_vulns"]:
                out.append('<div class="wrap"><table><tr><th>Severity</th><th>CVSS</th><th>ID</th>'
                           '<th>EPSS</th><th>Description</th><th>Source</th></tr>')
                for v in p["live_vulns"]:
                    url  = vuln_url(v)
                    vid  = f'<a href="{e(url)}" target="_blank" rel="noopener">{e(v["cve"])}</a>' \
                           if url else e(v["cve"])
                    kev  = ' <span class="pill kev">KEV</span>' if v.get("kev") else ""
                    if v.get("kev_ransomware"):
                        kev += ' <span class="pill kev">ransomware</span>'
                    epss = fmt_epss(v["epss"]) if v.get("epss") is not None else "–"
                    out.append(f'<tr class="cve" data-sev="{e(v["severity"])}" '
                               f'data-kev="{1 if v.get("kev") else 0}">'
                               f'<td>{pill(v["severity"])}</td><td>{e(fmt_cvss(v))}</td>'
                               f'<td class="mono">{vid}{kev}</td><td>{e(epss)}</td>'
                               f'<td class="desc">{e(v["description"])}'
                               f'{"<br>Published " + e(v["published"]) if v.get("published") else ""}</td>'
                               f'<td>{e(v["source"])}</td></tr>')
                out.append("</table></div>")
            if p["exploits"]:
                out.append('<p><b>Exploit-DB</b></p><div class="wrap"><table>'
                           '<tr><th>EDB-ID</th><th>Type</th><th>Title</th></tr>')
                for x in p["exploits"]:
                    link = f'<a href="{e(x["url"])}" target="_blank" rel="noopener">' \
                           f'{e(x["edb_id"])}</a>' if x.get("url") else e(x["edb_id"])
                    out.append(f'<tr><td class="mono">{link}</td><td>{e(x["type"])}</td>'
                               f'<td>{e(x["title"])}</td></tr>')
                out.append("</table></div>")
            out.append("</div></details>")
        out.append("</section>")

    out.append(f"""<footer>Generated by PorTriage {__version__} ·
CVE data: NIST NVD, OSV.dev, Vulners · Threat intel: CISA KEV, FIRST EPSS · Exploits: Exploit-DB.
Matches are based on detected product versions and may include false positives — verify before acting.
Only scan systems you are authorized to test.</footer></main>
{f'<script>{HTML_JS}</script>' if stats['cves'] else ''}</body></html>""")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(green(f"  [+] HTML report saved → {path}"))

# ══════════════════════════════════════════════════════════════════════════════
#  COMPARE WITH A PREVIOUS SCAN
# ══════════════════════════════════════════════════════════════════════════════

def compare_results(old: dict, new: dict) -> dict:
    """What changed since *old*: opened/closed ports, version changes and
    newly matching CVEs."""
    def index(r):
        return {f"{h['ip']}:{p['port']}/{p['proto']}": p
                for h in r.get("hosts", []) for p in h.get("ports", [])}
    old_p, new_p = index(old), index(new)
    changes = {"since": old.get("scan_time", "?"), "opened": [], "closed": [],
               "changed": [], "new_cves": []}
    for key, p in new_p.items():
        before = old_p.get(key)
        if before is None:
            changes["opened"].append({"endpoint": key, "service": p["service"],
                                      "version": p["version"]})
        elif before.get("version") != p["version"]:
            changes["changed"].append({"endpoint": key, "from": before.get("version"),
                                       "to": p["version"]})
        old_cves = {v["cve"] for v in (before or {}).get("live_vulns", [])}
        for v in p["live_vulns"]:
            if v["cve"] not in old_cves:
                changes["new_cves"].append({"endpoint": key, "cve": v["cve"],
                                            "severity": v["severity"], "kev": bool(v.get("kev"))})
    for key, p in old_p.items():
        if key not in new_p:
            changes["closed"].append({"endpoint": key, "service": p.get("service", ""),
                                      "version": p.get("version", "")})
    return changes

def print_changes(changes: dict):
    W = term_width()
    print("═" * W)
    print(bold(f"  CHANGES SINCE {changes['since']}"))
    if not any(changes[k] for k in ("opened", "closed", "changed", "new_cves")):
        print(green("  No changes — same open ports, versions and CVEs."))
        print()
        return
    for c in changes["opened"]:
        print(f"  {green('+')} {pad(c['endpoint'], 26, bold)} {cyan(c['service'])}  "
              f"{c['version']}  {green('(newly open)')}")
    for c in changes["closed"]:
        print(f"  {red('-')} {pad(c['endpoint'], 26, bold)} {cyan(c['service'])}  "
              f"{dim(c['version'])}  {dim('(closed)')}")
    for c in changes["changed"]:
        print(f"  {yellow('~')} {pad(c['endpoint'], 26, bold)} {dim(c['from'])} → {c['to']}")
    if changes["new_cves"]:
        by_sev = Counter(c["severity"] for c in changes["new_cves"])
        summary = ", ".join(f"{n} {s.lower()}" for s in SEVERITIES if (n := by_sev.get(s)))
        print(f"  {red('!')} {len(changes['new_cves'])} new CVE match(es): {summary}")
        for c in sorted(changes["new_cves"], key=lambda c: (c["kev"], SEV_RANK[c["severity"]]),
                        reverse=True)[:10]:
            print(f"      {pad(c['cve'], 18, yellow)} {pad(c['severity'], 8, sev_colour)} "
                  f"{dim('on')} {c['endpoint']}" + (" " + alert(" KEV ") if c["kev"] else ""))
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def looks_like_hostname(target: str) -> bool:
    """IPs, CIDRs, nmap ranges (10.0.0.1-50) and IPv6 don't need DNS."""
    host = target.split("/")[0]
    return ":" not in host and bool(re.search(r"[a-zA-Z]", host))

def banner():
    lines = [f"PorTriage {__version__}  ·  Scan. Rank. Fix first.",
             "nmap · NVD · OSV · Vulners · CISA KEV · EPSS · Exploit-DB"]
    w = max(len(line) for line in lines) + 4
    if UNICODE:
        top, bottom, side = "╭" + "─" * w + "╮", "╰" + "─" * w + "╯", "│"
    else:
        top = bottom = "+" + "-" * w + "+"
        side = "|"
    print("\n  " + cyan(top))
    print(f"  {cyan(side)}  {bold(pad(lines[0], w - 2))}{cyan(side)}")
    print(f"  {cyan(side)}  {pad(lines[1], w - 2, dim)}{cyan(side)}")
    print("  " + cyan(bottom) + "\n")

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PorTriage — port scanner with live NVD/OSV/Vulners CVE lookup, CISA KEV, EPSS + SearchSploit.\nScan. Rank. Fix first.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CVE & threat-intel sources (all free):
  • NIST NVD    https://nvd.nist.gov/developers/vulnerabilities
  • OSV.dev     https://osv.dev/
  • Vulners     https://vulners.com/  (only used with --vulners-key)
  • CISA KEV    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  • FIRST EPSS  https://www.first.org/epss/
  • Exploit-DB  https://www.exploit-db.com/  (via searchsploit offline)

Install searchsploit:
  sudo apt install exploitdb          (Debian/Ubuntu/Kali)
  brew install exploitdb              (macOS)

Optional free API keys (flags or environment variables):
  NVD key:     --nvd-key / NVD_API_KEY          (higher rate limit)
               https://nvd.nist.gov/developers/request-an-api-key
  Vulners key: --vulners-key / VULNERS_API_KEY  (enables Vulners lookups)
               https://vulners.com/

Examples:
  python portriage.py 192.168.1.1
  python portriage.py 192.168.1.1 -p 22,80,443,3306
  python portriage.py 10.0.0.1 --full -o report.json --html report.html
  python portriage.py 10.0.0.0/24 --top-ports 100 --min-severity high
  python portriage.py -iL targets.txt --csv findings.csv
  python portriage.py 10.0.0.5 --compare last-week.json -o today.json
  python portriage.py 10.0.0.5 --fail-on critical        (exit code 2 for CI)
  sudo python portriage.py 192.168.1.0/24 -O --nmap-args "-sS -Pn"
        """
    )
    tg = parser.add_argument_group("targets")
    tg.add_argument("target", nargs="*",
                    help="IP, hostname, CIDR or nmap range (e.g. 10.0.0.1-50); several allowed")
    tg.add_argument("-iL", "--input-list", metavar="FILE",
                    help="Read targets from a file (one per line, # for comments)")

    sg = parser.add_argument_group("scan")
    ports = sg.add_mutually_exclusive_group()
    ports.add_argument("-p", "--ports", default="1-1024",
                       help="Port range (default: 1-1024)")
    ports.add_argument("--full", action="store_true",
                       help="Scan all 65535 ports")
    ports.add_argument("--top-ports", type=int, metavar="N",
                       help="Scan nmap's N most common ports (fast)")
    sg.add_argument("-T", "--timing", type=int, choices=range(6), default=4, metavar="0-5",
                    help="nmap timing template (default: 4 = aggressive, 3 = nmap default)")
    sg.add_argument("-O", "--os-detect", action="store_true",
                    help="Enable nmap OS detection (needs root/Administrator)")
    sg.add_argument("--nmap-args", default="", metavar="ARGS",
                    help='Extra nmap arguments, e.g. "-Pn" or "-sS -sU"')

    lg = parser.add_argument_group("vulnerability lookups")
    lg.add_argument("--no-cve", action="store_true",
                    help="Skip all CVE enrichment (nmap only)")
    lg.add_argument("--no-osv", action="store_true",
                    help="Skip OSV.dev lookup")
    lg.add_argument("--no-searchsploit", action="store_true",
                    help="Skip SearchSploit / Exploit-DB check")
    lg.add_argument("--no-kev", action="store_true",
                    help="Skip CISA Known Exploited Vulnerabilities flags")
    lg.add_argument("--no-epss", action="store_true",
                    help="Skip FIRST EPSS exploit-probability scores")
    lg.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""), metavar="KEY",
                    help="NIST NVD API key (raises rate limit from 5 to 50 requests / 30 s)")
    lg.add_argument("--vulners-key", default=os.environ.get("VULNERS_API_KEY", ""), metavar="KEY",
                    help="Vulners API key (free; Vulners is skipped without one)")
    lg.add_argument("-w", "--workers", type=int, default=4, metavar="N",
                    help="Parallel service lookups (default: 4; NVD stays rate-limited)")
    lg.add_argument("--parallel", action="store_true",
                    help=argparse.SUPPRESS)  # kept for compatibility; parallel is the default
    lg.add_argument("--no-cache", action="store_true",
                    help="Don't read or write the local lookup cache")
    lg.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS",
                    help="How long cached lookups stay valid (default: 24)")

    og = parser.add_argument_group("output")
    og.add_argument("--min-severity", choices=["low", "medium", "high", "critical"],
                    help="Only report CVEs at or above this severity (KEV CVEs always kept)")
    og.add_argument("--max-cves", type=int, default=10, metavar="N",
                    help="Max CVEs to display per port (default: 10)")
    og.add_argument("--max-exploits", type=int, default=10, metavar="N",
                    help="Max exploits to display per port (default: 10)")
    og.add_argument("-o", "--output", metavar="FILE",
                    help="Save full JSON report to file")
    og.add_argument("--html", metavar="FILE",
                    help="Save a self-contained HTML report")
    og.add_argument("--csv", metavar="FILE",
                    help="Save findings as CSV (one row per CVE / exploit)")
    og.add_argument("--compare", metavar="OLD.json",
                    help="Show what changed since a previous JSON report")
    og.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                    help="Exit with code 2 if any CVE at or above this severity is found")
    og.add_argument("--no-color", action="store_true",
                    help="Disable coloured output (also: NO_COLOR env var)")
    args = parser.parse_args()

    if args.no_color or os.environ.get("NO_COLOR") or \
            (not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR")):
        C.disable()

    # ── Targets ────────────────────────────────────────────────────────────
    targets = list(args.target)
    if args.input_list:
        try:
            with open(args.input_list, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    targets.extend(line.split())
        except OSError as e:
            parser.error(f"cannot read target list: {e}")
    if not targets:
        parser.error("no target given (pass one or more targets, or -iL FILE)")
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    previous = None
    if args.compare:
        try:
            with open(args.compare, encoding="utf-8") as f:
                previous = json.load(f)
        except (OSError, ValueError) as e:
            parser.error(f"cannot read --compare report: {e}")

    banner()

    # ── Optional source status ─────────────────────────────────────────────
    print(f"  {green('[✓]')} nmap {'.'.join(map(str, nmap.PortScanner().nmap_version()))}")
    if not args.no_cve:
        if args.nvd_key:
            print(f"  {green('[✓]')} NVD API key set — fast lookups")
        else:
            print(dim("  [-] No NVD API key — lookups limited to 5 requests / 30 s"))
        if not args.vulners_key:
            print(dim("  [-] Vulners skipped — needs a free API key "
                      "(--vulners-key or VULNERS_API_KEY)"))
        if not args.no_searchsploit:
            if searchsploit_available():
                print(f"  {green('[✓]')} searchsploit found")
            else:
                print(yellow("  [!] searchsploit not installed — Exploit-DB checks disabled"))
                print(dim("      sudo apt install exploitdb   (or brew install exploitdb)"))

    global cache
    if not args.no_cache and not args.no_cve:
        cache = DiskCache(default_cache_path(), args.cache_ttl)
        print(dim(f"  [i] Lookup cache: {cache.path}  ({args.cache_ttl:g} h)"))

    for t in targets:
        if looks_like_hostname(t):
            host = t.split("/")[0]
            try:
                resolved = socket.gethostbyname(host)
                print(f"  Resolved {cyan(host)} → {cyan(resolved)}")
            except socket.gaierror:
                print(red(f"[!] Cannot resolve host: {host}"))
                sys.exit(1)

    if args.full:
        port_range = "1-65535"
    elif args.top_ports:
        port_range = None
    else:
        port_range = args.ports
    nmap_args = build_nmap_args(args.timing, args.top_ports or 0, args.os_detect, args.nmap_args)

    # Step 1: nmap scan
    try:
        results = scan(" ".join(targets), port_range, nmap_args)
    except KeyboardInterrupt:
        status.stop()
        print(yellow("\n  [!] Scan cancelled."))
        sys.exit(130)

    # Step 2: CVE enrichment
    complete = True
    if not args.no_cve:
        try:
            complete = enrich_results(
                results,
                LookupOptions(
                    nvd_key=args.nvd_key,
                    vulners_key=args.vulners_key,
                    use_osv=not args.no_osv,
                    use_searchsploit=not args.no_searchsploit,
                ),
                workers=args.workers,
                use_kev=not args.no_kev,
                use_epss=not args.no_epss,
                min_severity=args.min_severity or "",
            )
        finally:
            cache.save()
    results["enriched"] = not args.no_cve
    results["complete"] = complete

    # Step 3: print report
    print_results(results, max_cves=args.max_cves, max_exploits=args.max_exploits)

    if previous is not None:
        results["changes"] = compare_results(previous, results)
        print_changes(results["changes"])

    # Step 4: exports
    if args.output:
        save_json(results, args.output)
    if args.csv:
        save_csv(results, args.csv)
    if args.html:
        save_html(results, args.html)

    if not complete:
        sys.exit(130)
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on.upper()]
        if any(SEV_RANK.get(v["severity"], 0) >= threshold
               for h in results["hosts"] for p in h["ports"] for v in p["live_vulns"]):
            print(red(f"  [!] Findings at or above {args.fail_on.upper()} — exiting with code 2"))
            sys.exit(2)

if __name__ == "__main__":
    main()

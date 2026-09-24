"""
recon_tools.py — Passive, read-only checks of the TARGET site plus a report writer.

All target requests are GET-only and go through the existing single-domain
lock (security.build_target_url / validate_url / validate_redirect). The one
external lookup is DNS-over-HTTPS (dns.google) for the target's own hostname —
a public knowledge lookup, like lookup_cve.

  check_dns_records               A/AAAA/MX/NS/TXT/CAA + SPF & DMARC review
  detect_tech_stack               frameworks / servers / libraries + versions
  check_robots_and_security_txt   robots.txt hints, sitemap links, security.txt
  extract_forms_and_endpoints     forms, inputs, API routes, websocket URLs
  trace_redirects                 full redirect chain + HTTP->HTTPS upgrade check
  generate_report                 Markdown report with severity summary

`tools` is imported lazily inside functions (tools.py imports this module).
"""

import os
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

import config
import logger
import security

_REPORT_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,80}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target_host() -> str:
    return urlparse(config.TARGET_BASE_URL).hostname or ""


def _target_get(path: str):
    """GET a target path. Returns (response, redirect_info, url, error_dict_or_None)."""
    import tools
    try:
        url = security.build_target_url(path)
    except security.SecurityError as e:
        logger.log_security_block("recon", str(e))
        return None, None, None, {"error": f"BLOCKED: {e}"}
    tools._enforce_rate_limit()
    try:
        resp, redirect = tools._safe_request("GET", url)
    except RuntimeError as e:
        return None, None, url, {"error": str(e)}
    return resp, redirect, url, None


def _looks_like_html(text: str) -> bool:
    return text.lstrip()[:300].lower().startswith(("<!doctype", "<html", "<head", "<body"))


# ---------------------------------------------------------------------------
# DNS (DNS-over-HTTPS, free, no key)
# ---------------------------------------------------------------------------

def _doh(name: str, rtype: str) -> list:
    resp = requests.get("https://dns.google/resolve", params={"name": name, "type": rtype},
                        headers={"Accept": "application/dns-json"}, timeout=config.SEARCH_TIMEOUT_SECONDS)
    resp.raise_for_status()
    answers = resp.json().get("Answer") or []
    wanted = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}[rtype]
    out = []
    for a in answers:
        if a.get("type") == wanted:
            data = a.get("data", "")
            if rtype == "TXT":
                data = re.sub(r'"\s*"', "", data).strip('"')
            out.append(data)
    return out


def _parent_chain(host: str) -> list:
    """host, then each parent down to a 2-label domain (good enough for SPF/DMARC fallback)."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]


def tool_check_dns_records() -> dict:
    host = _target_host()
    if not host:
        return {"error": "TARGET_BASE_URL has no hostname."}
    if re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host):
        return {"error": "Target is an IP address; DNS record checks need a domain name."}

    records, errors = {}, []
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"):
        try:
            records[rtype] = _doh(host, rtype)
        except (requests.exceptions.RequestException, ValueError) as e:
            errors.append(f"{rtype}: {e}")
            records[rtype] = []

    findings = []
    spf = dmarc = None
    for candidate in _parent_chain(host):
        try:
            txts = records["TXT"] if candidate == host else _doh(candidate, "TXT")
        except (requests.exceptions.RequestException, ValueError):
            continue
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        if spf:
            break
    for candidate in _parent_chain(host):
        try:
            found = [t for t in _doh(f"_dmarc.{candidate}", "TXT") if t.lower().startswith("v=dmarc1")]
        except (requests.exceptions.RequestException, ValueError):
            continue
        if found:
            dmarc = found[0]
            break

    if spf is None:
        findings.append({"severity": "info", "issue": "No SPF record found (only matters if this domain sends email)."})
    else:
        if re.search(r"[+?]all\b", spf):
            findings.append({"severity": "medium", "issue": "SPF ends with +all / ?all — allows anyone to send as this domain."})
        elif not re.search(r"[-~]all\b", spf):
            findings.append({"severity": "low", "issue": "SPF has no '-all' or '~all' terminator."})
    if dmarc is None:
        findings.append({"severity": "info", "issue": "No DMARC record found (only matters if this domain sends email)."})
    else:
        m = re.search(r"\bp=(\w+)", dmarc, re.I)
        policy = m.group(1).lower() if m else "unknown"
        if policy == "none":
            findings.append({"severity": "low", "issue": "DMARC policy is p=none (monitoring only, no enforcement)."})
    if not records["CAA"]:
        findings.append({"severity": "info", "issue": "No CAA record — any CA may issue certificates for this domain."})

    logger.log_event({"tool": "check_dns_records", "host": host})
    result = {"host": host, "records": records, "spf": spf, "dmarc": dmarc, "findings": findings, "source": "dns.google (DNS-over-HTTPS)"}
    if errors:
        result["lookup_errors"] = errors
    return result


# ---------------------------------------------------------------------------
# Tech stack fingerprinting
# ---------------------------------------------------------------------------

_HEADER_SIGNS = [
    ("x-powered-by", None, None), ("server", None, None), ("x-aspnet-version", "ASP.NET", None),
    ("x-generator", None, None), ("x-drupal-cache", "Drupal", None),
    ("cf-ray", "Cloudflare", None), ("x-vercel-id", "Vercel", None), ("x-amz-cf-id", "AWS CloudFront", None),
    ("x-github-request-id", "GitHub Pages", None), ("fly-request-id", "Fly.io", None),
    ("x-nextjs-cache", "Next.js", None), ("x-railway-request-id", "Railway", None),
    ("x-served-by", "Fastly/Varnish", None), ("x-shopify-stage", "Shopify", None),
]
_COOKIE_SIGNS = {"phpsessid": "PHP", "jsessionid": "Java servlet", "connect.sid": "Node.js/Express",
                 "asp.net_sessionid": "ASP.NET", "laravel_session": "Laravel", "csrftoken": "Django",
                 "_rails": "Ruby on Rails", "wordpress_": "WordPress", "__cf_bm": "Cloudflare", "io": "Socket.IO (cookie)"}
_HTML_SIGNS = [
    (r"/wp-content/|/wp-includes/", "WordPress"), (r"/_next/", "Next.js"), (r"__NUXT__|/_nuxt/", "Nuxt"),
    (r"data-reactroot|react(?:\.production)?\.min\.js|__REACT_DEVTOOLS", "React"), (r"ng-version=|angular(?:\.min)?\.js", "Angular"),
    (r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|data-v-[0-9a-f]{6,}", "Vue"), (r"svelte", "Svelte"),
    (r"cdn\.shopify\.com|Shopify\.theme", "Shopify"), (r"wixstatic\.com", "Wix"), (r"squarespace", "Squarespace"),
    (r"googletagmanager\.com|gtag\(", "Google Tag Manager / Analytics"), (r"cdn\.tailwindcss\.com|tailwind", "Tailwind CSS"),
    (r"socket\.io", "Socket.IO"), (r"supabase", "Supabase"), (r"firebase", "Firebase"), (r"/static/js/main\.[0-9a-f]+\.js", "Create React App"),
]
_VERSION_SIGNS = [
    (r"jquery[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "jQuery"), (r"bootstrap[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "Bootstrap"),
    (r"angular(?:js)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "Angular"), (r"react(?:-dom)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "React"),
    (r"vue[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "Vue"), (r"lodash[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "lodash"),
    (r"socket\.io[-.@/]v?(\d+\.\d+(?:\.\d+)?)", "Socket.IO client"),
]


def tool_detect_tech_stack(path: str = "/") -> dict:
    resp, redirect, url, err = _target_get(path or "/")
    if err:
        return err
    tech = {}

    def add(name, evidence, version=None):
        entry = tech.setdefault(name, {"name": name, "evidence": [], "version": None})
        if evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)
        if version and not entry["version"]:
            entry["version"] = version

    for header, label, _ in _HEADER_SIGNS:
        value = resp.headers.get(header)
        if not value:
            continue
        if label:
            add(label, f"header {header}: {value[:80]}")
        else:
            products = re.findall(r"([A-Za-z][\w.\-]*)/(\d[\w.\-]*)", value)
            if products:
                for name, ver in products:
                    add(name, f"header {header}: {value[:80]}", ver)
            else:  # e.g. "cloudflare", "Express"
                add(value.split(",")[0].strip()[:40] or header, f"header {header}: {value[:80]}")

    set_cookie = resp.headers.get("Set-Cookie", "").lower()
    for needle, label in _COOKIE_SIGNS.items():
        if re.search(rf"(^|[,;\s]){re.escape(needle)}", set_cookie):
            add(label, f"cookie name contains '{needle}'")

    body = resp.text or ""
    for pattern, label in _HTML_SIGNS:
        if re.search(pattern, body, re.I):
            add(label, f"page markup matches /{pattern[:40]}/")
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        name, _, ver = gen.group(1).partition(" ")
        add(name, f"meta generator: {gen.group(1)[:80]}", ver or None)
    for pattern, label in _VERSION_SIGNS:
        m = re.search(pattern, body, re.I)
        if m:
            add(label, "script/link filename", m.group(1))

    logger.log_tool_call("detect_tech_stack", path=path, url=url, method="GET", status=resp.status_code)
    techs = sorted(tech.values(), key=lambda t: t["name"].lower())
    with_versions = [f"{t['name']} {t['version']}" for t in techs if t["version"]]
    return {
        "url": url, "status": resp.status_code, "technologies": techs,
        "next_step": ("Run lookup_cve for: " + ", ".join(with_versions)) if with_versions else
                     "No versions exposed — nothing to look up in CVE databases.",
        "note": "Fingerprints are heuristics; confirm before reporting.",
    }


# ---------------------------------------------------------------------------
# robots.txt / security.txt
# ---------------------------------------------------------------------------

def tool_check_robots_and_security_txt() -> dict:
    out = {}

    resp, _, url, err = _target_get("/robots.txt")
    if err:
        out["robots_txt"] = err
    elif resp.status_code == 200 and not _looks_like_html(resp.text):
        disallow, allow, sitemaps, agents = [], [], [], []
        for line in resp.text.splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            k, v = (s.strip() for s in line.split(":", 1))
            k = k.lower()
            if k == "disallow" and v:
                disallow.append(v)
            elif k == "allow" and v:
                allow.append(v)
            elif k == "sitemap" and v:
                sitemaps.append(v)
            elif k == "user-agent":
                agents.append(v)
        out["robots_txt"] = {"present": True, "user_agents": agents[:10], "disallow": disallow[:60],
                             "allow": allow[:30], "sitemaps": sitemaps[:10],
                             "note": "Disallow paths are hints about what the owner wants hidden from crawlers — "
                                     "they are NOT access control; check each is properly protected."}
    else:
        out["robots_txt"] = {"present": False, "status": resp.status_code}

    for candidate in ("/.well-known/security.txt", "/security.txt"):
        resp, _, url, err = _target_get(candidate)
        if err:
            continue
        if resp.status_code == 200 and not _looks_like_html(resp.text):
            fields = {}
            for line in resp.text.splitlines():
                if ":" in line and not line.startswith("#"):
                    k, v = line.split(":", 1)
                    fields.setdefault(k.strip().lower(), []).append(v.strip()[:200])
            out["security_txt"] = {"present": True, "url": url, "fields": fields,
                                   "has_contact": "contact" in fields, "has_expires": "expires" in fields}
            break
    else:
        out["security_txt"] = {"present": False,
                               "note": "No security.txt — consider adding /.well-known/security.txt with a Contact."}

    logger.log_event({"tool": "check_robots_and_security_txt"})
    return out


# ---------------------------------------------------------------------------
# Forms and endpoints
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self._cur = [], None
        self.scripts, self.inline_scripts, self._in_script, self._buf = [], [], False, []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                         "enctype": a.get("enctype", ""), "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or tag).lower(),
                                        "autocomplete": a.get("autocomplete", "")})
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None
        elif tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._buf))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


_ENDPOINT_PATTERNS = [
    r"""["'`](/api/[^"'`\s?#<>]{1,120})""",
    r"""["'`](/[A-Za-z0-9_\-/]{1,80}\.(?:json|php|aspx?|action|do))["'`?]""",
    r"""fetch\(\s*["'`]([^"'`]{1,160})["'`]""",
    r"""axios\.(?:get|post|put|delete|patch)\(\s*["'`]([^"'`]{1,160})["'`]""",
    r"""\.open\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'`]([^"'`]{1,160})["'`]""",
    r"""(wss?://[^\s"'`<>]{1,160})""",
]
_TOKEN_NAME_RE = re.compile(r"csrf|xsrf|token|nonce|authenticity", re.I)


def tool_extract_forms_and_endpoints(path: str = "/", max_scripts: int = 5) -> dict:
    resp, _, url, err = _target_get(path or "/")
    if err:
        return err
    parser = _FormParser()
    try:
        parser.feed(resp.text or "")
        parser.close()
    except Exception:
        pass

    forms = []
    for f in parser.forms[:30]:
        names = [i["name"] for i in f["inputs"]]
        has_password = any(i["type"] == "password" for i in f["inputs"])
        has_token = any(i["type"] == "hidden" and _TOKEN_NAME_RE.search(i["name"]) for i in f["inputs"])
        issues = []
        action_abs = urljoin(url, f["action"]) if f["action"] else url
        if url.startswith("https://") and action_abs.startswith("http://"):
            issues.append("form on an HTTPS page submits to plain HTTP")
        if f["method"] == "POST" and not has_token:
            issues.append("POST form without an obvious CSRF token field (may be handled via headers/cookies)")
        if has_password:
            pw = next(i for i in f["inputs"] if i["type"] == "password")
            if pw["autocomplete"].lower() not in ("off", "new-password", "current-password"):
                issues.append("password field without an autocomplete hint")
            if f["method"] == "GET":
                issues.append("password submitted with GET (ends up in URLs/logs)")
        forms.append({"action": f["action"] or "(same page)", "method": f["method"], "has_password_field": has_password,
                      "input_names": names[:20], "issues": issues})

    sources = [("inline HTML", resp.text or "")] + [("inline script", s) for s in parser.inline_scripts[:10]]
    target_host = _target_host()
    fetched = []
    try:
        limit = max(0, min(int(max_scripts), 10))
    except (TypeError, ValueError):
        limit = 5
    for src in parser.scripts:
        if len(fetched) >= limit:
            break
        full = urljoin(url, src)
        if urlparse(full).hostname != target_host:
            continue
        rel = urlparse(full).path + (f"?{urlparse(full).query}" if urlparse(full).query else "")
        r2, _, _, e2 = _target_get(rel)
        if e2 or r2 is None or r2.status_code != 200:
            continue
        fetched.append(urlparse(full).path)
        sources.append((urlparse(full).path, r2.text or ""))

    endpoints = {}
    for label, text in sources:
        for pat in _ENDPOINT_PATTERNS:
            for m in re.finditer(pat, text):
                ep = m.group(1)
                if ep.startswith(("data:", "javascript:", "#")) or len(ep) < 2:
                    continue
                endpoints.setdefault(ep, label)
                if len(endpoints) >= 80:
                    break

    logger.log_tool_call("extract_forms_and_endpoints", path=path, url=url, method="GET", status=resp.status_code)
    return {
        "url": url, "status": resp.status_code, "forms": forms,
        "endpoints_found": [{"endpoint": e, "seen_in": s} for e, s in list(endpoints.items())[:80]],
        "scripts_analyzed": fetched,
        "note": "Endpoints are extracted with pattern matching — verify with get_page before drawing conclusions.",
    }


# ---------------------------------------------------------------------------
# Redirect chain
# ---------------------------------------------------------------------------

def _trace(start_url: str, max_hops: int = 8) -> dict:
    import tools
    hops, current = [], start_url
    for _ in range(max_hops + 1):
        tools._enforce_rate_limit()
        try:
            r = tools._session.get(current, headers=tools._merge_headers(), timeout=config.REQUEST_TIMEOUT_SECONDS,
                                   allow_redirects=False)
        except requests.exceptions.RequestException as e:
            hops.append({"url": current, "error": str(e)})
            return {"hops": hops, "final_url": current, "ended": "error"}
        hop = {"url": current, "status": r.status_code}
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            hop["location"] = loc
            try:
                nxt = security.validate_redirect(current, loc)
            except security.SecurityError as e:
                hop["blocked"] = str(e)
                hops.append(hop)
                return {"hops": hops, "final_url": current, "ended": "blocked (redirect leaves the allowed domain)"}
            hops.append(hop)
            current = nxt
            continue
        hops.append(hop)
        return {"hops": hops, "final_url": current, "ended": "final response"}
    return {"hops": hops, "final_url": current, "ended": f"stopped after {max_hops} hops (possible redirect loop)"}


def tool_trace_redirects(path: str = "/") -> dict:
    try:
        https_or_http = security.build_target_url(path or "/")
    except security.SecurityError as e:
        logger.log_security_block("trace_redirects", str(e))
        return {"error": f"BLOCKED: {e}"}

    result = {"path": path or "/", "as_configured": _trace(https_or_http)}
    if https_or_http.startswith("https://"):
        http_url = "http://" + https_or_http[len("https://"):]
        try:
            security.validate_url(http_url, context="http variant")
            plain = _trace(http_url)
            first = plain["hops"][0] if plain["hops"] else {}
            upgraded = plain["final_url"].startswith("https://")
            result["plain_http"] = plain
            result["http_upgrades_to_https"] = upgraded
            if not upgraded:
                result["finding"] = {"severity": "medium",
                                     "issue": "Plain HTTP does not redirect to HTTPS (users can be served unencrypted)."}
            elif first.get("status") not in (301, 308):
                result["note"] = f"HTTP->HTTPS redirect uses status {first.get('status')}; 301/308 is preferred for permanence."
        except security.SecurityError as e:
            result["plain_http"] = {"error": f"BLOCKED: {e}"}
    logger.log_event({"tool": "trace_redirects", "path": path})
    return result


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def tool_generate_report(name: str, title: str, summary: str = "", findings: list = None) -> dict:
    """Write a Markdown report to REPORTS_DIR/<name>.md (same fixed folder as save_report)."""
    if not isinstance(name, str) or not _REPORT_NAME_RE.match(name):
        return {"error": "Invalid report name. Use letters, digits, underscore, hyphen (max 80), e.g. 'site_review'."}
    if not isinstance(title, str) or not title.strip():
        return {"error": "title is required."}
    findings = findings if isinstance(findings, list) else []

    clean = []
    for f in findings[:200]:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "info")).lower()
        clean.append({
            "title": str(f.get("title", "Untitled finding"))[:200],
            "severity": sev if sev in _SEV_ORDER else "info",
            "description": str(f.get("description", ""))[:3000],
            "evidence": str(f.get("evidence", ""))[:3000],
            "recommendation": str(f.get("recommendation", ""))[:2000],
        })
    clean.sort(key=lambda x: _SEV_ORDER[x["severity"]])

    counts = {s: sum(1 for f in clean if f["severity"] == s) for s in _SEV_ORDER}
    from datetime import datetime, timezone
    lines = [f"# {title.strip()}", "",
             f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} — target: {config.TARGET_BASE_URL}*", ""]
    if summary:
        lines += ["## Summary", "", str(summary)[:5000], ""]
    lines += ["## Findings overview", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {s.capitalize()} | {counts[s]} |" for s in _SEV_ORDER]
    lines += [""]
    for i, f in enumerate(clean, 1):
        lines += [f"## {i}. [{f['severity'].upper()}] {f['title']}", ""]
        if f["description"]:
            lines += [f["description"], ""]
        if f["evidence"]:
            lines += ["**Evidence**", "", "```", f["evidence"], "```", ""]
        if f["recommendation"]:
            lines += [f"**Recommendation:** {f['recommendation']}", ""]
    if not clean:
        lines += ["_No findings were recorded._", ""]

    reports_dir = config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)
    file_path = os.path.join(reports_dir, f"{name}.md")
    if not os.path.realpath(file_path).startswith(os.path.realpath(reports_dir) + os.sep):
        return {"error": "BLOCKED: resolved path escapes the reports directory."}
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError as e:
        return {"error": f"Failed to write report: {e}"}
    logger.log_event({"tool": "generate_report", "path": file_path, "findings": len(clean)})
    return {"result": f"Report saved to {file_path}", "counts": counts}


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

_P = {"type": "string", "description": "Path on the target site, e.g. '/' or '/login'."}

DEFINITIONS = [
    {"name": "check_dns_records",
     "description": "Look up the target hostname's DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA) and review SPF/DMARC. Read-only, uses public DNS-over-HTTPS.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "detect_tech_stack",
     "description": "Fingerprint the target page's technologies (server, framework, CMS, JS libraries, hosting) and any exposed versions. Follow with lookup_cve for versioned software.",
     "parameters": {"type": "object", "properties": {"path": _P}}},
    {"name": "check_robots_and_security_txt",
     "description": "Fetch and parse robots.txt (disallow hints, sitemaps) and security.txt on the target site.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "extract_forms_and_endpoints",
     "description": "Parse a target page for HTML forms (with basic issue flags such as missing CSRF token or HTTP action) and API endpoints / websocket URLs referenced in inline and same-domain scripts. GET only.",
     "parameters": {"type": "object", "properties": {
         "path": _P,
         "max_scripts": {"type": "integer", "description": "Same-domain script files to analyze (0-10, default 5)."}}}},
    {"name": "trace_redirects",
     "description": "Follow and report the full redirect chain for a target path, and test whether plain HTTP upgrades to HTTPS. Redirects leaving the domain are reported, not followed.",
     "parameters": {"type": "object", "properties": {"path": _P}}},
    {"name": "generate_report",
     "description": "Write a Markdown report (severity summary + findings) to the reports folder. Call this at the end of an assessment with everything you found.",
     "parameters": {"type": "object", "properties": {
         "name": {"type": "string", "description": "File identifier: letters, digits, underscore, hyphen. e.g. 'site_review'."},
         "title": {"type": "string", "description": "Report title."},
         "summary": {"type": "string", "description": "Short executive summary."},
         "findings": {"type": "array", "description": "List of findings.", "items": {
             "type": "object", "properties": {
                 "title": {"type": "string", "description": "Short finding title."},
                 "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Severity."},
                 "description": {"type": "string", "description": "What the issue is and why it matters."},
                 "evidence": {"type": "string", "description": "Observed proof (header value, URL, snippet)."},
                 "recommendation": {"type": "string", "description": "How to fix it."}},
             "required": ["title", "severity"]}}},
         "required": ["name", "title"]}},
]

IMPLEMENTATIONS = {
    "check_dns_records": lambda a: tool_check_dns_records(),
    "detect_tech_stack": lambda a: tool_detect_tech_stack(a.get("path", "/")),
    "check_robots_and_security_txt": lambda a: tool_check_robots_and_security_txt(),
    "extract_forms_and_endpoints": lambda a: tool_extract_forms_and_endpoints(a.get("path", "/"), a.get("max_scripts", 5)),
    "trace_redirects": lambda a: tool_trace_redirects(a.get("path", "/")),
    "generate_report": lambda a: tool_generate_report(a.get("name", ""), a.get("title", ""), a.get("summary", ""), a.get("findings")),
}

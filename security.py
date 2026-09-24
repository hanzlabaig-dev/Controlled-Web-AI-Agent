"""
security.py — THE real enforcement boundary.

Nothing here trusts the LLM. Every function assumes its input may be
adversarial (either from a malicious/careless model, or from a malicious
website via redirects) and validates accordingly.

Design principle: fail closed. If anything is ambiguous, reject.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import config


class SecurityError(Exception):
    """Raised whenever a request would violate the domain/security policy."""


def _get_target_hostname() -> str:
    if not config.TARGET_BASE_URL:
        raise SecurityError("TARGET_BASE_URL is not configured.")
    parsed = urlparse(config.TARGET_BASE_URL)
    if parsed.scheme not in ("http", "https"):
        raise SecurityError("TARGET_BASE_URL must be http:// or https://.")
    if not parsed.hostname:
        raise SecurityError("TARGET_BASE_URL has no hostname.")
    return parsed.hostname.lower()


def _is_private_or_dangerous_ip(hostname: str) -> bool:
    """
    Resolve hostname and check if it (or any of its resolved IPs) points to
    a private, loopback, link-local, or cloud-metadata address.
    """
    dangerous_literal_hosts = {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",  # AWS/GCP/Azure metadata endpoint
    }
    if hostname in dangerous_literal_hosts:
        return True

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Can't resolve — treat as dangerous/unknown rather than allow it.
        return True

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
        # Cloud metadata range 169.254.169.254 is link-local and already caught.
    return False


def validate_url(url: str, *, context: str = "request") -> str:
    """
    Validate that `url` is allowed to be requested. Returns the normalized
    URL if valid, otherwise raises SecurityError. This is the single choke
    point every outgoing request must pass through — including redirect
    targets.
    """
    if not isinstance(url, str) or not url.strip():
        raise SecurityError(f"Empty or invalid URL in {context}.")

    url = url.strip()

    lowered = url.lower()
    if lowered.startswith("javascript:") or lowered.startswith("file:") or lowered.startswith("data:"):
        raise SecurityError(f"Disallowed URL scheme in {context}: {url}")

    target_host = _get_target_hostname()
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise SecurityError(f"Disallowed scheme '{parsed.scheme}' in {context}.")

    if not parsed.hostname:
        raise SecurityError(f"URL has no hostname in {context}: {url}")

    host = parsed.hostname.lower()

    if host != target_host:
        raise SecurityError(
            f"Blocked request to '{host}' — only '{target_host}' is permitted."
        )

    if _is_private_or_dangerous_ip(host):
        raise SecurityError(
            f"Blocked request to '{host}' — resolves to a private, loopback, "
            f"reserved, or metadata address."
        )

    return url


def build_target_url(path: str) -> str:
    """
    Join a path (e.g. "/api/status") onto TARGET_BASE_URL safely, then
    validate the result. Rejects attempts to smuggle a full URL/host via
    the path (e.g. "http://evil.com" or "//evil.com").
    """
    if not isinstance(path, str):
        raise SecurityError("Path must be a string.")

    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path

    # Reject scheme-relative or absolute-URL smuggling attempts in the path.
    if path.startswith("//") or "://" in path:
        raise SecurityError(f"Path attempts to redirect to another host: {path}")

    base = config.TARGET_BASE_URL.rstrip("/")
    full_url = base + path
    return validate_url(full_url, context="constructed path")


def validate_redirect(current_url: str, location_header: str) -> str:
    """
    Validate a redirect target found in a Location header. Resolves
    relative redirects against current_url, then applies the same
    domain/IP checks as any other request.
    """
    from urllib.parse import urljoin

    if not location_header:
        raise SecurityError("Redirect with empty Location header.")

    resolved = urljoin(current_url, location_header)
    return validate_url(resolved, context="redirect target")


def redact_headers(headers: dict) -> dict:
    """Return a copy of headers with sensitive values redacted."""
    redacted = {}
    for key, value in headers.items():
        if key.lower() in config.SENSITIVE_HEADER_NAMES:
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted


def redact_json_body(data):
    """Recursively redact sensitive keys in a JSON-like structure for logging."""
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if isinstance(k, str) and k.lower() in config.SENSITIVE_JSON_KEYS:
                result[k] = "***REDACTED***"
            else:
                result[k] = redact_json_body(v)
        return result
    if isinstance(data, list):
        return [redact_json_body(item) for item in data]
    return data


def enforce_post_body_size(raw_body: bytes) -> None:
    if len(raw_body) > config.MAX_POST_BODY_BYTES:
        raise SecurityError(
            f"POST body of {len(raw_body)} bytes exceeds limit of "
            f"{config.MAX_POST_BODY_BYTES} bytes."
        )


# ---------------------------------------------------------------------------
# Public-internet validation (used ONLY by web_search / fetch_url).
#
# This is deliberately separate from validate_url(): the target-site tools
# stay locked to ONE host, while fetch_url may read any PUBLIC page. It keeps
# every SSRF protection: no private / loopback / link-local / reserved /
# multicast / metadata addresses, no odd schemes, no embedded credentials,
# only common web ports. Every redirect hop must pass through it again.
# ---------------------------------------------------------------------------

_ALLOWED_PUBLIC_PORTS = {80, 443, 8080, 8443}


def _ip_is_public(ip) -> bool:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def validate_public_url(url: str, *, context: str = "fetch") -> str:
    """Return the URL if it points at a public host, else raise SecurityError."""
    if not isinstance(url, str) or not url.strip():
        raise SecurityError(f"Empty or invalid URL in {context}.")
    url = url.strip()

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SecurityError(f"Disallowed scheme '{parsed.scheme}' in {context} (http/https only).")
    if not parsed.hostname:
        raise SecurityError(f"URL has no hostname in {context}.")
    if parsed.username or parsed.password:
        raise SecurityError("URLs with embedded credentials are not allowed.")

    try:
        port = parsed.port
    except ValueError:
        raise SecurityError("Invalid port in URL.")
    if port is not None and port not in _ALLOWED_PUBLIC_PORTS:
        raise SecurityError(f"Port {port} is not allowed (allowed: 80, 443, 8080, 8443).")

    host = parsed.hostname.lower()
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal", ".localhost")):
        raise SecurityError(f"Blocked host '{host}'.")

    # Literal IP in the URL?
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _ip_is_public(literal):
            raise SecurityError(f"Blocked non-public IP address '{host}'.")
        return url

    try:
        infos = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        raise SecurityError(f"Could not resolve host '{host}'.")

    if not infos:
        raise SecurityError(f"Host '{host}' did not resolve.")
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise SecurityError(f"Host '{host}' resolved to an unparseable address.")
        if not _ip_is_public(ip):
            raise SecurityError(f"Blocked '{host}' — it resolves to a non-public address ({ip}).")

    return url

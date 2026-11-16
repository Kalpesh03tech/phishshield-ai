"""
PhishShield AI 2.0 - SSRF Guard Middleware
Prevents Server-Side Request Forgery by validating that target URLs
do not resolve to private, loopback, link-local, or multicast IP ranges.

Applied as FastAPI middleware to intercept all outbound scan requests.
"""

import ipaddress
import socket
import logging
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger('phishshield.ssrf')


class SSRFBlockedError(Exception):
    """Raised when a target URL resolves to a blocked IP range."""

    def __init__(self, url: str, ip: str, reason: str):
        self.url = url
        self.ip = ip
        self.reason = reason
        super().__init__(f"SSRF Blocked: {url} -> {ip} ({reason})")


# RFC 1918 private, loopback, link-local, multicast, and reserved ranges
_BLOCKED_NETWORKS_V4 = [
    ipaddress.IPv4Network('10.0.0.0/8'),         # RFC 1918 Private Class A
    ipaddress.IPv4Network('172.16.0.0/12'),       # RFC 1918 Private Class B
    ipaddress.IPv4Network('192.168.0.0/16'),      # RFC 1918 Private Class C
    ipaddress.IPv4Network('127.0.0.0/8'),         # Loopback
    ipaddress.IPv4Network('169.254.0.0/16'),      # Link-local
    ipaddress.IPv4Network('224.0.0.0/4'),         # Multicast
    ipaddress.IPv4Network('240.0.0.0/4'),         # Reserved
    ipaddress.IPv4Network('0.0.0.0/8'),           # "This" network
    ipaddress.IPv4Network('100.64.0.0/10'),       # Shared Address Space (CGNAT)
    ipaddress.IPv4Network('192.0.0.0/24'),        # IETF Protocol Assignments
    ipaddress.IPv4Network('192.0.2.0/24'),        # TEST-NET-1
    ipaddress.IPv4Network('198.51.100.0/24'),     # TEST-NET-2
    ipaddress.IPv4Network('203.0.113.0/24'),      # TEST-NET-3
    ipaddress.IPv4Network('198.18.0.0/15'),       # Benchmarking
]

_BLOCKED_NETWORKS_V6 = [
    ipaddress.IPv6Network('::1/128'),             # Loopback
    ipaddress.IPv6Network('fc00::/7'),            # Unique Local Address (ULA)
    ipaddress.IPv6Network('fe80::/10'),           # Link-local
    ipaddress.IPv6Network('ff00::/8'),            # Multicast
    ipaddress.IPv6Network('::ffff:0:0/96'),       # IPv4-mapped IPv6
    ipaddress.IPv6Network('100::/64'),            # Discard prefix
    ipaddress.IPv6Network('2001:db8::/32'),       # Documentation
]


def _is_blocked_ip(ip_str: str) -> bool:
    """Check if an IP address falls within any blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in network for network in _BLOCKED_NETWORKS_V4)
    elif isinstance(addr, ipaddress.IPv6Address):
        # Also check IPv4-mapped addresses
        if addr.ipv4_mapped:
            return any(addr.ipv4_mapped in network for network in _BLOCKED_NETWORKS_V4)
        return any(addr in network for network in _BLOCKED_NETWORKS_V6)

    return False


def validate_url_target(url: str) -> str:
    """
    Validates that a URL's hostname does not resolve to a blocked IP range.
    Returns the resolved IP if safe, raises SSRFBlockedError if blocked.
    """
    if not url:
        raise SSRFBlockedError(url, 'N/A', 'Empty URL')

    url_str = url.strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        hostname = (parsed.hostname or '').lower()
    except Exception as e:
        raise SSRFBlockedError(url, 'N/A', f'Invalid URL: {e}')

    if not hostname:
        raise SSRFBlockedError(url, 'N/A', 'Empty hostname')

    # Strip IPv6 bracket notation (e.g., [::1] → ::1)
    clean_host = hostname.strip('[]')

    # Check if hostname is a raw IP address
    try:
        addr = ipaddress.ip_address(clean_host)
        if _is_blocked_ip(clean_host):
            raise SSRFBlockedError(
                url, clean_host,
                f'Direct IP {clean_host} is in a blocked range (private/loopback/multicast)'
            )
        return clean_host
    except ValueError:
        pass  # Not a raw IP, proceed with DNS resolution

    # Resolve hostname to IP and validate
    try:
        resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, socktype, proto, canonname, sockaddr in resolved_ips:
            ip = sockaddr[0]
            if _is_blocked_ip(ip):
                raise SSRFBlockedError(
                    url, ip,
                    f'Hostname {hostname} resolves to blocked IP {ip} (private/loopback/multicast)'
                )
        if resolved_ips:
            return resolved_ips[0][4][0]
    except socket.gaierror:
        pass  # DNS resolution failed — let the scanner handle NXDOMAIN
    except SSRFBlockedError:
        raise

    return hostname


class SSRFGuard(BaseHTTPMiddleware):
    """
    FastAPI middleware that intercepts scan requests and validates
    target URLs against SSRF-vulnerable IP ranges.
    """

    # Routes that accept target URLs for scanning
    SCAN_ROUTES = {'/api/scan', '/api/quick-check', '/api/scan-batch'}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in self.SCAN_ROUTES and request.method in ('POST', 'GET'):
            try:
                if request.method == 'POST' and path != '/api/scan-batch':
                    # Read and validate single URL from JSON body
                    body = await request.body()
                    if body:
                        import json
                        try:
                            data = json.loads(body)
                            target_url = data.get('url', '')
                            if target_url:
                                validate_url_target(target_url)
                        except json.JSONDecodeError:
                            pass

                elif request.method == 'GET':
                    # Validate URL from query params
                    target_url = request.query_params.get('url', '')
                    if target_url:
                        validate_url_target(target_url)

                elif path == '/api/scan-batch' and request.method == 'POST':
                    body = await request.body()
                    if body:
                        import json
                        try:
                            data = json.loads(body)
                            urls = data.get('urls', [])
                            for u in urls[:50]:  # Validate first 50
                                validate_url_target(str(u).strip())
                        except json.JSONDecodeError:
                            pass

            except SSRFBlockedError as e:
                logger.warning(f"SSRF BLOCKED: {e}")
                return JSONResponse(
                    status_code=403,
                    content={
                        'success': False,
                        'error': f'Security Policy: Target URL blocked — {e.reason}',
                        'blocked_ip': e.ip,
                        'ssrf_blocked': True
                    }
                )

        response = await call_next(request)
        return response

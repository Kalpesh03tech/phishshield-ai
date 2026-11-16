"""
PhishShield AI - String, Math & Domain Utility Helpers
"""

import re
import math
from urllib.parse import urlparse
from utils.constants import TRUSTED_DOMAINS, TRUSTED_SUFFIXES


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect randomized DGA domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    prob_map = {}
    for char in text:
        prob_map[char] = prob_map.get(char, 0) + 1
    for count in prob_map.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_address(host: str) -> int:
    """Detects if hostname is a raw IPv4/IPv6 address or hex/octal encoded IP."""
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ipv4_pattern, host):
        return 1
    if re.match(r'^(0x[0-9a-fA-F]+\.?)+$', host) or re.match(r'^(0[0-7]+\.?)+$', host):
        return 1
    return 0


def clean_domain(host: str) -> str:
    """Safely strips leading 'www.' from a hostname without removing 'w' characters."""
    if not host:
        return ''
    host = host.lower().split(':')[0]
    return host[4:] if host.startswith('www.') else host


def is_trusted_domain(raw_url: str) -> bool:
    """Checks if input URL belongs to a verified trusted whitelist domain or suffix."""
    if not raw_url:
        return False

    url_str = raw_url.strip().lower()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        hostname = parsed.netloc.split(':')[0].lower()
    except Exception:
        return False

    clean_host = clean_domain(hostname)

    for domain in TRUSTED_DOMAINS:
        d = clean_domain(domain)
        if clean_host == d or clean_host.endswith('.' + d):
            return True

    for suffix in TRUSTED_SUFFIXES:
        if hostname.endswith(suffix):
            return True

    return False

"""
PhishShield AI - Input Validation & URL Format Checking Module
"""

import re


def is_valid_url_format(raw_url: str) -> bool:
    """Validates if input string is a plausible URL, domain name, localhost, or IP host."""
    if not raw_url or len(raw_url.strip()) < 3:
        return False
    url = raw_url.strip().lower()

    if url.startswith(('http://', 'https://')):
        return len(url.replace('http://', '').replace('https://', '').strip()) >= 3

    # Localhost & Loopback Dev Hosts (e.g. localhost, localhost:5005, 127.0.0.1:8080)
    host_only = url.split('/')[0].split(':')[0]
    if host_only in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
        return True

    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}', url):
        return True

    if re.match(r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z0-9.-]{2,}', url):
        return True

    return False

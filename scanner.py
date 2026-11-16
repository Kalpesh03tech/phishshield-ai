"""
PhishShield AI - Unified Real-Time Web Security Scanner & Feature Engine
Consolidates live DNS resolution, SSL/TLS inspection, HTML content crawling,
lexical feature extraction, and explainable risk factor computation into a single clean module.
"""

import re
import ssl
import socket
import urllib.request
import urllib.error
import html as html_lib
from datetime import datetime
from urllib.parse import urlparse

from config import DNS_TIMEOUT, SSL_TIMEOUT, HTTP_TIMEOUT
from utils.constants import (
    SHORTENERS, SUSPICIOUS_KEYWORDS, AUTH_SCAM_KEYWORDS,
    TARGET_IMPERSONATION_BRANDS, HIGH_RISK_TLDS, SENSITIVE_EXTENSIONS,
    OBFUSCATION_PATTERNS, CREDENTIAL_FIELDS
)
from utils.helpers import calculate_entropy, is_ip_address, clean_domain, is_trusted_domain
from services.logger import logger


TRACKING_PARAMS = {
    'gclid', 'fbclid', 'gbraid', 'wbraid', 'gad_source', 'gad_campaignid',
    'msclkid', 'yclid', 'mc_eid', '_ga', 'utm_source', 'utm_medium',
    'utm_campaign', 'utm_term', 'utm_content', 'ref'
}


# Real-World Levenshtein Brand Typosquatting Analyzer
def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_brand_typosquatting(hostname: str) -> dict:
    """Detects real-world brand typosquatting & homograph imposter domains."""
    if not hostname:
        return {'is_typosquatting': False, 'spoofed_brand': None, 'distance': 99, 'detail': ''}

    clean_host = clean_domain(hostname).lower()
    sub_tokens = [t for t in re.split(r'[\.\-]', clean_host) if t and t not in ('www', 'com', 'org', 'net', 'in', 'co', 'io', 'xyz', 'top', 'live', 'app', 'site', 'bank', 'edu', 'gov')]
    if not sub_tokens:
        return {'is_typosquatting': False, 'spoofed_brand': None, 'distance': 99, 'detail': ''}

    MAJOR_BRANDS = [
        'paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'facebook',
        'instagram', 'whatsapp', 'telegram', 'chase', 'wellsfargo', 'bankofamerica',
        'citibank', 'paytm', 'phonepe', 'sbi', 'hdfc', 'icici', 'axis', 'kotak',
        'steam', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex', 'usps', 'icloud', 'github',
        'adobe', 'linkedin', 'twitter', 'x', 'dropbox', 'spotify', 'discord', 'airbnb', 'uber',
        'ebay', 'walmart', 'target', 'roblox', 'openai', 'chatgpt', 'cloudflare', 'fastly',
        'mcafee', 'norton', 'avast', 'kaspersky', 'sophos', 'cisco', 'oracle', 'ibm',
        'salesforce', 'stripe', 'razorpay', 'square', 'wise', 'revolut', 'zelle', 'venmo',
        'airport', 'airline', 'flight', 'booking', 'expedia', 'delta', 'united', 'american',
        'lufthansa', 'emirates', 'qatar', 'ryanair'
    ]

    for token in sub_tokens:
        for brand in MAJOR_BRANDS:
            if token == brand:
                continue
            dist = _levenshtein_distance(token, brand)
            if 1 <= dist <= 2 and len(token) >= 4:
                return {
                    'is_typosquatting': True,
                    'spoofed_brand': brand.upper(),
                    'distance': dist,
                    'detail': f'Subdomain/label token "{token}" is a {dist}-character typosquatting imposter of official brand {brand.upper()}'
                }

    return {'is_typosquatting': False, 'spoofed_brand': None, 'distance': 99, 'detail': ''}



# ================= 1. LIVE DNS & DOMAIN INSPECTION =================


def inspect_domain_live(raw_url: str) -> dict:
    """Performs live DNS socket resolution & web server connectivity check."""
    if not raw_url:
        return {'exists': False, 'ip_address': None, 'is_active_site': False, 'dns_status': 'NO_INPUT', 'error_reason': 'No URL provided'}

    url_str = raw_url.strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        hostname = parsed.netloc.split(':')[0].lower()
    except Exception as e:
        return {'exists': False, 'ip_address': None, 'is_active_site': False, 'dns_status': 'INVALID_URL', 'error_reason': str(e)}

    if is_ip_address(hostname):
        return {
            'exists': True,
            'ip_address': hostname,
            'is_active_site': True,
            'dns_status': 'DIRECT_IP_HOST',
            'error_reason': None
        }

    resolved_ip = None
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return {
            'exists': False,
            'ip_address': None,
            'is_active_site': False,
            'dns_status': 'NXDOMAIN (Unregistered / Taken Down)',
            'error_reason': f'Domain does not exist on global DNS ({e.strerror})'
        }
    except Exception as e:
        return {
            'exists': False,
            'ip_address': None,
            'is_active_site': False,
            'dns_status': 'DNS_LOOKUP_FAILED',
            'error_reason': str(e)
        }

    is_active_site = False
    try:
        req = urllib.request.Request(url_str, headers={'User-Agent': 'Mozilla/5.0'}, method='HEAD')
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            is_active_site = True
    except urllib.error.HTTPError:
        is_active_site = True
    except Exception:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url_str, headers={'User-Agent': 'Mozilla/5.0'}, method='GET')
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                is_active_site = True
        except urllib.error.HTTPError:
            is_active_site = True
        except Exception:
            is_active_site = False

    return {
        'exists': True,
        'ip_address': resolved_ip,
        'is_active_site': is_active_site,
        'dns_status': 'ACTIVE_DNS_RESOLVED',
        'error_reason': None
    }


# ================= 2. LIVE SSL/TLS CERTIFICATE INSPECTION =================

def inspect_ssl_cert(raw_url: str) -> dict:
    """Inspects SSL certificate for an HTTPS domain."""
    if not raw_url:
        return {'has_ssl': False, 'is_valid': False, 'issuer': None, 'days_left': 0, 'cert_warnings': ['No URL provided']}

    url_str = raw_url.strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'https://' + url_str

    try:
        parsed = urlparse(url_str)
        hostname = parsed.netloc.split(':')[0].lower()
        port = int(parsed.port) if parsed.port else 443
    except Exception as e:
        return {'has_ssl': False, 'is_valid': False, 'issuer': None, 'days_left': 0, 'cert_warnings': [str(e)]}

    if not url_str.lower().startswith('https://') or is_ip_address(hostname):
        return {
            'has_ssl': False,
            'is_valid': False,
            'issuer': 'None (Unencrypted HTTP)',
            'days_left': 0,
            'valid_from': None,
            'valid_to': None,
            'protocol_version': 'HTTP (Unencrypted)',
            'is_expired': False,
            'cert_warnings': []
        }

    cert_warnings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        issuer = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Unknown Authority'

        valid_from_str = cert.get('notBefore')
        valid_to_str = cert.get('notAfter')
        
        valid_from = datetime.strptime(valid_from_str, '%b %d %H:%M:%S %Y %Z') if valid_from_str else datetime.now()
        valid_to = datetime.strptime(valid_to_str, '%b %d %H:%M:%S %Y %Z') if valid_to_str else datetime.now()

        now = datetime.utcnow()
        days_left = (valid_to - now).days
        is_expired = days_left < 0

        if is_expired:
            cert_warnings.append(f'SSL Certificate expired {abs(days_left)} days ago!')
        elif days_left <= 7:
            cert_warnings.append(f'SSL Certificate expires soon ({days_left} days remaining)')

        return {
            'has_ssl': True,
            'is_valid': not is_expired,
            'issuer': issuer,
            'days_left': max(0, days_left),
            'valid_from': valid_from.strftime('%Y-%m-%d'),
            'valid_to': valid_to.strftime('%Y-%m-%d'),
            'protocol_version': version or 'TLSv1.3',
            'is_expired': is_expired,
            'cert_warnings': cert_warnings
        }

    except ssl.SSLCertVerificationError as e:
        return {
            'has_ssl': True,
            'is_valid': False,
            'issuer': 'Untrusted / Self-Signed Authority',
            'days_left': 0,
            'protocol_version': 'TLS (Untrusted)',
            'is_expired': True,
            'cert_warnings': [f'SSL Verification Failed: Invalid/Self-Signed Certificate ({e.verify_message})']
        }
    except Exception:
        return {
            'has_ssl': False,
            'is_valid': False,
            'issuer': 'HTTP (Unencrypted / No SSL)',
            'days_left': 0,
            'valid_from': None,
            'valid_to': None,
            'protocol_version': 'HTTP',
            'is_expired': False,
            'cert_warnings': []
        }


# ================= 3. LIVE HTML WEBSITE CONTENT ANALYZER =================

def _fetch_page_html(url: str) -> tuple:
    """Fetches live page HTML content safely over HTTP/HTTPS with automatic decompression."""
    import gzip
    import zlib

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate'
    }
    url_str = url if url.startswith(('http://', 'https://')) else 'http://' + url
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url_str, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            final_url = resp.geturl()
            status = resp.status
            resp_headers = dict(resp.headers)
            content_bytes = resp.read(1500000)  # Max 1.5MB read

            encoding = resp_headers.get('content-encoding', '').lower()
            if 'gzip' in encoding:
                try:
                    content_bytes = gzip.decompress(content_bytes)
                except Exception:
                    pass
            elif 'deflate' in encoding:
                try:
                    content_bytes = zlib.decompress(content_bytes)
                except Exception:
                    pass

            html = content_bytes.decode('utf-8', errors='ignore')
            return html, final_url, status, '', resp_headers
    except urllib.error.HTTPError as e:
        return '', url_str, e.code, f'HTTP Error {e.code}: {e.reason}', {}
    except Exception as e:
        return '', url_str, 0, str(e), {}


def analyze_website(raw_url: str, pre_fetched_html: str = None) -> dict:
    """Performs deep HTML website content & metadata analysis."""
    signals = []
    content_score = 0.0

    if not raw_url:
        return {'content_score': 0.0, 'signals': [], 'error': 'No URL provided', 'analyzed': False}

    if pre_fetched_html:
        html = pre_fetched_html
        final_url = raw_url
        http_status = 200
        fetch_error = ''
        resp_headers = {}
    else:
        html, final_url, http_status, fetch_error, resp_headers = _fetch_page_html(raw_url)

    if not html:
        return {
            'content_score': 0.0,
            'signals': [],
            'error': fetch_error or 'Could not fetch page content',
            'analyzed': False,
            'final_url': final_url,
            'http_status': http_status,
            'page_title': '',
            'meta_description': '',
            'headings_summary': '',
            'server_header': 'N/A',
            'has_hsts': False,
            'has_csp': False,
            'form_action_domains': [],
            'redirect_detected': False,
            'has_password_field': False,
            'form_count': 0,
            'external_script_count': 0
        }

    try:
        parsed_orig = urlparse(raw_url)
        parsed_final = urlparse(final_url)
        orig_host = clean_domain(parsed_orig.netloc)
        final_host = clean_domain(parsed_final.netloc)
    except Exception:
        orig_host = ''
        final_host = ''

    # Check Brand Typosquatting
    typo_info = detect_brand_typosquatting(orig_host or final_host)
    if typo_info.get('is_typosquatting'):
        content_score += 50.0
        signals.append({
            'signal': f'Brand Typosquatting Imposter ({typo_info.get("spoofed_brand")})',
            'severity': 'CRITICAL',
            'detail': typo_info.get('detail'),
            'icon': 'fa-mask'
        })

    has_password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE))

    if has_password_field:
        content_score += 15.0
        signals.append({
            'signal': 'Password Input Field Detected',
            'severity': 'MEDIUM',
            'detail': 'Page contains a password input field — verify this is a legitimate login page.',
            'icon': 'fa-key'
        })

    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    for action in form_actions:
        if action.startswith(('http://', 'https://')):
            act_host = clean_domain(urlparse(action).netloc)
            if act_host and orig_host and act_host != orig_host:
                content_score += 45.0
                signals.append({
                    'signal': 'External Form Exfiltration Target',
                    'severity': 'CRITICAL',
                    'detail': f'HTML form submits sensitive data to external domain: {act_host}',
                    'icon': 'fa-triangle-exclamation'
                })
                break

    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            content_score += 35.0
            signals.append({
                'signal': 'Obfuscated JavaScript Payload',
                'severity': 'HIGH',
                'detail': 'Page contains obfuscated JS execution patterns (eval/unescape/atob).',
                'icon': 'fa-code-compare'
            })
            break

    if not signals:
        signals.append({
            'signal': 'Page Content Appears Clean',
            'severity': 'SAFE',
            'detail': 'No phishing indicators found in page HTML.',
            'icon': 'fa-circle-check'
        })

    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    page_title = html_lib.unescape(re.sub(r'\s+', ' ', title_match.group(1)).strip())[:150] if title_match else ''

    meta_desc_m = re.search(r'<meta[^>]*name=["\'](?:description|og:description)["\'][^>]*content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    meta_desc = html_lib.unescape(meta_desc_m.group(1).strip())[:200] if meta_desc_m else ''

    headings = [html_lib.unescape(re.sub(r'<[^>]+>', '', h).strip()) for h in re.findall(r'<h[12][^>]*>(.*?)</h[12]>', html, re.IGNORECASE | re.DOTALL)]
    headings_summary = ' | '.join([h for h in headings if h][:3])[:200]

    server_header = resp_headers.get('server', 'N/A')
    has_hsts = 'strict-transport-security' in resp_headers
    has_csp = 'content-security-policy' in resp_headers

    form_domains = list(set([clean_domain(urlparse(a).netloc) for a in form_actions if clean_domain(urlparse(a).netloc)]))

    return {
        'analyzed': True,
        'content_score': round(min(100.0, content_score), 1),
        'signals': signals,
        'page_title': page_title,
        'meta_description': meta_desc,
        'headings_summary': headings_summary,
        'server_header': server_header,
        'has_hsts': has_hsts,
        'has_csp': has_csp,
        'form_action_domains': form_domains,
        'final_url': final_url,
        'http_status': http_status,
        'redirect_detected': raw_url.rstrip('/').lower() != final_url.rstrip('/').lower(),
        'has_password_field': has_password_field,
        'form_count': len(form_actions),
        'external_script_count': len(re.findall(r'<script[^>]*src=["\']?https?://', html, re.IGNORECASE)),
        'error': ''
    }


# ================= 4. FEATURE EXTRACTION ENGINE =================

def sanitize_url_query(raw_url: str) -> str:
    """Strips standard ad tracking query parameters (gclid, utm_*, fbclid)."""
    try:
        parsed = urlparse(raw_url)
        if not parsed.query:
            return raw_url
        params = parsed.query.split('&')
        clean_params = [p for p in params if p.split('=')[0].lower() not in TRACKING_PARAMS]
        clean_query = '&'.join(clean_params)
        return parsed._replace(query=clean_query).geturl()
    except Exception:
        return raw_url


def extract_features(raw_url: str) -> dict:
    """Extracts 30 distinct lexical and structural feature metrics from a URL."""
    clean_url = sanitize_url_query(raw_url.strip())
    url = clean_url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse('http://invalid-url.local')

    hostname = parsed.netloc.lower()
    hostname_clean = hostname.split(':')[0]
    path = parsed.path
    query = parsed.query

    url_len = len(clean_url)
    host_len = len(hostname_clean)
    path_len = len(path)
    query_len = len(query)

    count_dots = clean_url.count('.')
    count_hyphens = clean_url.count('-')
    count_at = clean_url.count('@')
    count_question = clean_url.count('?')
    count_equal = clean_url.count('=')
    count_percent = clean_url.count('%')
    count_slash = clean_url.count('/')
    count_digits = sum(c.isdigit() for c in clean_url)
    digit_ratio = round(count_digits / url_len, 4) if url_len > 0 else 0.0

    domain_parts = [p for p in hostname_clean.split('.') if p and p != 'www']
    subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) >= 2 else 0

    has_ip = is_ip_address(hostname_clean)
    is_shortened = 1 if (hostname_clean in SHORTENERS or any(hostname_clean.endswith('.' + s) for s in SHORTENERS)) else 0
    has_hyphen_domain = 1 if '-' in hostname_clean else 0

    tld = domain_parts[-1] if domain_parts else ''
    suspicious_tld = 1 if tld in HIGH_RISK_TLDS else 0

    url_lower = clean_url.lower()
    suspicious_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    is_official_domain = is_trusted_domain(clean_url)

    has_scam_kw_domain = any(kw in hostname_clean for kw in AUTH_SCAM_KEYWORDS)
    has_brand_kw_domain = any(b in hostname_clean for b in TARGET_IMPERSONATION_BRANDS)
    
    if is_official_domain:
        suspicious_kw_in_domain = 0
    else:
        suspicious_kw_in_domain = 1 if (has_scam_kw_domain or (has_brand_kw_domain and (has_hyphen_domain or subdomain_count > 0))) else 0

    shannon_entropy_host = calculate_entropy(hostname_clean)
    shannon_entropy_url = calculate_entropy(clean_url)

    is_https = 1 if clean_url.lower().startswith('https://') else 0
    has_port = 1 if ':' in hostname and not has_ip else 0

    has_double_slash_path = 1 if '//' in path else 0
    is_punycode = 1 if 'xn--' in hostname_clean else 0
    path_depth = len([segment for segment in path.split('/') if segment])
    has_sensitive_ext = 1 if any(path.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS) else 0
    param_count = len(query.split('&')) if query else 0
    hex_encoding_count = len(re.findall(r'%[0-9a-fA-F]{2}', clean_url))

    # Advanced Feature Engineering
    typo_check = detect_brand_typosquatting(hostname_clean)
    is_typosquatting = 1 if (typo_check.get('is_typosquatting') and not is_official_domain) else 0

    has_tracking_params = 1 if any(tp in query.lower() for tp in TRACKING_PARAMS) else 0
    has_fragment_hash = 1 if '#' in clean_url else 0

    return {
        'url': clean_url,
        'url_length': url_len,
        'hostname_length': host_len,

        'path_length': path_len,
        'query_length': query_len,
        'count_dots': count_dots,
        'count_hyphens': count_hyphens,
        'count_at': count_at,
        'count_question': count_question,
        'count_equal': count_equal,
        'count_percent': count_percent,
        'count_slash': count_slash,
        'count_digits': count_digits,
        'digit_ratio': digit_ratio,
        'subdomain_count': subdomain_count,
        'has_ip': has_ip,
        'is_shortened': is_shortened,
        'has_hyphen_domain': has_hyphen_domain,
        'suspicious_kw_count': suspicious_kw_count,
        'suspicious_kw_in_domain': suspicious_kw_in_domain,
        'suspicious_tld': suspicious_tld,
        'shannon_entropy_host': shannon_entropy_host,
        'shannon_entropy_url': shannon_entropy_url,
        'is_https': is_https,
        'has_port': has_port,
        'has_double_slash_path': has_double_slash_path,
        'is_punycode': is_punycode,
        'path_depth': path_depth,
        'has_sensitive_ext': has_sensitive_ext,
        'param_count': param_count,
        'hex_encoding_count': hex_encoding_count,
        'is_typosquatting': is_typosquatting,
        'spoofed_brand': typo_check.get('spoofed_brand'),
        'has_tracking_params': has_tracking_params,
        'has_fragment_hash': has_fragment_hash
    }


FEATURE_NAMES = [
    'url_length', 'hostname_length', 'path_length', 'query_length',
    'count_dots', 'count_hyphens', 'count_at', 'count_question',
    'count_equal', 'count_percent', 'count_slash', 'count_digits',
    'digit_ratio', 'subdomain_count', 'has_ip', 'is_shortened',
    'has_hyphen_domain', 'suspicious_kw_count', 'suspicious_kw_in_domain',
    'suspicious_tld', 'shannon_entropy_host', 'shannon_entropy_url',
    'is_https', 'has_port', 'has_double_slash_path', 'is_punycode',
    'path_depth', 'has_sensitive_ext', 'param_count', 'hex_encoding_count'
]


def extract_feature_vector(raw_url: str) -> list:
    """Converts extracted feature dict to ordered list for ML model input."""
    feat_dict = extract_features(raw_url)
    return [feat_dict[name] for name in FEATURE_NAMES]


# ================= 5. EXPLAINABLE RISK SCORING ENGINE =================

def calculate_heuristic_risk(feat: dict) -> float:
    """Calculates expert heuristic rule-based risk score (0-100%)."""
    score = 0.0
    if feat.get('is_typosquatting') == 1: score += 45.0
    if feat.get('has_ip') == 1: score += 40.0
    if feat.get('is_punycode') == 1: score += 35.0
    if feat.get('suspicious_kw_in_domain') == 1: score += 30.0
    if feat.get('suspicious_kw_count', 0) > 0: score += min(35.0, feat['suspicious_kw_count'] * 12.0)
    if feat.get('suspicious_tld') == 1: score += 25.0
    if feat.get('is_shortened') == 1: score += 20.0
    if feat.get('has_hyphen_domain') == 1: score += 15.0
    if feat.get('has_sensitive_ext') == 1: score += 20.0
    if feat.get('digit_ratio', 0.0) > 0.35: score += 15.0
    if feat.get('shannon_entropy_host', 0.0) > 4.2: score += 25.0
    if feat.get('is_https') == 0: score += 15.0
    if feat.get('has_tracking_params') == 1: score += 10.0

    return min(100.0, score)


def generate_explainable_signals(feat: dict) -> list:
    """Evaluates extracted feature values and returns explainable threat factors (XAI)."""
    signals = []

    # Check Real-World Brand Typosquatting
    if feat.get('is_typosquatting') == 1:
        brand_name = feat.get('spoofed_brand') or 'Official Brand'
        signals.append({
            'factor': 'Brand Typosquatting Imposter',
            'severity': 'CRITICAL',
            'impact': '+45%',
            'description': f'Hostname label is a typosquatting imposter mimicking the official brand {brand_name}.'
        })
    elif feat.get('url'):
        try:
            host_val = urlparse(feat['url'] if feat['url'].startswith(('http://', 'https://')) else 'http://' + feat['url']).netloc
            typo_info = detect_brand_typosquatting(host_val)
            if typo_info.get('is_typosquatting') and not is_trusted_domain(feat['url']):
                signals.append({
                    'factor': 'Brand Typosquatting Imposter',
                    'severity': 'CRITICAL',
                    'impact': '+45%',
                    'description': typo_info.get('detail')
                })
        except Exception:
            pass

    if feat.get('has_ip') == 1:
        signals.append({'factor': 'IP Address Hostname', 'severity': 'CRITICAL', 'impact': '+35%', 'description': 'URL uses a raw IP address instead of a domain name — signature of phishing/malware distribution.'})


    if feat.get('is_punycode') == 1:
        signals.append({'factor': 'Punycode Homograph Spoofing', 'severity': 'CRITICAL', 'impact': '+35%', 'description': 'Domain uses Internationalized Domain Name (IDN) Punycode (xn--) to mimic a legitimate brand.'})

    if feat.get('suspicious_kw_in_domain') == 1 and not is_trusted_domain(feat.get('url', '')):
        signals.append({'factor': 'Domain Brand/Keyword Spoofing', 'severity': 'HIGH', 'impact': '+30%', 'description': 'Domain contains high-risk auth/brand keywords combined with hyphen or subdomain tricks.'})

    if feat.get('is_shortened') == 1:
        signals.append({'factor': 'URL Shortener Redirection', 'severity': 'MEDIUM', 'impact': '+20%', 'description': 'URL uses a shortening service to hide the true landing destination.'})

    if feat.get('suspicious_tld') == 1:
        signals.append({'factor': 'High-Risk Cheap/Free TLD', 'severity': 'HIGH', 'impact': '+25%', 'description': 'Registered under a top-level domain frequently associated with automated scam generation.'})

    if feat.get('shannon_entropy_host', 0.0) > 4.2:
        signals.append({'factor': 'High Shannon Entropy Hostname', 'severity': 'HIGH', 'impact': '+25%', 'description': f'Hostname has an entropy of {feat.get("shannon_entropy_host")} bits, indicating Domain Generation Algorithm (DGA) randomness.'})

    if feat.get('has_sensitive_ext') == 1:
        signals.append({'factor': 'Executable/Sensitive Extension', 'severity': 'HIGH', 'impact': '+20%', 'description': 'URL path targets an executable file extension.'})

    if feat.get('is_https') == 0:
        signals.append({'factor': 'Unencrypted HTTP Connection', 'severity': 'MEDIUM', 'impact': '+15%', 'description': 'Page operates over unencrypted HTTP — any transmitted data can be intercepted.'})

    if feat.get('has_tracking_params') == 1:
        signals.append({'factor': 'Tracking Redirect Parameters', 'severity': 'LOW', 'impact': '+10%', 'description': 'URL query string contains redirection or ad-tracking parameters frequently used in open-redirect attacks.'})

    if not signals:
        signals.append({'factor': 'No Structural Anomaly', 'severity': 'SAFE', 'impact': '0%', 'description': 'URL structure and domain features fall within normal legitimate baseline ranges.'})

    return signals


def calculate_radar_vectors(feat: dict, risk_score: float) -> dict:
    """Computes normalized 0-100 radar chart values for 5 threat dimensions."""
    lexical = min(100.0, (feat.get('url_length', 0) / 120.0 * 40) + (feat.get('count_dots', 0) * 12) + (feat.get('count_hyphens', 0) * 10))
    keyword = min(100.0, feat.get('suspicious_kw_count', 0) * 30 + (45 if feat.get('suspicious_kw_in_domain') else 0))
    domain_rep = min(100.0, (40 if feat.get('has_ip') else 0) + (35 if feat.get('suspicious_tld') else 0) + (25 if feat.get('is_shortened') else 0))
    entropy_val = min(100.0, max(0.0, (feat.get('shannon_entropy_host', 0.0) - 2.5) * 35.0))
    structural = min(100.0, (35 if feat.get('is_punycode') else 0) + (25 if feat.get('has_sensitive_ext') else 0) + (20 if feat.get('is_https') == 0 else 0))

    return {
        'Lexical Anomaly': round(lexical, 1),
        'Keyword Threat': round(keyword, 1),
        'Domain Reputation': round(domain_rep, 1),
        'Entropy Randomness': round(entropy_val, 1),
        'Structural Risk': round(structural, 1)
    }


def calculate_ensemble_score(xgb_prob: float, rf_prob: float, mlp_prob: float) -> tuple:
    """Calculates weighted ensemble risk score from ML model probabilities (0-100%)."""
    xgb_score = round(float(xgb_prob) * 100.0, 1)
    rf_score = round(float(rf_prob) * 100.0, 1)
    mlp_score = round(float(mlp_prob) * 100.0, 1)

    ensemble_val = round((xgb_score * 0.40) + (rf_score * 0.35) + (mlp_score * 0.25), 1)
    return ensemble_val, xgb_score, rf_score, mlp_score


def generate_infrastructure_graph(raw_url: str, live_info: dict, ssl_info: dict, feat_dict: dict, typosquat_info: dict = None, threat_intel: dict = None) -> dict:
    """Generates structured nodes and edges for Vis.js dynamic network graph rendering."""
    try:
        parsed = urlparse(raw_url if raw_url.startswith(('http://', 'https://')) else 'http://' + raw_url)
        hostname = parsed.netloc.split(':')[0].lower() if parsed.netloc else raw_url
    except Exception:
        hostname = raw_url

    nodes = []
    edges = []

    # 1. Main Target Node
    nodes.append({
        'id': 'target_url',
        'label': hostname,
        'group': 'target',
        'title': f'Target Host: {hostname}\nFull URL: {raw_url}',
        'shape': 'dot',
        'size': 25,
        'color': {'background': '#38bdf8', 'border': '#0284c7'}
    })

    # 2. Resolved IP Node
    if live_info and live_info.get('ip_address'):
        ip_addr = live_info['ip_address']
        nodes.append({
            'id': 'ip_node',
            'label': f'IP: {ip_addr}',
            'group': 'ip',
            'title': f'Resolved IPv4 Address: {ip_addr}\nStatus: {live_info.get("dns_status", "Active")}',
            'shape': 'diamond',
            'size': 20,
            'color': {'background': '#a855f7', 'border': '#9333ea'}
        })
        edges.append({'from': 'target_url', 'to': 'ip_node', 'label': 'DNS A-Record', 'color': {'color': '#a855f7'}})
    else:
        nodes.append({
            'id': 'ip_node',
            'label': 'DNS: Unresolved',
            'group': 'warning',
            'title': 'Domain does not resolve on global DNS',
            'shape': 'triangle',
            'size': 18,
            'color': {'background': '#ef4444', 'border': '#dc2626'}
        })
        edges.append({'from': 'target_url', 'to': 'ip_node', 'label': 'Unresolved', 'color': {'color': '#ef4444'}, 'dashes': True})

    # 3. SSL Cert Node
    if ssl_info and ssl_info.get('has_ssl'):
        issuer = ssl_info.get('issuer', 'Valid SSL/TLS')
        days = ssl_info.get('days_left', 0)
        nodes.append({
            'id': 'ssl_node',
            'label': f'SSL: {issuer}',
            'group': 'ssl',
            'title': f'Issuer: {issuer}\nDays Valid: {days} days',
            'shape': 'star',
            'size': 20,
            'color': {'background': '#10b981', 'border': '#059669'}
        })
        edges.append({'from': 'target_url', 'to': 'ssl_node', 'label': 'HTTPS Encrypted', 'color': {'color': '#10b981'}})
    else:
        nodes.append({
            'id': 'ssl_node',
            'label': 'No SSL (HTTP)',
            'group': 'warning',
            'title': 'Unencrypted connection (HTTP only)',
            'shape': 'square',
            'size': 18,
            'color': {'background': '#f59e0b', 'border': '#d97706'}
        })
        edges.append({'from': 'target_url', 'to': 'ssl_node', 'label': 'Unencrypted', 'color': {'color': '#f59e0b'}, 'dashes': True})

    # 4. Brand Impersonation / Typosquat Node
    if typosquat_info and typosquat_info.get('is_typosquatting'):
        brand = typosquat_info.get('spoofed_brand', 'UNKNOWN')
        nodes.append({
            'id': 'brand_node',
            'label': f'Target: {brand}',
            'group': 'threat',
            'title': f'Detected Brand Impersonation: {brand}\nDetail: {typosquat_info.get("detail", "")}',
            'shape': 'hexagon',
            'size': 22,
            'color': {'background': '#f43f5e', 'border': '#e11d48'}
        })
        edges.append({'from': 'target_url', 'to': 'brand_node', 'label': 'Impersonates', 'color': {'color': '#f43f5e'}, 'width': 3})

    # 5. Threat Intelligence Nodes (VirusTotal)
    if threat_intel:
        vt = threat_intel.get('virustotal', {})
        if vt.get('vt_checked') and vt.get('flagged'):
            mal_cnt = vt.get('malicious_count', 0)
            tot_eng = vt.get('total_engines', 0)
            nodes.append({
                'id': 'vt_node',
                'label': f'VirusTotal: {mal_cnt}/{tot_eng} Malicious',
                'group': 'threat',
                'title': f'Flagged by {mal_cnt} vendors on VirusTotal',
                'shape': 'database',
                'size': 20,
                'color': {'background': '#ef4444', 'border': '#b91c1c'}
            })
            edges.append({'from': 'target_url', 'to': 'vt_node', 'label': 'AV Detections', 'color': {'color': '#ef4444'}})
        elif vt.get('vt_checked'):
            tot_eng = vt.get('total_engines', 0)
            nodes.append({
                'id': 'vt_node',
                'label': f'VirusTotal: Clean (0/{tot_eng})',
                'group': 'clean',
                'title': 'No security vendor flags on VirusTotal',
                'shape': 'database',
                'size': 18,
                'color': {'background': '#10b981', 'border': '#047857'}
            })
            edges.append({'from': 'target_url', 'to': 'vt_node', 'label': 'Clean Reputation', 'color': {'color': '#10b981'}})

    # 6. TLD Category Node
    tld = hostname.split('.')[-1] if '.' in hostname else 'TLD'
    is_bad_tld = feat_dict.get('suspicious_tld') == 1
    nodes.append({
        'id': 'tld_node',
        'label': f'TLD: .{tld}',
        'group': 'tld',
        'title': 'Suspicious TLD' if is_bad_tld else 'Standard Domain Extension',
        'shape': 'ellipse',
        'size': 16,
        'color': {'background': '#f43f5e' if is_bad_tld else '#64748b', 'border': '#cbd5e1'}
    })
    edges.append({'from': 'target_url', 'to': 'tld_node', 'label': 'TLD Scope', 'color': {'color': '#64748b'}})

    return {'nodes': nodes, 'edges': edges}



"""
PhishShield AI - Constants & Security Dictionary Registries
"""

# URL Shorteners commonly abused in phishing
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cuts.in', 'tiny.cc', 'bc.vc', 'twitthis.com',
    'u.to', 'j.mp', 'buzurl.com', 'cutt.ly', 'rb.gy', 'v.gd', 'qr.ae',
    'clck.ru', 's.id', 'shorturl.at', 'rotf.lol', 'snip.ly'
}

# Suspicious keywords frequently embedded in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'banking', 'account', 'update', 'paypal', 'secure',
    'token', 'signin', 'confirm', 'password', 'billing', 'support', 'wallet',
    'credential', 'webscr', 'security', 'service', 'auth', 'admin', 'ebay',
    'apple', 'microsoft', 'netflix', 'amazon', 'google', 'facebook', 'instagram',
    'bank', 'checkout', 'verification', 'recover', 'validation', 'alert',
    'fraud', 'phish', 'scam', 'claim', 'prize', 'lottery', 'winner', 'gift',
    'crypto', 'airdrop', 'urgent', 'free', 'reward', 'bonus'
]

# Sensitive auth/credential keywords
AUTH_SCAM_KEYWORDS = {
    'login', 'verify', 'banking', 'account', 'update', 'secure', 'token', 'signin',
    'confirm', 'password', 'billing', 'support', 'wallet', 'credential', 'webscr',
    'security', 'service', 'auth', 'admin', 'checkout', 'verification', 'recover',
    'validation', 'alert', 'fraud', 'phish', 'scam', 'claim', 'prize', 'lottery',
    'winner', 'gift', 'crypto', 'airdrop', 'urgent', 'free', 'reward', 'bonus'
}

# High-risk financial/service brands targeted in phishing
TARGET_IMPERSONATION_BRANDS = [
    'paypal', 'apple', 'microsoft', 'netflix', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'usbank', 'sbi', 'hdfc', 'icici', 'axis',
    'kotak', 'paytm', 'phonepe', 'steam', 'coinbase', 'binance', 'metamask',
    'dhl', 'fedex', 'usps', 'icloud', 'onedrive'
]

# TLDs associated with higher rates of free/cheap phishing registration
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'club', 'info',
    'site', 'online', 'tech', 'space', 'monster', 'icu', 'buzz', 'best', 'rest'
}

# Sensitive/Executable file extensions in URL paths
SENSITIVE_EXTENSIONS = {
    '.exe', '.scr', '.bin', '.zip', '.rar', '.php', '.asp', '.aspx', '.py', '.apk', '.iso', '.vbs', '.bat'
}

# Obfuscation regex patterns for JS page scanner
OBFUSCATION_PATTERNS = [
    r'eval\s*\(\s*(?:unescape|atob|decodeURIComponent)',
    r'document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)',
    r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)',
    r'decodeURIComponent\s*\(\s*unescape\s*\(',
    r'window\[["\']\\x[0-9a-fA-F]{2}["\']\]',
]

# Credential input field names
CREDENTIAL_FIELDS = [
    'password', 'passwd', 'pass', 'pwd', 'pin', 'otp', 'cvv',
    'card', 'cardnumber', 'credit', 'debit', 'account', 'ssn',
    'social', 'dob', 'birthdate',
]

# Trusted Whitelisted Domains & Suffixes
TRUSTED_DOMAINS = {
    # Local Development & Loopback Hosts
    'localhost', '127.0.0.1', '0.0.0.0', '::1',

    # Tech Giants & Search
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',

    'github.com', 'wikipedia.org', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'reddit.com', 'stackoverflow.com', 'medium.com', 'quora.com', 'wordpress.com', 'wordpress.org',
    
    # Cybersecurity & Software Vendors
    'mcafee.com', 'norton.com', 'kaspersky.com', 'avast.com', 'bitdefender.com',
    'sophos.com', 'malwarebytes.com', 'trendmicro.com', 'eset.com', 'cloudflare.com',
    'cisco.com', 'oracle.com', 'ibm.com', 'salesforce.com', 'adobe.com',

    # Indian & Global Banks / Payments
    'hdfcbank.com', 'sbi.co.in', 'onlinesbi.sbi', 'icicibank.com', 'axisbank.com',
    'kotak.com', 'kotakbank.com', 'pnbindia.in', 'bankofbaroda.in', 'paytm.com', 'phonepe.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com', 'paypal.com',
    'razorpay.com', 'stripe.com', 'wise.com', 'revolut.com',

    # Sports, Media & News
    'mumbaiindians.com', 'bcci.tv', 'icc-cricket.com', 'cricbuzz.com', 'espncricinfo.com', 'iplt20.com',
    'ndtv.com', 'indiatimes.com', 'timesofindia.com', 'hindustantimes.com', 'thehindu.com',
    'indianexpress.com', 'bbc.com', 'cnn.com', 'reuters.com',

    # E-Commerce, OTT & Productivity
    'ebay.com', 'flipkart.com', 'myntra.com', 'meesho.com', 'shopify.com', 'etsy.com',
    'zoom.us', 'slack.com', 'dropbox.com', 'spotify.com', 'discord.com', 'notion.so',
    'hotstar.com', 'jiocinema.com', 'bookmyshow.com', 'brightstart.in',

    # Government, Cultural & Regulated
    'nathdwaratemple.org', 'gov.in', 'india.gov.in', 'uidai.gov.in', 'incometax.gov.in', 'irs.gov', 'usa.gov', 'gov.uk'
}

TRUSTED_SUFFIXES = (
    '.gov.in', '.nic.in', '.bank.in', '.gov', '.gov.uk', '.edu', '.ac.in', '.org.in'
)

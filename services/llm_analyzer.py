"""
PhishShield AI - Dynamic LLM Threat Analysis Engine
Leverages DeepSeek V4 Flash (via OpenRouter) & NVIDIA Nemotron with dual-provider fallback.
Generates dynamic cybersecurity threat synthesis, attack vectors, and recommended security actions.
"""

import json
import urllib.request
import urllib.error
from urllib.parse import urlparse

from config import (
    GROQ_API_KEY, GROQ_BASE_URL, GROQ_MODEL,
    NVIDIA_NEMOTRON_API_KEY, NVIDIA_NEMOTRON_BASE_URL, NVIDIA_NEMOTRON_MODEL,
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL, OPENROUTER_MODEL,
    LLM_TIMEOUT
)

from core.scanner import detect_brand_typosquatting
from utils.helpers import is_trusted_domain
from services.logger import logger


def _build_llm_prompt(scan_data: dict) -> str:
    """Builds a structured prompt with deep telemetry for the LLM cybersecurity engine."""
    url = scan_data.get('url', '')
    risk_score = scan_data.get('risk_score', 0.0)
    threat_level = scan_data.get('threat_level', 'UNKNOWN')
    xgb_score = scan_data.get('xgb_score', 0.0)
    rf_score = scan_data.get('rf_score', 0.0)
    mlp_score = scan_data.get('mlp_score', 0.0)
    heuristic_score = scan_data.get('heuristic_score', 0.0)
    content_score = scan_data.get('content_score', 0.0)
    
    ssl_info = scan_data.get('ssl_info', {})
    content_analysis = scan_data.get('content_analysis', {})
    risk_factors = scan_data.get('risk_factors', [])
    
    risk_factor_strs = [f"- {rf.get('factor')}: {rf.get('description')}" for rf in risk_factors[:5] if isinstance(rf, dict)]
    raw_signals = content_analysis.get('signals', []) if isinstance(content_analysis, dict) else []
    content_signals = [f"- {s.get('signal')}: {s.get('detail')}" for s in raw_signals[:5] if isinstance(s, dict)]

    try:
        host_val = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url).netloc
        typo_info = detect_brand_typosquatting(host_val)
        typo_str = f"ALERT CRITICAL: {typo_info['detail']}" if typo_info.get('is_typosquatting') else "Clean (No brand typosquatting detected)"
        is_trusted = is_trusted_domain(url)
    except Exception:
        typo_str = "Clean"
        is_trusted = False

    threat_intel = scan_data.get('threat_intel', {})
    vt_info = threat_intel.get('virustotal', {})
    gsb_info = threat_intel.get('google_safe_browsing', {})
    vt_str = vt_info.get('detail', 'Not configured / skipped')
    gsb_str = gsb_info.get('detail', 'Not configured / skipped')

    prompt = f"""You are PhishShield AI's Senior Cyber Threat Analyst LLM Engine. Analyze the following target website security audit telemetry:

TARGET URL: {url}
OVERALL RISK SCORE: {risk_score}/100
CLASSIFIED THREAT LEVEL: {threat_level}

OFFICIAL BRAND WHITELIST STATUS:
- Verified Official Trusted Domain: {"YES (Official legitimate major brand domain)" if is_trusted else "No (Standard domain)"}

REAL-WORLD BRAND TYPOSQUATTING FORENSICS:
- Brand Typosquatting Audit: {typo_str}

THREAT INTELLIGENCE VENDOR FEEDS:
- VirusTotal API Audit: {vt_str}
- Google Safe Browsing API Audit: {gsb_str}

MACHINE LEARNING ENSEMBLE SCORES:
- XGBoost Model Score: {xgb_score}%
- Random Forest Score: {rf_score}%
- Multi-Layer Perceptron (MLP) Score: {mlp_score}%
- Rule Heuristic Engine Risk: {heuristic_score}%
- Live Content Threat Score: {content_score}%

SSL / DOMAIN FORENSICS:
- SSL Valid: {ssl_info.get('is_valid', False)}
- Issuer: {ssl_info.get('issuer', 'N/A')}
- Days Left: {ssl_info.get('days_left', 'N/A')}
- Cert Warnings: {', '.join(ssl_info.get('cert_warnings', [])) or 'None'}

LIVE HTML SCAN & DEEP INSIDE-OUT WEBSITE FORENSICS:
- Page Title: {content_analysis.get('page_title', 'N/A')}
- Meta Description: {content_analysis.get('meta_description', 'N/A')}
- Page Headings Snippet: {content_analysis.get('headings_summary', 'N/A')}
- Server Header: {content_analysis.get('server_header', 'N/A')}
- HSTS Security Enabled: {content_analysis.get('has_hsts', False)}
- CSP Policy Present: {content_analysis.get('has_csp', False)}
- Form Action Destination Domains: {', '.join(content_analysis.get('form_action_domains', [])) or 'Same Domain / None'}
- Password Input Field Present: {content_analysis.get('has_password_field', False)}
- Form Exfiltration Count: {content_analysis.get('form_count', 0)}
- Redirect Detected: {content_analysis.get('redirect_detected', False)}

KEY RISK FACTORS IDENTIFIED:
{chr(10).join(risk_factor_strs) if risk_factor_strs else '- No critical risk flags raised.'}

CRITICAL RULES:
1. OFFICIAL TRUSTED DOMAIN: If Verified Official Trusted Domain is YES, and there is NO brand typosquatting alert, you MUST classify safety_verdict as 'SAFE' and set ai_risk_score <= 15.0%. Long internal path URLs on official domains like mail.google.com are SAFE.
2. BRAND TYPOSQUATTING: If REAL-WORLD BRAND TYPOSQUATTING FORENSICS contains an "ALERT CRITICAL" (e.g. 'paypall' imposter of PAYPAL), safety_verdict MUST be 'PHISHING DANGER' and set ai_risk_score >= 85.0%.


Provide your expert threat analysis strictly in valid JSON format with the following keys:

{{
  "safety_verdict": "Specify 'SAFE', 'SUSPICIOUS', or 'PHISHING DANGER' based on your deep AI security audit.",
  "ai_risk_score": 0.0 to 100.0 (float number representing your calculated threat risk score),
  "ai_summary": "A concise 2-3 sentence executive threat assessment summarizing the intent and safety of this target URL.",
  "attack_vectors": ["Array of active threat tactics identified (e.g. Credential Harvesting, Homograph Impersonation, Obfuscated Payload execution, SSL Spoofing). If website is SAFE with NO active threat vectors, return an empty array []. DO NOT list negative statements starting with 'No'."],
  "recommended_actions": ["Array of 3 clear, actionable defense recommendations for security analysts or users."],
  "confidence_reasoning": "A 1-2 sentence technical breakdown explaining why the AI model reached this conclusion.",
  "risk_factors": [
    {{
      "factor": "Specific threat factor name (e.g., Domain Brand Impersonation, SSL Cert Expired, External Form Action)",
      "severity": "CRITICAL, HIGH, MEDIUM, or SAFE",
      "impact": "Percentage impact string like +30% or 0%",
      "description": "Clear technical forensic explanation for this factor."
    }}
  ]
}}

Respond ONLY with valid JSON. No markdown code blocks, no preambles.
"""
    return prompt


def _call_openai_compatible_api(base_url: str, api_key: str, model: str, prompt: str) -> dict:
    """Invokes OpenAI-compatible completion endpoint (used for OpenRouter & NVIDIA Nemotron)."""
    endpoint = base_url.rstrip('/') + '/chat/completions'
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
        'HTTP-Referer': 'https://github.com/phishshield-ai',
        'X-Title': 'PhishShield AI Threat Scanner'
    }


    system_instruction = (
        "You are PhishShield AI's Principal Cyber Threat Intelligence Architect specializing in Zero-Day Phishing Detection, Brand Impersonation Analysis, and Web Infrastructure Forensics.\n"
        "EVALUATION GUIDELINES FOR HIGH ACCURACY:\n"
        "1. Verified Infrastructure: Official government (.gov.in, .gov, .nic.in), educational (.edu, .ac.in), and regulated banking suffixes (.bank.in, .co.in) with valid SSL and matching titles are SAFE legitimate properties (risk_score 0.0 to 15.0%).\n"
        "2. High-Risk Indicators: Flag raw IP hostnames, Punycode (xn--), suspicious cheap TLDs (.xyz, .top, .work), and external form action exfiltration as PHISHING DANGER (risk_score 70.0 to 100.0%).\n"
        "3. Moderate Warnings: Flag unencrypted HTTP login forms or recent self-signed SSL certs as SUSPICIOUS (risk_score 35.0 to 65.0%).\n"
        "Synthesize all telemetry and output JSON with high accuracy."
    )

    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_instruction},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.1,
        'max_tokens': 600
    }


    data_bytes = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(endpoint, data=data_bytes, headers=headers, method='POST')

    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as response:
        res_raw = response.read().decode('utf-8')
        res_json = json.loads(res_raw)
        
        content = res_json['choices'][0]['message']['content'].strip()
        # Clean potential markdown formatting
        if content.startswith('```'):
            content = content.split('\n', 1)[-1].rsplit('```', 1)[0].strip()
            if content.startswith('json'):
                content = content[4:].strip()
                
        return json.loads(content)


def generate_heuristic_llm_fallback(scan_data: dict, provider_label: str = "PhishShield Heuristic Engine") -> dict:
    """Generates structured AI security synthesis when LLM API keys are unconfigured or unavailable."""
    url = scan_data.get('url', '')
    risk_score = scan_data.get('risk_score', 0.0)
    threat_level = scan_data.get('threat_level', 'SAFE')
    features = scan_data.get('features', {})
    ssl_info = scan_data.get('ssl_info', {})
    is_https = url.lower().startswith('https://')
    ssl_broken = is_https and (not ssl_info.get('is_valid', True) or ssl_info.get('is_expired', False) or 'Timed Out' in str(ssl_info.get('issuer', '')) or 'None' in str(ssl_info.get('issuer', '')))

    if features.get('is_typosquatting') == 1 or risk_score >= 65.0:
        brand = features.get('spoofed_brand') or 'Official Brand'
        if features.get('is_typosquatting') == 1:
            summary = f"CRITICAL SECURITY ALERT: The target domain {url} is a brand typosquatting imposter mimicking {brand}. Do not enter login credentials, passwords, or personal details."
            vectors = [f"Brand Typosquatting Imposter ({brand})", "Levenshtein Edit Distance Spoofing", "Credential Harvesting Lure"]
        else:
            summary = f"CRITICAL SECURITY ALERT: The domain {url} exhibits high-risk indicators characteristic of active credential harvesting or brand impersonation. ML models show elevated confidence in threat classification."
            vectors = ["Credential Harvesting Form", "Suspicious Domain Structure", "Lexical Spoofing Anomaly"]
        actions = [
            "DO NOT enter passwords, MFA codes, or financial information on this URL.",
            "Report domain to anti-phishing blacklists (Google Safe Browsing / PhishTank).",
            "Block destination domain on enterprise DNS firewall / perimeter filtering."
        ]
        reasoning = f"XGBoost classifier and heuristic rules flagged elevated threat indicators with risk score {risk_score}/100."
    elif ssl_broken or risk_score >= 35.0:
        if ssl_broken:
            summary = f"SECURITY WARNING: {url} failed TLS/SSL certificate verification. Web browsers will block access with a security certificate warning (e.g. ERR_CERT_DATE_INVALID or connection timeout)."
            vectors = ["Invalid or Expired TLS Certificate", "HTTPS Handshake Anomaly / Parked Host"]
            actions = [
                "Do NOT bypass browser security warnings (ERR_CERT_DATE_INVALID / Net Error).",
                "Inspect certificate validity and domain registration dates before accessing.",
                "Avoid submitting sensitive credentials or financial details."
            ]
        else:
            summary = f"MODERATE THREAT LEVEL: {url} displays structural or SSL anomalies that warrant caution. Proceed only after verifying the true domain owner."
            vectors = ["SSL Cert Anomaly or Recent Registration", "Elevated Heuristic Keyword Match"]
            actions = [
                "Verify identity via known official domain or phone support.",
                "Inspect full certificate chain and domain registration dates.",
                "Avoid submitting sensitive account data."
            ]
        reasoning = f"XGBoost classifier and security telemetry calculated a moderate combined risk index of {risk_score}/100."
    else:
        summary = f"VERIFIED LOW RISK: {url} displays clean structural indicators, valid SSL signatures, and no exfiltration mechanisms. Content appears legitimate."
        vectors = ["Standard Legitimate Traffic Profile", "Valid SSL / Clean HTML Structure"]
        actions = [
            "Domain safe for standard browsing interaction.",
            "Standard security hygiene recommended."
        ]
        reasoning = f"XGBoost classifier and heuristic signatures converged on clean safety metrics with score {risk_score}/100."

    return {
        'ai_summary': summary,
        'attack_vectors': vectors,
        'recommended_actions': actions,
        'confidence_reasoning': reasoning,
        'provider_used': provider_label,
        'is_live_llm': False
    }


def analyze_threat_with_llm(scan_data: dict) -> dict:
    """
    Executes dynamic AI threat analysis prioritizing Groq API:
    1. Try Groq API (using GROQ_API_KEY, GROQ_BASE_URL, GROQ_MODEL).
    2. Fall back to NVIDIA Nemotron or OpenRouter API (if configured).
    3. Fall back to local structured AI security synthesis engine if keys missing or API calls fail.
    """
    prompt = _build_llm_prompt(scan_data)

    # 1. Primary: Groq API
    if GROQ_API_KEY and len(GROQ_API_KEY.strip()) > 5:
        try:
            logger.info(f"Invoking Groq API ({GROQ_MODEL}) for dynamic threat analysis...")
            parsed_resp = _call_openai_compatible_api(
                GROQ_BASE_URL, GROQ_API_KEY, GROQ_MODEL, prompt
            )
            parsed_resp['provider_used'] = f"Groq AI ({GROQ_MODEL})"
            parsed_resp['is_live_llm'] = True
            return parsed_resp
        except Exception as e:
            logger.warning(f"Groq API call failed or timed out: {e}. Attempting fallback...")

    # 2. Secondary Fallback: NVIDIA Nemotron API
    if NVIDIA_NEMOTRON_API_KEY and len(NVIDIA_NEMOTRON_API_KEY.strip()) > 5:
        try:
            logger.info(f"Invoking NVIDIA Nemotron API ({NVIDIA_NEMOTRON_MODEL}) for fallback threat analysis...")
            parsed_resp = _call_openai_compatible_api(
                NVIDIA_NEMOTRON_BASE_URL, NVIDIA_NEMOTRON_API_KEY, NVIDIA_NEMOTRON_MODEL, prompt
            )
            parsed_resp['provider_used'] = f"NVIDIA Nemotron ({NVIDIA_NEMOTRON_MODEL})"
            parsed_resp['is_live_llm'] = True
            return parsed_resp
        except Exception as e:
            logger.warning(f"NVIDIA Nemotron API call failed or timed out: {e}. Attempting fallback...")

    # 3. Tertiary Fallback: OpenRouter API (DeepSeek V4 Flash)
    if OPENROUTER_API_KEY and len(OPENROUTER_API_KEY.strip()) > 5:
        try:
            logger.info(f"Invoking OpenRouter LLM ({OPENROUTER_MODEL}) for fallback scan analysis...")
            parsed_resp = _call_openai_compatible_api(
                OPENROUTER_BASE_URL, OPENROUTER_API_KEY, OPENROUTER_MODEL, prompt
            )
            parsed_resp['provider_used'] = f"DeepSeek V4 Flash (via OpenRouter)"
            parsed_resp['is_live_llm'] = True
            return parsed_resp
        except Exception as e:
            logger.warning(f"OpenRouter API call failed or timed out: {e}.")

    # 4. Fallback to Local AI Security Telemetry Engine
    logger.info("Using local dynamic AI threat synthesis engine.")
    return generate_heuristic_llm_fallback(scan_data, provider_label="PhishShield Rule & Telemetry Engine (Add GROQ_API_KEY in .env for Live Groq AI)")



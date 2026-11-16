"""
PhishShield AI 2.0 - Multi-Tier Verdict Engine
Implements tiered classification for optimal latency and accuracy:

Tier 1: Local Allowlist/Blocklist check (immediate, <1ms)
Tier 2: Local ML Ensemble (XGBoost/RF/MLP) with 34 features (<5ms)
Tier 3: Groq-LLM Explainable AI (only if ML confidence ∈ [0.4, 0.7])
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from config import settings, DATA_DIR
from utils.helpers import is_trusted_domain, clean_domain
from utils.constants import TRUSTED_DOMAINS, TRUSTED_SUFFIXES

logger = logging.getLogger('phishshield.verdict')


@dataclass
class VerdictResult:
    """Structured verdict from the multi-tier engine."""
    risk_score: float = 0.0
    threat_level: str = 'SAFE'           # SAFE | SUSPICIOUS | PHISHING DANGER
    badge_class: str = 'success'          # success | warning | danger | inactive
    summary_msg: str = ''
    tier_used: int = 0                    # 1, 2, or 3
    tier_label: str = ''
    confidence: float = 1.0
    needs_llm: bool = False
    ensemble_score: float = 0.0
    xgb_score: float = 0.0
    rf_score: float = 0.0
    mlp_score: float = 0.0
    heuristic_score: float = 0.0


# ======================== BLOCKLIST LOADER ========================

_blocklist: Optional[set] = None


def _load_blocklist() -> set:
    """Load known phishing domains from data/blocklist.txt (lazy, cached)."""
    global _blocklist
    if _blocklist is not None:
        return _blocklist

    blocklist_path = os.path.join(DATA_DIR, 'blocklist.txt')
    _blocklist = set()

    if os.path.exists(blocklist_path):
        try:
            with open(blocklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        _blocklist.add(line.lower())
            logger.info(f"Loaded {len(_blocklist)} domains into blocklist")
        except Exception as e:
            logger.warning(f"Failed to load blocklist: {e}")

    return _blocklist


def _extract_domain_from_url(url: str) -> str:
    """Extract clean domain from URL string."""
    from urllib.parse import urlparse

    url_str = url.strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        hostname = parsed.netloc.split(':')[0].lower()
        return clean_domain(hostname)
    except Exception:
        return ''


# ======================== TIER 1: ALLOWLIST / BLOCKLIST ========================

def check_allowlist_blocklist(raw_url: str) -> Optional[VerdictResult]:
    """
    Tier 1: Immediate verdict from local allowlist/blocklist.
    Returns VerdictResult if matched, None if no match (proceed to Tier 2).
    """
    if not raw_url:
        return None

    # Check allowlist (trusted domains → immediate SAFE)
    if is_trusted_domain(raw_url):
        return VerdictResult(
            risk_score=5.0,
            threat_level='SAFE',
            badge_class='success',
            summary_msg='VERIFIED TRUSTED DOMAIN — URL belongs to an officially whitelisted organization.',
            tier_used=1,
            tier_label='Tier 1: Local Allowlist',
            confidence=0.99,
        )

    # Check blocklist (known phishing → immediate DANGER)
    domain = _extract_domain_from_url(raw_url)
    blocklist = _load_blocklist()

    if domain in blocklist:
        return VerdictResult(
            risk_score=95.0,
            threat_level='PHISHING DANGER',
            badge_class='danger',
            summary_msg=f'BLOCKED — Domain {domain} matches a known phishing blocklist entry.',
            tier_used=1,
            tier_label='Tier 1: Local Blocklist',
            confidence=0.99,
        )

    # Also check if any blocklist entry is a subdomain match
    for blocked in blocklist:
        if domain.endswith('.' + blocked) or blocked.endswith('.' + domain):
            return VerdictResult(
                risk_score=90.0,
                threat_level='PHISHING DANGER',
                badge_class='danger',
                summary_msg=f'BLOCKED — Domain {domain} is associated with blocklisted domain {blocked}.',
                tier_used=1,
                tier_label='Tier 1: Local Blocklist (subdomain match)',
                confidence=0.95,
            )

    return None  # No match — proceed to Tier 2


# ======================== TIER 2: ML ENSEMBLE ========================

def run_ml_ensemble(
    feature_vector: list,
    feature_dict: dict,
    model_manager: Any
) -> VerdictResult:
    """
    Tier 2: Local ML Ensemble prediction using XGBoost, Random Forest, and MLP.
    Returns VerdictResult with needs_llm=True if confidence is ambiguous.
    """
    from core.scanner import (
        calculate_ensemble_score,
        calculate_heuristic_risk,
    )

    # Run ensemble prediction
    xgb_prob, rf_prob, mlp_prob = model_manager.predict(feature_vector)
    ensemble_score, xgb_score, rf_score, mlp_score = calculate_ensemble_score(
        xgb_prob, rf_prob, mlp_prob
    )

    # Calculate heuristic risk
    heuristic_score = calculate_heuristic_risk(feature_dict)

    # Determine confidence: how "decisive" is the ensemble?
    # Confidence is distance from the decision boundary (0.5)
    ensemble_prob = ensemble_score / 100.0
    confidence = abs(ensemble_prob - 0.5) * 2  # Maps [0,1] prob → [0,1] confidence

    # Check for typosquatting (always overrides)
    is_typo = feature_dict.get('is_typosquatting') == 1

    if is_typo:
        result = VerdictResult(
            risk_score=round(max(85.0, heuristic_score, ensemble_score), 1),
            threat_level='PHISHING DANGER',
            badge_class='danger',
            summary_msg='BRAND TYPOSQUATTING DETECTED — Domain is an imposter mimicking a legitimate brand.',
            tier_used=2,
            tier_label='Tier 2: ML Ensemble + Typosquatting Detection',
            confidence=0.95,
            needs_llm=False,
            ensemble_score=ensemble_score,
            xgb_score=xgb_score,
            rf_score=rf_score,
            mlp_score=mlp_score,
            heuristic_score=round(heuristic_score, 1),
        )
    elif ensemble_score >= 65.0:
        result = VerdictResult(
            risk_score=round(max(ensemble_score, heuristic_score), 1),
            threat_level='PHISHING DANGER',
            badge_class='danger',
            summary_msg='HIGH PHISHING PROBABILITY DETECTED — DO NOT SUBMIT CREDENTIALS ON THIS SITE',
            tier_used=2,
            tier_label='Tier 2: ML Ensemble (High Confidence)',
            confidence=confidence,
            needs_llm=False,
            ensemble_score=ensemble_score,
            xgb_score=xgb_score,
            rf_score=rf_score,
            mlp_score=mlp_score,
            heuristic_score=round(heuristic_score, 1),
        )
    elif ensemble_score < 35.0 and heuristic_score < 35.0:
        result = VerdictResult(
            risk_score=round(max(ensemble_score * 0.3, heuristic_score * 0.35), 1),
            threat_level='SAFE',
            badge_class='success',
            summary_msg='LOW THREAT RISK — URL AND PAGE CONTENT APPEAR LEGITIMATE AND CLEAN',
            tier_used=2,
            tier_label='Tier 2: ML Ensemble (High Confidence)',
            confidence=confidence,
            needs_llm=False,
            ensemble_score=ensemble_score,
            xgb_score=xgb_score,
            rf_score=rf_score,
            mlp_score=mlp_score,
            heuristic_score=round(heuristic_score, 1),
        )
    else:
        # Ambiguous zone: confidence is between 0.4 and 0.7 → trigger LLM
        needs_llm = (
            settings.LLM_TRIGGER_LOW <= ensemble_prob <= settings.LLM_TRIGGER_HIGH
        )
        result = VerdictResult(
            risk_score=round(max(ensemble_score, heuristic_score), 1),
            threat_level='SUSPICIOUS',
            badge_class='warning',
            summary_msg='MODERATE THREAT RISK — EXERCISE EXTREME CAUTION BEFORE PROCEEDING',
            tier_used=2,
            tier_label='Tier 2: ML Ensemble (Ambiguous — LLM recommended)' if needs_llm else 'Tier 2: ML Ensemble',
            confidence=confidence,
            needs_llm=needs_llm,
            ensemble_score=ensemble_score,
            xgb_score=xgb_score,
            rf_score=rf_score,
            mlp_score=mlp_score,
            heuristic_score=round(heuristic_score, 1),
        )

    return result


# ======================== TIER 3: LLM VERDICT ========================

async def async_llm_verdict(scan_context: dict) -> Optional[dict]:
    """
    Tier 3: Groq-LLM Explainable AI verdict.
    Only invoked when ML ensemble confidence is ambiguous (0.4–0.7).
    Runs asynchronously to avoid blocking the event loop.
    """
    import asyncio
    from services.llm_analyzer import analyze_threat_with_llm

    try:
        # Run synchronous LLM call in thread executor to avoid blocking
        loop = asyncio.get_event_loop()
        llm_result = await loop.run_in_executor(
            None,
            analyze_threat_with_llm,
            scan_context
        )
        return llm_result
    except Exception as e:
        logger.error(f"Tier 3 LLM verdict failed: {e}")
        return None


# ======================== ORCHESTRATOR ========================

async def compute_verdict(
    raw_url: str,
    feature_dict: dict,
    feature_vector: list,
    model_manager: Any,
    forensics_result: Any = None,
    content_analysis: dict = None,
) -> tuple:
    """
    Multi-tier verdict orchestrator.
    Runs tiers sequentially, short-circuiting at the earliest confident tier.

    Returns: (VerdictResult, llm_analysis_dict_or_None)
    """
    llm_analysis = None

    # ---- Tier 1: Allowlist / Blocklist ----
    tier1 = check_allowlist_blocklist(raw_url)
    if tier1 is not None:
        logger.info(f"Verdict: {tier1.tier_label} → {tier1.threat_level} (score={tier1.risk_score})")
        return tier1, None

    # ---- Tier 2: ML Ensemble ----
    tier2 = run_ml_ensemble(feature_vector, feature_dict, model_manager)

    # Apply content analysis adjustments if available
    if content_analysis and content_analysis.get('analyzed', False):
        content_score = content_analysis.get('content_score', 0.0)
        if content_score > 0.0 and tier2.threat_level != 'PHISHING DANGER':
            # Active threat indicators found in HTML
            adjusted_score = round(max(content_score, (tier2.ensemble_score * 0.4 + content_score * 0.6)), 1)
            if adjusted_score >= 65.0:
                tier2.risk_score = adjusted_score
                tier2.threat_level = 'PHISHING DANGER'
                tier2.badge_class = 'danger'
                tier2.summary_msg = 'HIGH PHISHING PROBABILITY — Active threat indicators found in page content.'
        elif content_score == 0.0 and tier2.threat_level == 'SUSPICIOUS':
            # Clean content dampens ML noise
            tier2.risk_score = round(tier2.risk_score * 0.5, 1)
            if tier2.risk_score < 35.0:
                tier2.threat_level = 'SAFE'
                tier2.badge_class = 'success'
                tier2.summary_msg = 'LOW THREAT RISK — Page content verified clean.'

    # Check for broken SSL on HTTPS targets
    if forensics_result and raw_url.lower().startswith('https://'):
        ssl_res = forensics_result.ssl
        if not ssl_res.is_valid or ssl_res.is_expired or 'Timed Out' in (ssl_res.issuer or '') or 'None' in (ssl_res.issuer or ''):
            if tier2.threat_level == 'SAFE':
                tier2.threat_level = 'SUSPICIOUS'
                tier2.badge_class = 'warning'
                tier2.risk_score = max(tier2.risk_score, 45.0)
                tier2.summary_msg = 'HTTPS SSL CERTIFICATE ANOMALY — Certificate verification failed or expired (e.g. ERR_CERT_DATE_INVALID).'

    # ---- Tier 3: LLM (only if ambiguous) ----
    from core.async_scanner import ssl_result_to_dict
    ssl_dict = ssl_result_to_dict(forensics_result.ssl) if forensics_result else {}

    if tier2.needs_llm:
        logger.info(f"Tier 2 ambiguous (confidence={tier2.confidence:.2f}), triggering Tier 3 LLM...")

        scan_context = {
            'url': raw_url,
            'risk_score': tier2.risk_score,
            'threat_level': tier2.threat_level,
            'xgb_score': tier2.xgb_score,
            'rf_score': tier2.rf_score,
            'mlp_score': tier2.mlp_score,
            'heuristic_score': tier2.heuristic_score,
            'features': feature_dict,
            'content_score': content_analysis.get('content_score', 0.0) if content_analysis else 0.0,
            'ssl_info': ssl_dict,
            'content_analysis': content_analysis or {},
            'risk_factors': [],
        }

        llm_analysis = await async_llm_verdict(scan_context)

        if llm_analysis and llm_analysis.get('is_live_llm', False):
            tier2.tier_used = 3
            tier2.tier_label = f'Tier 3: LLM Explainable AI ({llm_analysis.get("provider_used", "Groq")})'

            # Let LLM refine the verdict
            if llm_analysis.get('safety_verdict') in ['SAFE', 'SUSPICIOUS', 'PHISHING DANGER']:
                tier2.threat_level = llm_analysis['safety_verdict']
                if tier2.threat_level == 'PHISHING DANGER':
                    tier2.badge_class = 'danger'
                elif tier2.threat_level == 'SUSPICIOUS':
                    tier2.badge_class = 'warning'
                else:
                    tier2.badge_class = 'success'

            if 'ai_risk_score' in llm_analysis:
                try:
                    tier2.risk_score = round(float(llm_analysis['ai_risk_score']), 1)
                except (ValueError, TypeError):
                    pass

            if llm_analysis.get('ai_summary'):
                tier2.summary_msg = llm_analysis['ai_summary']
    else:
        # Generate heuristic fallback for non-LLM tiers
        from services.llm_analyzer import generate_heuristic_llm_fallback
        scan_context = {
            'url': raw_url,
            'risk_score': tier2.risk_score,
            'threat_level': tier2.threat_level,
            'features': feature_dict,
            'ssl_info': ssl_dict,
        }
        llm_analysis = generate_heuristic_llm_fallback(scan_context)

    logger.info(
        f"Verdict: {tier2.tier_label} → {tier2.threat_level} "
        f"(score={tier2.risk_score}, confidence={tier2.confidence:.2f})"
    )

    return tier2, llm_analysis

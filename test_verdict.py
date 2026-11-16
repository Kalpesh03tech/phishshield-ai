"""
PhishShield AI 2.0 - Multi-Tier Verdict Engine Test Suite
Tests allowlist/blocklist logic, ML ensemble verdicts,
and tier short-circuiting behavior.
"""

import pytest
from unittest.mock import MagicMock, patch

from core.verdict import (
    check_allowlist_blocklist,
    run_ml_ensemble,
    VerdictResult,
    _load_blocklist,
    _extract_domain_from_url,
)


class TestTier1AllowlistBlocklist:
    """Test Tier 1: Allowlist and Blocklist immediate verdicts."""

    # ---- Allowlist Tests ----

    def test_trusted_google(self):
        result = check_allowlist_blocklist('https://google.com/search?q=test')
        assert result is not None
        assert result.threat_level == 'SAFE'
        assert result.tier_used == 1
        assert result.risk_score <= 10.0

    def test_trusted_github(self):
        result = check_allowlist_blocklist('https://github.com/user/repo')
        assert result is not None
        assert result.threat_level == 'SAFE'
        assert result.tier_used == 1

    def test_trusted_subdomain(self):
        result = check_allowlist_blocklist('https://mail.google.com/inbox')
        assert result is not None
        assert result.threat_level == 'SAFE'

    def test_trusted_gov_domain(self):
        result = check_allowlist_blocklist('https://india.gov.in/services')
        assert result is not None
        assert result.threat_level == 'SAFE'

    def test_trusted_localhost(self):
        result = check_allowlist_blocklist('http://localhost:5000')
        assert result is not None
        assert result.threat_level == 'SAFE'

    # ---- Blocklist Tests ----

    def test_blocklisted_domain(self):
        result = check_allowlist_blocklist('http://paypal-secure-login.tk/verify')
        assert result is not None
        assert result.threat_level == 'PHISHING DANGER'
        assert result.tier_used == 1
        assert result.risk_score >= 90.0

    def test_blocklisted_crypto_scam(self):
        result = check_allowlist_blocklist('http://free-crypto-airdrop.xyz/claim')
        assert result is not None
        assert result.threat_level == 'PHISHING DANGER'

    # ---- No Match Tests (should proceed to Tier 2) ----

    def test_unknown_domain_returns_none(self):
        result = check_allowlist_blocklist('https://some-random-website.com')
        assert result is None  # No match → proceed to Tier 2

    def test_empty_url_returns_none(self):
        result = check_allowlist_blocklist('')
        assert result is None


class TestDomainExtraction:
    """Test URL → domain extraction helper."""

    def test_simple_url(self):
        assert _extract_domain_from_url('https://example.com/page') == 'example.com'

    def test_www_stripped(self):
        assert _extract_domain_from_url('https://www.example.com') == 'example.com'

    def test_subdomain_preserved(self):
        domain = _extract_domain_from_url('https://mail.google.com')
        assert 'google.com' in domain

    def test_no_scheme(self):
        assert _extract_domain_from_url('example.com/path') == 'example.com'


class TestTier2MLEnsemble:
    """Test Tier 2: ML Ensemble verdict logic."""

    def _make_mock_model_manager(self, xgb_prob=0.1, rf_prob=0.1, mlp_prob=0.1):
        """Create a mock ModelManager that returns specified probabilities."""
        mock = MagicMock()
        mock.predict.return_value = (xgb_prob, rf_prob, mlp_prob)
        return mock

    def test_safe_verdict_low_scores(self):
        """Low ML scores + low heuristic → SAFE."""
        mock_mm = self._make_mock_model_manager(0.05, 0.08, 0.03)
        feat_dict = {
            'is_typosquatting': 0, 'has_ip': 0, 'is_punycode': 0,
            'suspicious_kw_in_domain': 0, 'suspicious_kw_count': 0,
            'suspicious_tld': 0, 'is_shortened': 0, 'has_hyphen_domain': 0,
            'has_sensitive_ext': 0, 'digit_ratio': 0.05,
            'shannon_entropy_host': 2.5, 'is_https': 1,
            'has_tracking_params': 0, 'url': 'https://example.com',
        }
        feat_vec = [0] * 30

        result = run_ml_ensemble(feat_vec, feat_dict, mock_mm)
        assert result.threat_level == 'SAFE'
        assert result.needs_llm is False

    def test_danger_verdict_high_scores(self):
        """High ML scores → PHISHING DANGER."""
        mock_mm = self._make_mock_model_manager(0.92, 0.88, 0.85)
        feat_dict = {
            'is_typosquatting': 0, 'has_ip': 0, 'is_punycode': 0,
            'suspicious_kw_in_domain': 0, 'suspicious_kw_count': 0,
            'suspicious_tld': 0, 'is_shortened': 0, 'has_hyphen_domain': 0,
            'has_sensitive_ext': 0, 'digit_ratio': 0.05,
            'shannon_entropy_host': 2.5, 'is_https': 1,
            'has_tracking_params': 0, 'url': 'https://suspicious-site.xyz',
        }
        feat_vec = [0] * 30

        result = run_ml_ensemble(feat_vec, feat_dict, mock_mm)
        assert result.threat_level == 'PHISHING DANGER'
        assert result.needs_llm is False
        assert result.risk_score >= 65.0

    def test_typosquatting_always_danger(self):
        """Typosquatting detection overrides to PHISHING DANGER regardless of ML scores."""
        mock_mm = self._make_mock_model_manager(0.2, 0.15, 0.1)
        feat_dict = {
            'is_typosquatting': 1, 'has_ip': 0, 'is_punycode': 0,
            'suspicious_kw_in_domain': 0, 'suspicious_kw_count': 0,
            'suspicious_tld': 0, 'is_shortened': 0, 'has_hyphen_domain': 0,
            'has_sensitive_ext': 0, 'digit_ratio': 0.05,
            'shannon_entropy_host': 2.5, 'is_https': 1,
            'has_tracking_params': 0, 'url': 'https://g00gle.com',
        }
        feat_vec = [0] * 30

        result = run_ml_ensemble(feat_vec, feat_dict, mock_mm)
        assert result.threat_level == 'PHISHING DANGER'
        assert result.risk_score >= 85.0

    def test_ambiguous_triggers_llm(self):
        """Mid-range ML confidence (0.4–0.7) should trigger LLM."""
        # ensemble_score = (50*0.4 + 55*0.35 + 48*0.25) = 20 + 19.25 + 12 = 51.25
        mock_mm = self._make_mock_model_manager(0.50, 0.55, 0.48)
        feat_dict = {
            'is_typosquatting': 0, 'has_ip': 0, 'is_punycode': 0,
            'suspicious_kw_in_domain': 0, 'suspicious_kw_count': 0,
            'suspicious_tld': 0, 'is_shortened': 0, 'has_hyphen_domain': 0,
            'has_sensitive_ext': 0, 'digit_ratio': 0.05,
            'shannon_entropy_host': 2.5, 'is_https': 1,
            'has_tracking_params': 0, 'url': 'https://ambiguous-site.com',
        }
        feat_vec = [0] * 30

        result = run_ml_ensemble(feat_vec, feat_dict, mock_mm)
        assert result.threat_level == 'SUSPICIOUS'
        assert result.needs_llm is True


class TestVerdictResult:
    """Test VerdictResult dataclass defaults."""

    def test_default_values(self):
        v = VerdictResult()
        assert v.risk_score == 0.0
        assert v.threat_level == 'SAFE'
        assert v.badge_class == 'success'
        assert v.tier_used == 0
        assert v.needs_llm is False
        assert v.confidence == 1.0

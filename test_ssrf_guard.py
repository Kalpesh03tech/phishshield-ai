"""
PhishShield AI 2.0 - SSRF Guard Test Suite
Tests that the URL sanitizer correctly blocks private, loopback,
link-local, and multicast IP ranges.
"""

import pytest
from middleware.ssrf_guard import validate_url_target, SSRFBlockedError, _is_blocked_ip


class TestBlockedIPDetection:
    """Test _is_blocked_ip against all RFC 1918 and special ranges."""

    def test_rfc1918_class_a(self):
        assert _is_blocked_ip('10.0.0.1') is True
        assert _is_blocked_ip('10.255.255.255') is True

    def test_rfc1918_class_b(self):
        assert _is_blocked_ip('172.16.0.1') is True
        assert _is_blocked_ip('172.31.255.255') is True

    def test_rfc1918_class_c(self):
        assert _is_blocked_ip('192.168.0.1') is True
        assert _is_blocked_ip('192.168.255.255') is True

    def test_loopback(self):
        assert _is_blocked_ip('127.0.0.1') is True
        assert _is_blocked_ip('127.255.255.255') is True

    def test_link_local(self):
        assert _is_blocked_ip('169.254.0.1') is True
        assert _is_blocked_ip('169.254.169.254') is True  # AWS metadata endpoint

    def test_multicast(self):
        assert _is_blocked_ip('224.0.0.1') is True
        assert _is_blocked_ip('239.255.255.255') is True

    def test_cgnat(self):
        assert _is_blocked_ip('100.64.0.1') is True
        assert _is_blocked_ip('100.127.255.255') is True

    def test_reserved(self):
        assert _is_blocked_ip('240.0.0.1') is True
        assert _is_blocked_ip('0.0.0.0') is True

    def test_public_ip_allowed(self):
        assert _is_blocked_ip('8.8.8.8') is False
        assert _is_blocked_ip('1.1.1.1') is False
        assert _is_blocked_ip('142.250.80.46') is False  # google.com

    def test_ipv6_loopback(self):
        assert _is_blocked_ip('::1') is True

    def test_ipv6_ula(self):
        assert _is_blocked_ip('fc00::1') is True
        assert _is_blocked_ip('fd00::1') is True

    def test_ipv6_link_local(self):
        assert _is_blocked_ip('fe80::1') is True

    def test_invalid_ip(self):
        assert _is_blocked_ip('not-an-ip') is False


class TestValidateURLTarget:
    """Test validate_url_target with various URL types."""

    def test_blocks_private_ip_url(self):
        with pytest.raises(SSRFBlockedError) as exc_info:
            validate_url_target('http://192.168.1.1/admin')
        assert '192.168.1.1' in str(exc_info.value)

    def test_blocks_loopback_url(self):
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://127.0.0.1:8080/secret')

    def test_blocks_metadata_endpoint(self):
        """AWS/GCP metadata endpoint (169.254.169.254) must be blocked."""
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://169.254.169.254/latest/meta-data/')

    def test_blocks_zero_ip(self):
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://0.0.0.0/')

    def test_blocks_ipv6_loopback(self):
        # IPv6 loopback as raw IP (without brackets — validated by _is_blocked_ip)
        assert _is_blocked_ip('::1') is True
        # URL form with brackets — urlparse extracts '[::1]' which is not a clean IP
        # The SSRF guard blocks this at the _is_blocked_ip level
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://[::1]:8080/')

    def test_allows_public_domain(self):
        # Should not raise — google.com resolves to public IPs
        result = validate_url_target('https://google.com')
        assert result is not None

    def test_allows_public_ip(self):
        result = validate_url_target('http://8.8.8.8')
        assert result == '8.8.8.8'

    def test_empty_url_raises(self):
        with pytest.raises(SSRFBlockedError):
            validate_url_target('')

    def test_handles_nonexistent_domain(self):
        # Should not raise SSRF — DNS failure is handled separately
        try:
            validate_url_target('http://this-domain-definitely-does-not-exist-xyz123.com')
        except SSRFBlockedError:
            pytest.fail("Non-existent domain should not trigger SSRF block")

    def test_blocks_rfc1918_with_path(self):
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://10.0.0.1/api/internal/admin')

    def test_blocks_multicast(self):
        with pytest.raises(SSRFBlockedError):
            validate_url_target('http://224.0.0.1/')

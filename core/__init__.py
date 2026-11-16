"""
PhishShield AI 2.0 - Core Module Init
Exposes unified scanner, async forensics, feature extraction, and verdict engine.
"""

from core.scanner import (
    inspect_domain_live,
    inspect_ssl_cert,
    analyze_website,
    extract_features,
    extract_feature_vector,
    calculate_heuristic_risk,
    generate_explainable_signals,
    calculate_radar_vectors,
    calculate_ensemble_score,
    generate_infrastructure_graph,
    detect_brand_typosquatting
)

from core.async_scanner import (
    async_parallel_scan,
    async_inspect_dns,
    async_inspect_ssl,
    async_inspect_headers,
    dns_result_to_dict,
    ssl_result_to_dict,
    headers_result_to_dict,
    ForensicsResult,
    DNSResult,
    SSLResult,
    HeadersResult,
)

from core.verdict import (
    compute_verdict,
    check_allowlist_blocklist,
    run_ml_ensemble,
    async_llm_verdict,
    VerdictResult,
)

__all__ = [
    # Legacy sync scanner (kept for backward compatibility)
    'inspect_domain_live',
    'inspect_ssl_cert',
    'analyze_website',

    # Feature extraction
    'extract_features',
    'extract_feature_vector',
    'calculate_heuristic_risk',
    'generate_explainable_signals',
    'calculate_radar_vectors',
    'calculate_ensemble_score',
    'generate_infrastructure_graph',
    'detect_brand_typosquatting',

    # Async scanner
    'async_parallel_scan',
    'async_inspect_dns',
    'async_inspect_ssl',
    'async_inspect_headers',
    'dns_result_to_dict',
    'ssl_result_to_dict',
    'headers_result_to_dict',
    'ForensicsResult',
    'DNSResult',
    'SSLResult',
    'HeadersResult',

    # Verdict engine
    'compute_verdict',
    'check_allowlist_blocklist',
    'run_ml_ensemble',
    'async_llm_verdict',
    'VerdictResult',
]

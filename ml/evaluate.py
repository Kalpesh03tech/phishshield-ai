"""
PhishShield AI 2.0 - ML Evaluation CLI Runner
Ties together TemporalDomainSplit + PhishingMetricsSuite for
scientifically rigorous model evaluation.

Usage:
    python -m ml.evaluate --dataset data/phishing_urls.csv --output reports/
    python -m ml.evaluate --generate-sample --output reports/
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime

import numpy as np
import pandas as pd

logger = logging.getLogger('phishshield.ml.evaluate')


def generate_sample_dataset(output_path: str, n_samples: int = 2000) -> str:
    """
    Generate a synthetic phishing URL dataset for demonstration.
    Creates realistic feature distributions for benign and phishing URLs.
    """
    rng = np.random.RandomState(42)

    domains_benign = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org', 'linkedin.com', 'salesforce.com',
        'slack.com', 'zoom.us', 'dropbox.com', 'adobe.com', 'cloudflare.com',
        'stripe.com', 'notion.so', 'figma.com', 'atlassian.com', 'netflix.com',
        'spotify.com', 'twitter.com', 'reddit.com', 'medium.com', 'shopify.com',
    ]

    domains_phish = [
        'g00gle-verify.tk', 'microsoft-secure.ml', 'apple-id-update.ga',
        'amaz0n-alert.cf', 'github-login.gq', 'paypal-confirm.xyz',
        'netflix-billing.top', 'chase-secure.work', 'bank-verify.club',
        'facebook-login.info', 'instagram-help.site', 'coinbase-wallet.online',
        'binance-airdrop.tech', 'metamask-verify.space', 'steam-gift.monster',
        'dhl-tracking.icu', 'fedex-delivery.buzz', 'usps-package.best',
        'wellsfargo-alert.rest', 'citibank-update.tk',
    ]

    from core.scanner import extract_features, FEATURE_NAMES

    rows = []
    n_benign = n_samples // 2
    n_phish = n_samples - n_benign

    for i in range(n_benign):
        domain = rng.choice(domains_benign)
        paths = ['', '/about', '/login', '/dashboard', '/products', '/pricing',
                 f'/user/{rng.randint(1000, 9999)}', '/docs/api', '/settings']
        path = rng.choice(paths)
        scheme = rng.choice(['https://', 'https://', 'https://', 'http://'])
        url = f"{scheme}{domain}{path}"

        feats = extract_features(url)
        feats['label'] = 0
        feats['timestamp'] = f"2024-{rng.randint(1,6):02d}-{rng.randint(1,28):02d}"
        rows.append(feats)

    for i in range(n_phish):
        domain = rng.choice(domains_phish)
        paths = ['/login', '/verify', '/secure', '/update-billing',
                 f'/account/confirm/{rng.randint(100000, 999999)}',
                 '/password-reset', f'/token/{hex(rng.randint(0, 2**32))}']
        path = rng.choice(paths)
        scheme = rng.choice(['http://', 'https://', 'http://'])
        url = f"{scheme}{domain}{path}"

        feats = extract_features(url)
        feats['label'] = 1
        feats['timestamp'] = f"2024-{rng.randint(4,12):02d}-{rng.randint(1,28):02d}"
        rows.append(feats)

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info(f"Generated sample dataset: {output_path} ({len(df)} samples)")
    return output_path


def run_evaluation(dataset_path: str, output_dir: str):
    """
    Run full evaluation pipeline:
    1. Load dataset
    2. Domain-aware split
    3. Evaluate each model in the ensemble
    4. Generate comprehensive report
    """
    from ml.temporal_split import TemporalDomainSplit
    from ml.metrics_suite import PhishingMetricsSuite, MetricsReport
    from models.inference import model_manager
    from core.scanner import FEATURE_NAMES

    os.makedirs(output_dir, exist_ok=True)

    # ---- 1. Load Dataset ----
    logger.info(f"Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    logger.info(f"Dataset shape: {df.shape}")

    # Determine timestamp column
    timestamp_col = 'timestamp' if 'timestamp' in df.columns else None

    # ---- 2. Domain-Aware Split ----
    splitter = TemporalDomainSplit(
        test_ratio=0.20,
        random_seed=42,
        timestamp_col=timestamp_col,
        url_col='url',
        label_col='label',
    )

    # Filter to only include known feature columns
    available_features = [f for f in FEATURE_NAMES if f in df.columns]
    if len(available_features) < len(FEATURE_NAMES):
        logger.warning(
            f"Only {len(available_features)}/{len(FEATURE_NAMES)} features available in dataset"
        )

    X_train, X_test, y_train, y_test, split_meta = splitter.split(
        df, feature_cols=available_features
    )

    # Save split metadata
    split_report_path = os.path.join(output_dir, 'split_metadata.json')
    with open(split_report_path, 'w') as f:
        json.dump(split_meta, f, indent=2)
    logger.info(f"Split metadata saved to {split_report_path}")

    # ---- 3. Evaluate Models ----
    metrics_suite = PhishingMetricsSuite()

    # Get test URLs for SaaS FPR computation
    test_urls = None
    if 'url' in df.columns:
        # Reconstruct test set URLs
        df_copy = df.copy()
        df_copy['_parent_domain'] = df_copy['url'].apply(
            lambda u: __import__('ml.temporal_split', fromlist=['_extract_parent_domain'])._extract_parent_domain(u)
        )
        # We need to match test indices — use the split metadata
        test_urls = df.iloc[-split_meta['test_samples']:]['url'].tolist()
        if len(test_urls) != len(y_test):
            test_urls = None  # Fallback if alignment is off

    reports = []

    # Scale features for prediction
    if model_manager.scaler is not None:
        X_test_scaled = model_manager.scaler.transform(X_test)
    else:
        X_test_scaled = X_test

    # XGBoost evaluation
    if model_manager.xgb_model is not None:
        y_pred_xgb = model_manager.xgb_model.predict(X_test_scaled)
        y_prob_xgb = model_manager.xgb_model.predict_proba(X_test_scaled)[:, 1]
        report_xgb = metrics_suite.evaluate(
            y_test, y_pred_xgb, y_prob_xgb, test_urls, model_name='XGBoost'
        )
        reports.append(report_xgb)

    # Random Forest evaluation
    if model_manager.rf_model is not None:
        y_pred_rf = model_manager.rf_model.predict(X_test_scaled)
        y_prob_rf = model_manager.rf_model.predict_proba(X_test_scaled)[:, 1]
        report_rf = metrics_suite.evaluate(
            y_test, y_pred_rf, y_prob_rf, test_urls, model_name='Random Forest'
        )
        reports.append(report_rf)

    # MLP Neural Network evaluation
    if model_manager.mlp_model is not None:
        y_pred_mlp = model_manager.mlp_model.predict(X_test_scaled)
        y_prob_mlp = model_manager.mlp_model.predict_proba(X_test_scaled)[:, 1]
        report_mlp = metrics_suite.evaluate(
            y_test, y_pred_mlp, y_prob_mlp, test_urls, model_name='MLP Neural Network'
        )
        reports.append(report_mlp)

    # Weighted Ensemble evaluation
    if len(reports) >= 2:
        from config import settings
        y_prob_ensemble = (
            y_prob_xgb * settings.ENSEMBLE_WEIGHT_XGB +
            y_prob_rf * settings.ENSEMBLE_WEIGHT_RF +
            y_prob_mlp * settings.ENSEMBLE_WEIGHT_MLP
        )
        y_pred_ensemble = (y_prob_ensemble >= 0.5).astype(int)
        report_ensemble = metrics_suite.evaluate(
            y_test, y_pred_ensemble, y_prob_ensemble, test_urls, model_name='Weighted Ensemble'
        )
        reports.append(report_ensemble)

    # ---- 4. Generate Reports ----
    # Individual model reports
    for report in reports:
        report_path = os.path.join(
            output_dir, f'metrics_{report.model_name.lower().replace(" ", "_")}.json'
        )
        with open(report_path, 'w') as f:
            f.write(metrics_suite.to_json(report))
        logger.info(f"Report saved: {report_path}")

    # Comparison report
    if len(reports) > 1:
        comparison = metrics_suite.compare_models(reports)
        comparison_path = os.path.join(output_dir, 'model_comparison.json')
        with open(comparison_path, 'w') as f:
            json.dump(comparison, f, indent=2)
        logger.info(f"Comparison report saved: {comparison_path}")

    # Summary output
    print("\n" + "=" * 70)
    print("  PhishShield AI 2.0 — ML Evaluation Report")
    print(f"  Dataset: {dataset_path}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    print(f"\n  Split: {split_meta['train_samples']} train / {split_meta['test_samples']} test")
    print(f"  Domains: {split_meta['train_domains']} train / {split_meta['test_domains']} test")
    print(f"  Domain Leakage: {split_meta['leaked_domains']} (must be 0)")

    print(f"\n  {'Model':<25} {'Acc':>7} {'F1':>7} {'PR-AUC':>8} {'FPR':>7} {'SaaS-FPR':>10}")
    print("  " + "-" * 66)
    for report in reports:
        print(
            f"  {report.model_name:<25} "
            f"{report.accuracy:>7.4f} "
            f"{report.f1_score:>7.4f} "
            f"{report.pr_auc:>8.4f} "
            f"{report.fpr_overall:>7.4f} "
            f"{report.fpr_enterprise_saas:>10.4f}"
        )

    print(f"\n  Reports saved to: {output_dir}/")
    print("=" * 70 + "\n")


def main():
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    parser = argparse.ArgumentParser(
        description='PhishShield AI 2.0 — ML Evaluation Suite'
    )
    parser.add_argument(
        '--dataset', type=str, default=None,
        help='Path to CSV dataset with url, label, and feature columns'
    )
    parser.add_argument(
        '--output', type=str, default='reports/',
        help='Output directory for evaluation reports (default: reports/)'
    )
    parser.add_argument(
        '--generate-sample', action='store_true',
        help='Generate a synthetic sample dataset for demonstration'
    )

    args = parser.parse_args()

    if args.generate_sample:
        dataset_path = os.path.join('data', 'sample_phishing_urls.csv')
        generate_sample_dataset(dataset_path, n_samples=2000)
        args.dataset = dataset_path

    if not args.dataset:
        parser.error("Please provide --dataset path or use --generate-sample")

    if not os.path.exists(args.dataset):
        parser.error(f"Dataset file not found: {args.dataset}")

    run_evaluation(args.dataset, args.output)


if __name__ == '__main__':
    main()

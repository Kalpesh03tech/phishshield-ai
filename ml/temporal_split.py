"""
PhishShield AI 2.0 - Temporal and Domain-Aware Data Split
Ensures scientifically valid ML evaluation by preventing domain leakage:
- No two subdomains from the same parent domain exist in both training and testing sets
- Optional temporal ordering when timestamps are available
"""

import logging
from typing import Optional, Tuple, List, Set
from collections import defaultdict

import numpy as np
import pandas as pd

logger = logging.getLogger('phishshield.ml.split')


def _extract_parent_domain(url: str) -> str:
    """
    Extract the effective TLD+1 (parent domain) from a URL.
    Uses tldextract for accurate public suffix handling.
    Falls back to simple heuristic if tldextract unavailable.
    """
    try:
        import tldextract
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        elif ext.domain:
            return ext.domain.lower()
        return url.lower()
    except ImportError:
        # Fallback: simple heuristic
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            hostname = parsed.netloc.split(':')[0].lower()
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return hostname
        except Exception:
            return url.lower()


class TemporalDomainSplit:
    """
    Domain-Aware Data Splitter for phishing URL classification.

    Key guarantee: All subdomains of a given parent domain (eTLD+1)
    appear entirely in either the training set OR the test set — never both.
    This prevents information leakage from domain-correlated features.

    Optional temporal ordering ensures the test set contains only URLs
    observed after all training URLs (simulating real-world deployment).
    """

    def __init__(
        self,
        test_ratio: float = 0.20,
        random_seed: int = 42,
        timestamp_col: Optional[str] = None,
        url_col: str = 'url',
        label_col: str = 'label',
    ):
        """
        Args:
            test_ratio: Fraction of data for test set (default 20%).
            random_seed: Reproducibility seed.
            timestamp_col: Column name for timestamps (optional).
            url_col: Column name containing URLs.
            label_col: Column name containing labels (0=benign, 1=phishing).
        """
        self.test_ratio = test_ratio
        self.random_seed = random_seed
        self.timestamp_col = timestamp_col
        self.url_col = url_col
        self.label_col = label_col

    def split(
        self,
        df: pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict]:
        """
        Perform domain-aware (and optionally temporal) train/test split.

        Args:
            df: DataFrame with URL, label, and feature columns.
            feature_cols: List of feature column names. If None, uses all
                          columns except url_col, label_col, and timestamp_col.

        Returns:
            (X_train, X_test, y_train, y_test, split_metadata)
        """
        rng = np.random.RandomState(self.random_seed)

        # Determine feature columns
        exclude_cols = {self.url_col, self.label_col}
        if self.timestamp_col:
            exclude_cols.add(self.timestamp_col)
        if feature_cols is None:
            feature_cols = [c for c in df.columns if c not in exclude_cols]

        logger.info(f"Dataset: {len(df)} samples, {len(feature_cols)} features")

        # Extract parent domains
        df = df.copy()
        df['_parent_domain'] = df[self.url_col].apply(_extract_parent_domain)

        # Group indices by parent domain
        domain_groups: dict = defaultdict(list)
        for idx, row in df.iterrows():
            domain_groups[row['_parent_domain']].append(idx)

        # Optional temporal ordering: sort domains by earliest timestamp
        domain_list = list(domain_groups.keys())
        if self.timestamp_col and self.timestamp_col in df.columns:
            domain_min_time = {}
            for domain, indices in domain_groups.items():
                timestamps = pd.to_datetime(df.loc[indices, self.timestamp_col], errors='coerce')
                valid_ts = timestamps.dropna()
                if len(valid_ts) > 0:
                    domain_min_time[domain] = valid_ts.min()
                else:
                    domain_min_time[domain] = pd.Timestamp.max

            domain_list.sort(key=lambda d: domain_min_time.get(d, pd.Timestamp.max))
            logger.info("Temporal ordering applied: domains sorted by earliest observation")
        else:
            # Shuffle domains for random split
            rng.shuffle(domain_list)

        # Split domains into train/test based on sample count ratio
        total_samples = len(df)
        target_test_samples = int(total_samples * self.test_ratio)

        test_domains: Set[str] = set()
        test_sample_count = 0

        # Assign domains to test set from the END (most recent in temporal mode)
        for domain in reversed(domain_list):
            if test_sample_count >= target_test_samples:
                break
            test_domains.add(domain)
            test_sample_count += len(domain_groups[domain])

        train_domains = set(domain_list) - test_domains

        # Build index arrays
        train_indices = []
        test_indices = []
        for domain in train_domains:
            train_indices.extend(domain_groups[domain])
        for domain in test_domains:
            test_indices.extend(domain_groups[domain])

        # Extract arrays
        X_train = df.loc[train_indices, feature_cols].values
        X_test = df.loc[test_indices, feature_cols].values
        y_train = df.loc[train_indices, self.label_col].values.astype(int)
        y_test = df.loc[test_indices, self.label_col].values.astype(int)

        # Verify no domain leakage
        train_parent_domains = set(df.loc[train_indices, '_parent_domain'].unique())
        test_parent_domains = set(df.loc[test_indices, '_parent_domain'].unique())
        leaked_domains = train_parent_domains & test_parent_domains

        assert len(leaked_domains) == 0, (
            f"DOMAIN LEAKAGE DETECTED: {len(leaked_domains)} domains appear in both splits: "
            f"{list(leaked_domains)[:10]}"
        )

        # Compute split metadata
        metadata = {
            'total_samples': total_samples,
            'train_samples': len(train_indices),
            'test_samples': len(test_indices),
            'actual_test_ratio': round(len(test_indices) / total_samples, 4),
            'total_unique_domains': len(domain_list),
            'train_domains': len(train_domains),
            'test_domains': len(test_domains),
            'leaked_domains': len(leaked_domains),
            'temporal_split': self.timestamp_col is not None,
            'feature_count': len(feature_cols),
            'feature_names': feature_cols,
            'train_label_distribution': {
                'benign': int(np.sum(y_train == 0)),
                'phishing': int(np.sum(y_train == 1)),
            },
            'test_label_distribution': {
                'benign': int(np.sum(y_test == 0)),
                'phishing': int(np.sum(y_test == 1)),
            },
        }

        logger.info(
            f"Split complete: "
            f"train={metadata['train_samples']} ({metadata['train_domains']} domains), "
            f"test={metadata['test_samples']} ({metadata['test_domains']} domains), "
            f"leakage={metadata['leaked_domains']}"
        )

        return X_train, X_test, y_train, y_test, metadata

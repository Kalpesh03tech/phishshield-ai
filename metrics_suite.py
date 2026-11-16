"""
PhishShield AI 2.0 - Comprehensive ML Performance Metrics Suite
Calculates scientifically rigorous evaluation metrics for phishing classification:

- Accuracy, Precision, Recall, F1-Score
- Precision-Recall AUC
- ROC AUC
- False Positive Rate (overall and Enterprise SaaS-specific)
- Confusion Matrix with normalized heatmap
"""

import json
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger('phishshield.ml.metrics')

# Enterprise SaaS domains for FPR-specific analysis
ENTERPRISE_SAAS_DOMAINS = {
    'salesforce.com', 'slack.com', 'zoom.us', 'github.com', 'gitlab.com',
    'atlassian.com', 'jira.com', 'confluence.com', 'notion.so',
    'dropbox.com', 'box.com', 'google.com', 'microsoft.com',
    'office365.com', 'office.com', 'okta.com', 'auth0.com',
    'datadog.com', 'splunk.com', 'pagerduty.com', 'twilio.com',
    'sendgrid.com', 'hubspot.com', 'intercom.com', 'zendesk.com',
    'freshdesk.com', 'monday.com', 'asana.com', 'trello.com',
    'figma.com', 'canva.com', 'adobe.com', 'aws.amazon.com',
    'cloud.google.com', 'azure.microsoft.com', 'heroku.com',
    'vercel.com', 'netlify.com', 'cloudflare.com',
    'stripe.com', 'square.com', 'shopify.com', 'bigcommerce.com',
    'linkedin.com', 'indeed.com', 'workday.com', 'bamboohr.com',
    'gusto.com', 'rippling.com', 'sap.com', 'oracle.com',
    'servicenow.com', 'snowflake.com', 'databricks.com',
}


@dataclass
class MetricsReport:
    """Structured performance metrics report."""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    pr_auc: float = 0.0
    roc_auc: float = 0.0
    fpr_overall: float = 0.0
    fpr_enterprise_saas: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=lambda: [[0, 0], [0, 0]])
    confusion_matrix_normalized: List[List[float]] = field(default_factory=lambda: [[0, 0], [0, 0]])
    total_samples: int = 0
    enterprise_saas_samples: int = 0
    model_name: str = ''
    additional_metrics: Dict[str, Any] = field(default_factory=dict)


class PhishingMetricsSuite:
    """
    Comprehensive evaluation suite for phishing URL classifiers.
    Computes standard and domain-specific metrics.
    """

    def __init__(self, enterprise_domains: Optional[set] = None):
        self.enterprise_domains = enterprise_domains or ENTERPRISE_SAAS_DOMAINS

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
        urls: Optional[List[str]] = None,
        model_name: str = 'Ensemble',
    ) -> MetricsReport:
        """
        Compute comprehensive performance metrics.

        Args:
            y_true: Ground truth labels (0=benign, 1=phishing)
            y_pred: Predicted labels (0=benign, 1=phishing)
            y_prob: Predicted probabilities for positive class (optional, for AUC)
            urls: List of URLs corresponding to each sample (for SaaS FPR)
            model_name: Name of the model being evaluated

        Returns:
            MetricsReport with all computed metrics
        """
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            confusion_matrix, roc_auc_score, average_precision_score,
        )

        report = MetricsReport(model_name=model_name)
        report.total_samples = len(y_true)

        # ---- Core Metrics ----
        report.accuracy = round(float(accuracy_score(y_true, y_pred)), 4)
        report.precision = round(float(precision_score(y_true, y_pred, zero_division=0)), 4)
        report.recall = round(float(recall_score(y_true, y_pred, zero_division=0)), 4)
        report.f1_score = round(float(f1_score(y_true, y_pred, zero_division=0)), 4)

        # ---- Confusion Matrix ----
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        report.confusion_matrix = cm.tolist()

        # Normalized confusion matrix
        cm_norm = cm.astype(float)
        row_sums = cm_norm.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1  # Prevent division by zero
        cm_normalized = (cm_norm / row_sums).round(4)
        report.confusion_matrix_normalized = cm_normalized.tolist()

        # ---- False Positive Rate ----
        tn, fp, fn, tp = cm.ravel()
        report.fpr_overall = round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4)

        # ---- AUC Metrics (require probability scores) ----
        if y_prob is not None and len(np.unique(y_true)) > 1:
            try:
                report.pr_auc = round(float(average_precision_score(y_true, y_prob)), 4)
            except Exception as e:
                logger.warning(f"PR-AUC computation failed: {e}")
                report.pr_auc = 0.0

            try:
                report.roc_auc = round(float(roc_auc_score(y_true, y_prob)), 4)
            except Exception as e:
                logger.warning(f"ROC-AUC computation failed: {e}")
                report.roc_auc = 0.0

        # ---- Enterprise SaaS FPR ----
        if urls is not None:
            report.fpr_enterprise_saas = self._compute_enterprise_fpr(
                y_true, y_pred, urls
            )
            report.enterprise_saas_samples = sum(
                1 for url in urls
                if self._is_enterprise_saas(url)
            )

        # ---- Additional Metrics ----
        report.additional_metrics = {
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'positive_class_count': int(np.sum(y_true == 1)),
            'negative_class_count': int(np.sum(y_true == 0)),
            'class_balance_ratio': round(
                float(np.sum(y_true == 1)) / len(y_true) if len(y_true) > 0 else 0, 4
            ),
        }

        logger.info(
            f"Metrics [{model_name}]: Acc={report.accuracy}, "
            f"F1={report.f1_score}, PR-AUC={report.pr_auc}, "
            f"FPR={report.fpr_overall}, SaaS-FPR={report.fpr_enterprise_saas}"
        )

        return report

    def _is_enterprise_saas(self, url: str) -> bool:
        """Check if a URL belongs to an Enterprise SaaS domain."""
        try:
            import tldextract
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}".lower()
            return domain in self.enterprise_domains
        except ImportError:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                hostname = parsed.netloc.split(':')[0].lower()
                return any(hostname.endswith(d) for d in self.enterprise_domains)
            except Exception:
                return False

    def _compute_enterprise_fpr(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        urls: List[str],
    ) -> float:
        """
        Compute False Positive Rate specifically for Enterprise SaaS domains.
        A false positive here means a legitimate SaaS URL is incorrectly
        classified as phishing — this is a critical business metric.
        """
        saas_indices = [
            i for i, url in enumerate(urls)
            if self._is_enterprise_saas(url)
        ]

        if not saas_indices:
            return 0.0

        saas_true = np.array([y_true[i] for i in saas_indices])
        saas_pred = np.array([y_pred[i] for i in saas_indices])

        # Only consider benign SaaS samples (y_true == 0)
        benign_mask = saas_true == 0
        if np.sum(benign_mask) == 0:
            return 0.0

        false_positives = np.sum((saas_pred[benign_mask] == 1))
        total_benign = np.sum(benign_mask)

        fpr = float(false_positives / total_benign)
        logger.info(
            f"Enterprise SaaS FPR: {false_positives}/{total_benign} = {fpr:.4f} "
            f"({len(saas_indices)} SaaS samples total)"
        )

        return round(fpr, 4)

    def compare_models(
        self,
        reports: List[MetricsReport],
    ) -> dict:
        """
        Compare multiple model evaluation reports side-by-side.
        Returns a summary comparison dict.
        """
        comparison = {
            'models': [],
            'best_f1': {'model': '', 'score': 0.0},
            'best_pr_auc': {'model': '', 'score': 0.0},
            'lowest_fpr': {'model': '', 'score': 1.0},
            'lowest_saas_fpr': {'model': '', 'score': 1.0},
        }

        for report in reports:
            model_summary = {
                'model_name': report.model_name,
                'accuracy': report.accuracy,
                'precision': report.precision,
                'recall': report.recall,
                'f1_score': report.f1_score,
                'pr_auc': report.pr_auc,
                'roc_auc': report.roc_auc,
                'fpr_overall': report.fpr_overall,
                'fpr_enterprise_saas': report.fpr_enterprise_saas,
            }
            comparison['models'].append(model_summary)

            if report.f1_score > comparison['best_f1']['score']:
                comparison['best_f1'] = {'model': report.model_name, 'score': report.f1_score}
            if report.pr_auc > comparison['best_pr_auc']['score']:
                comparison['best_pr_auc'] = {'model': report.model_name, 'score': report.pr_auc}
            if report.fpr_overall < comparison['lowest_fpr']['score']:
                comparison['lowest_fpr'] = {'model': report.model_name, 'score': report.fpr_overall}
            if report.fpr_enterprise_saas < comparison['lowest_saas_fpr']['score']:
                comparison['lowest_saas_fpr'] = {'model': report.model_name, 'score': report.fpr_enterprise_saas}

        return comparison

    def to_json(self, report: MetricsReport) -> str:
        """Serialize a MetricsReport to JSON string."""
        return json.dumps({
            'model_name': report.model_name,
            'total_samples': report.total_samples,
            'accuracy': report.accuracy,
            'precision': report.precision,
            'recall': report.recall,
            'f1_score': report.f1_score,
            'pr_auc': report.pr_auc,
            'roc_auc': report.roc_auc,
            'fpr_overall': report.fpr_overall,
            'fpr_enterprise_saas': report.fpr_enterprise_saas,
            'enterprise_saas_samples': report.enterprise_saas_samples,
            'confusion_matrix': report.confusion_matrix,
            'confusion_matrix_normalized': report.confusion_matrix_normalized,
            'additional_metrics': report.additional_metrics,
        }, indent=2)

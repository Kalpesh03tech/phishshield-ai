/**
 * PhishShield AI - Interactive Client Logic & Visualization Engine
 * Manages API communication, Chart.js graphs, history persistence, and exports.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- Global State & Chart Instances ---
    let gaugeChart = null;
    let radarChart = null;
    let featureChart = null;
    let lastScanResult = null;

    // --- DOM Element References ---
    const navTabs = document.querySelectorAll('.nav-tab');
    const tabPages = document.querySelectorAll('.tab-page');

    const urlInput = document.getElementById('url-input');
    const btnScan = document.getElementById('btn-scan');
    const btnClear = document.getElementById('btn-clear');
    const sampleChips = document.querySelectorAll('.sample-chip');

    const scanLoading = document.getElementById('scan-loading');
    const scanResults = document.getElementById('scan-results');
    const scanErrorCard = document.getElementById('scan-error-card');
    const errorCardTitle = document.getElementById('error-card-title');
    const errorCardDesc = document.getElementById('error-card-desc');

    // Result DOMs
    const resultsBanner = document.getElementById('results-banner');
    const threatBadge = document.getElementById('threat-badge');
    const threatLevelText = document.getElementById('threat-level-text');
    const targetUrlDisplay = document.getElementById('target-url-display');
    const summaryMsgDisplay = document.getElementById('summary-msg-display');
    const latencyDisplay = document.getElementById('latency-display');
    const timestampDisplay = document.getElementById('timestamp-display');
    const gaugeScoreNum = document.getElementById('gauge-score-num');

    const xgbScoreVal = document.getElementById('xgb-score-val');
    const xgbProgress = document.getElementById('xgb-progress');
    const rfScoreVal = document.getElementById('rf-score-val');
    const rfProgress = document.getElementById('rf-progress');
    const mlpScoreVal = document.getElementById('mlp-score-val');
    const mlpProgress = document.getElementById('mlp-progress');

    // Sandbox DOMs
    const sandboxUrlText = document.getElementById('sandbox-url-text');
    const sandboxLockIcon = document.getElementById('sandbox-lock-icon');
    const inspectHttps = document.getElementById('inspect-https');
    const inspectIp = document.getElementById('inspect-ip');
    const inspectShortener = document.getElementById('inspect-shortener');
    const inspectEntropy = document.getElementById('inspect-entropy');
    const inspectSubdomains = document.getElementById('inspect-subdomains');

    const xaiTableBody = document.getElementById('xai-table-body');
    const btnExportJson = document.getElementById('btn-export-json');
    const btnPrintReport = document.getElementById('btn-print-report');

    // Batch DOMs
    const batchUrlsInput = document.getElementById('batch-urls-input');
    const btnRunBatch = document.getElementById('btn-run-batch');
    const btnClearBatch = document.getElementById('btn-clear-batch');
    const batchResultsContainer = document.getElementById('batch-results-container');
    const batchTableBody = document.getElementById('batch-table-body');

    // History DOMs
    const historyTableBody = document.getElementById('history-table-body');
    const btnExportCsv = document.getElementById('btn-export-csv');
    const btnClearHistory = document.getElementById('btn-clear-history');


    function updateAnalyticsBar() {
        fetch('/api/analytics')
            .then(res => res.json())
            .then(res => {
                if (res.status === 'success' && res.data) {
                    const d = res.data;
                    const totalEl = document.getElementById('stat-total-scans');
                    const safePctEl = document.getElementById('stat-safe-pct');
                    const threatsEl = document.getElementById('stat-threats-count');
                    const speedEl = document.getElementById('stat-avg-speed');

                    if (totalEl) totalEl.textContent = d.total_scans;
                    if (safePctEl) safePctEl.textContent = d.safe_percentage + '%';
                    if (threatsEl) threatsEl.textContent = d.suspicious_count + d.danger_count;
                    if (speedEl) speedEl.textContent = d.avg_latency_ms + ' ms';
                }
            })
            .catch(() => {});
    }

    updateAnalyticsBar();


    // ================= 1. TAB SWITCHING LOGIC =================
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            navTabs.forEach(t => t.classList.remove('active'));
            tabPages.forEach(p => p.classList.remove('active'));


            tab.classList.add('active');
            const targetPageId = tab.getAttribute('data-tab');
            document.getElementById(targetPageId).classList.add('active');

            if (targetPageId === 'history-tab') {
                loadScanHistory();
                loadLiveLogs();
            }

        });
    });


    // ================= 2. INPUT HANDLERS =================
    urlInput.addEventListener('input', () => {
        btnClear.style.display = urlInput.value.length > 0 ? 'inline-block' : 'none';
    });

    btnClear.addEventListener('click', () => {
        urlInput.value = '';
        btnClear.style.display = 'none';
        urlInput.focus();
    });



    function isValidUrlInput(str) {
        if (!str || typeof str !== 'string') return false;
        const clean = str.trim().toLowerCase();

        if (clean.startsWith('http://') || clean.startsWith('https://')) {
            return clean.replace('http://', '').replace('https://', '').trim().length >= 3;
        }

        // IPv4 regex
        const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:\/.*)?$/;
        if (ipv4Regex.test(clean)) return true;

        // Domain pattern regex (must have dot and domain extension like example.com)
        const domainRegex = /^[a-zA-Z0-9-]{1,63}\.[a-zA-Z0-9.-]{2,}(?::[0-9]{1,5})?(?:\/.*)?$/;
        return domainRegex.test(clean);
    }

    btnScan.addEventListener('click', () => {
        const inputVal = urlInput.value.trim();
        if (!inputVal) {
            alert('Please paste or type a URL link to scan.');
            return;
        }
        if (!isValidUrlInput(inputVal)) {
            alert('Invalid Input: Please enter a valid website URL or domain link (e.g., https://example.com, google.com, or 192.168.1.1). Plain words are not links.');
            return;
        }
        triggerScan(inputVal);
    });

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            btnScan.click();
        }
    });


    // ================= 3. SINGLE SCAN EXECUTION =================
    async function triggerScan(url) {
        scanResults.style.display = 'none';
        if (scanErrorCard) scanErrorCard.style.display = 'none';
        scanLoading.style.display = 'block';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                let errMsg = `Server returned HTTP ${response.status}`;
                try {
                    const errData = await response.json();
                    errMsg = errData.error || errMsg;
                } catch (_) {}

                if (scanErrorCard) {
                    if (errorCardTitle) errorCardTitle.textContent = "Website Unreachable or Non-Existent";
                    if (errorCardDesc) errorCardDesc.textContent = errMsg;
                    scanErrorCard.style.display = 'block';
                }
                return;
            }

            const data = await response.json();
            lastScanResult = data;

            // Render results dashboard
            renderResults(data);
            saveToHistory(data);
            updateAnalyticsBar();


        } catch (error) {
            if (scanErrorCard) {
                if (errorCardTitle) errorCardTitle.textContent = "Scan Request Failed";
                if (errorCardDesc) errorCardDesc.textContent = error.message;
                scanErrorCard.style.display = 'block';
            }
        } finally {
            scanLoading.style.display = 'none';
        }
    }


    // ================= 4. RENDER SCAN RESULTS =================
    function renderResults(rawData) {
        if (!rawData) return;
        const data = (rawData.data && (rawData.data.threat_level || rawData.data.url)) ? rawData.data : rawData;
        scanResults.style.display = 'block';

        // 4.1 Update Banner & Badges
        resultsBanner.className = `banner-card ${data.badge_class || 'success'}`;
        threatBadge.className = `threat-badge ${data.badge_class || 'success'}`;
        threatLevelText.textContent = data.threat_level || 'UNKNOWN';
        targetUrlDisplay.textContent = data.url;
        summaryMsgDisplay.textContent = data.summary_msg;
        latencyDisplay.textContent = `${data.latency_ms} ms`;
        timestampDisplay.textContent = data.timestamp;

        // 4.2 Score Gauge
        gaugeScoreNum.textContent = `${data.risk_score}%`;
        let gaugeColor = '#10b981';
        if (data.badge_class === 'danger') gaugeColor = '#ff0055';
        else if (data.badge_class === 'warning') gaugeColor = '#f59e0b';
        else if (data.badge_class === 'inactive') gaugeColor = '#94a3b8';

        gaugeScoreNum.style.color = gaugeColor;
        renderGaugeChart(data.risk_score, gaugeColor);

        // 4.3 Model Scores
        if (xgbScoreVal && xgbProgress) {
            xgbScoreVal.textContent = `${data.xgb_score || data.rf_score}%`;
            xgbProgress.className = `progress-fill ${data.badge_class}`;
            xgbProgress.style.width = `${data.xgb_score || data.rf_score}%`;
        }

        rfScoreVal.textContent = `${data.rf_score}%`;
        rfProgress.className = `progress-fill ${data.badge_class}`;
        rfProgress.style.width = `${data.rf_score}%`;

        mlpScoreVal.textContent = `${data.mlp_score}%`;
        mlpProgress.className = `progress-fill ${data.badge_class}`;
        mlpProgress.style.width = `${data.mlp_score}%`;

        // 4.4 Threat Radar Chart
        renderRadarChart(data.radar_vectors, gaugeColor);

        // 4.5 Inspection Sandbox
        sandboxUrlText.textContent = data.url;
        if (data.features.is_https === 1) {
            sandboxLockIcon.className = 'fa-solid fa-lock text-success';
            inspectHttps.className = 'inspect-badge success';
            inspectHttps.textContent = 'Active (HTTPS)';
        } else {
            sandboxLockIcon.className = 'fa-solid fa-lock-open text-danger';
            inspectHttps.className = 'inspect-badge danger';
            inspectHttps.textContent = 'Disabled (HTTP)';
        }

        // Live DNS IP Display
        if (data.live_info && data.live_info.ip_address) {
            inspectIp.className = 'inspect-badge success';
            inspectIp.textContent = `${data.live_info.ip_address}`;
        } else if (data.live_info && !data.live_info.exists) {
            inspectIp.className = 'inspect-badge danger';
            inspectIp.textContent = 'NXDOMAIN (Unregistered)';
        } else if (data.features.has_ip === 1) {
            inspectIp.className = 'inspect-badge danger';
            inspectIp.textContent = 'Raw IP Host';
        } else {
            inspectIp.className = 'inspect-badge success';
            inspectIp.textContent = 'Domain Active';
        }

        if (data.features.is_shortened === 1) {
            inspectShortener.className = 'inspect-badge danger';
            inspectShortener.textContent = 'Shortened Link';
        } else {
            inspectShortener.className = 'inspect-badge success';
            inspectShortener.textContent = 'Direct URL';
        }

        inspectEntropy.textContent = `${data.features.shannon_entropy_host} (${data.features.shannon_entropy_host > 3.4 ? 'High/Random' : 'Normal'})`;
        inspectSubdomains.textContent = `${data.features.subdomain_count} Subdomain(s)`;

        // Render SSL Certificate Fingerprint
        if (data.ssl_info) {
            const sslIssuerEl = document.getElementById('inspect-ssl-issuer');
            const sslExpiryEl = document.getElementById('inspect-ssl-expiry');
            if (sslIssuerEl) sslIssuerEl.textContent = data.ssl_info.issuer || 'N/A';
            if (sslExpiryEl) {
                if (data.ssl_info.has_ssl && data.ssl_info.valid_to) {
                    const daysLeftStr = data.ssl_info.days_left !== undefined ? `${data.ssl_info.days_left}d left` : 'Valid';
                    sslExpiryEl.textContent = `${data.ssl_info.valid_to} (${daysLeftStr})`;
                    sslExpiryEl.style.color = data.ssl_info.is_expired ? '#ff0055' : '#10b981';
                } else {
                    sslExpiryEl.textContent = 'Unencrypted / No SSL';
                    sslExpiryEl.style.color = '#ff0055';
                }
            }
        }

        // 4.6 Explainable AI (XAI) Table
        xaiTableBody.innerHTML = '';
        data.risk_factors.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-weight: 600;">${item.factor}</td>
                <td><span class="sev-tag ${item.severity}">${item.severity}</span></td>
                <td style="font-family: var(--font-mono); font-weight: 700; color: ${item.severity === 'SAFE' ? '#10b981' : '#ff0055'};">${item.impact}</td>
                <td style="color: var(--text-secondary);">${item.description}</td>
            `;
            xaiTableBody.appendChild(tr);
        });

        // 4.7 Website Content Analysis Panel
        renderContentAnalysis(data.content_analysis, data.content_score);

        // 4.8 Dynamic LLM AI Threat Intelligence Panel
        renderLLMAnalysis(data.llm_analysis);

        // Smooth scroll to results
        scanResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }


    // ================= 4a. RENDER DYNAMIC LLM ANALYSIS =================
    function renderLLMAnalysis(llm) {
        const card = document.getElementById('llm-analysis-card');
        const badge = document.getElementById('llm-provider-badge');
        const summary = document.getElementById('llm-summary-text');
        const vectorsContainer = document.getElementById('llm-attack-vectors');
        const actionsList = document.getElementById('llm-actions-list');
        const reasoning = document.getElementById('llm-reasoning-text');

        if (!card || !llm) return;

        if (badge) badge.textContent = llm.provider_used || 'DeepSeek V4 / Nemotron';
        if (summary) summary.textContent = llm.ai_summary || 'No threat summary available.';
        
        if (vectorsContainer) {
            vectorsContainer.innerHTML = '';
            const rawVectors = llm.attack_vectors || llm.identified_attack_vectors || [];
            const activeThreats = rawVectors.filter(v => {
                if (!v || typeof v !== 'string') return false;
                const lower = v.trim().toLowerCase();
                return !lower.startsWith('no ') && !lower.startsWith('none') && !lower.startsWith('clean') && lower !== 'n/a' && lower !== 'none';
            });

            if (lastScanResult && (lastScanResult.threat_level === 'NON-EXISTENT DOMAIN' || lastScanResult.badge_class === 'inactive')) {
                vectorsContainer.innerHTML = '<span class="vector-tag" style="background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); font-size: 12px; padding: 4px 10px; border-radius: 4px;"><i class="fa-solid fa-globe-slash"></i> Inactive Host — DNS Resolution Failed</span>';
            } else if (activeThreats.length === 0) {
                vectorsContainer.innerHTML = '<span class="vector-tag" style="background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); font-size: 12px; padding: 4px 10px; border-radius: 4px;"><i class="fa-solid fa-shield-check"></i> Clean Profile — No Active Attack Vectors</span>';
            } else {
                activeThreats.forEach(v => {
                    const tag = document.createElement('span');
                    tag.style.cssText = 'background: rgba(244, 63, 94, 0.15); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.3); font-size: 12px; padding: 4px 10px; border-radius: 4px;';
                    tag.textContent = v;
                    vectorsContainer.appendChild(tag);
                });
            }
        }


        if (actionsList) {
            actionsList.innerHTML = '';
            const actions = llm.recommended_actions || [];
            if (actions.length === 0) {
                actionsList.innerHTML = '<li>Standard browsing precautions.</li>';
            } else {
                actions.forEach(act => {
                    const li = document.createElement('li');
                    li.textContent = act;
                    actionsList.appendChild(li);
                });
            }
        }

        if (reasoning) {
            reasoning.textContent = `Confidence Reasoning: ${llm.confidence_reasoning || 'Derived from neural feature analysis and live HTML inspection.'}`;
        }
    }


    // ================= 4b. RENDER CONTENT ANALYSIS =================
    function renderContentAnalysis(ca, contentScore) {
        const scoreBar = document.getElementById('content-score-bar');
        const scorePct = document.getElementById('content-score-pct');
        const scoreDisplay = document.getElementById('content-score-display');
        const signalsGrid = document.getElementById('content-signals-grid');

        const score = contentScore || (ca && ca.content_score) || 0;

        // Score bar color
        let barClass = 'success';
        if (score >= 65) barClass = 'danger';
        else if (score >= 35) barClass = 'warning';

        if (scoreBar) {
            scoreBar.className = `progress-fill ${barClass}`;
            scoreBar.style.width = `${score}%`;
        }
        if (scorePct) {
            scorePct.textContent = `${score}%`;
            scorePct.style.color = score >= 65 ? '#ff0055' : score >= 35 ? '#f59e0b' : '#10b981';
        }
        if (scoreDisplay) {
            scoreDisplay.textContent = `${score}%`;
        }

        if (!signalsGrid) return;

        // If content analysis failed or not done
        if (!ca || !ca.analyzed) {
            signalsGrid.innerHTML = `
                <div class="content-signal-card safe">
                    <i class="fa-solid fa-circle-info signal-icon"></i>
                    <div class="signal-body">
                        <div class="signal-name">Content Scan Unavailable</div>
                        <div class="signal-detail">${ca && ca.error ? ca.error : 'Website did not respond in time or blocked the scanner.'}</div>
                    </div>
                    <span class="sev-tag MEDIUM">N/A</span>
                </div>`;
            return;
        }

        // Page metadata safely
        const titleEl = document.getElementById('content-page-title');
        const redirectEl = document.getElementById('content-redirect');
        const formsEl = document.getElementById('content-forms');
        const passEl = document.getElementById('content-password');
        const scriptsEl = document.getElementById('content-scripts');

        if (titleEl) titleEl.textContent = ca.page_title || '(No title)';
        if (redirectEl) {
            redirectEl.innerHTML = ca.redirect_detected
                ? `<span style="color:#f59e0b"><i class="fa-solid fa-triangle-exclamation"></i> Yes</span>`
                : `<span style="color:#10b981"><i class="fa-solid fa-check"></i> No</span>`;
        }
        if (formsEl) formsEl.textContent = `${ca.form_count || 0} form(s)`;
        if (passEl) {
            passEl.innerHTML = ca.has_password_field
                ? `<span style="color:#f59e0b"><i class="fa-solid fa-key"></i> Detected</span>`
                : `<span style="color:#10b981"><i class="fa-solid fa-check"></i> None</span>`;
        }
        if (scriptsEl) scriptsEl.textContent = `${ca.external_script_count || 0} scripts`;


        // Render signal cards
        if (!ca.signals || ca.signals.length === 0) {
            signalsGrid.innerHTML = `<div class="content-scanning-msg"><i class="fa-solid fa-check-circle" style="color:#10b981"></i> No content threats detected.</div>`;
            return;
        }

        signalsGrid.innerHTML = '';
        ca.signals.forEach(sig => {
            const sevClass = sig.severity === 'CRITICAL' ? 'danger' :
                             sig.severity === 'HIGH' ? 'danger' :
                             sig.severity === 'MEDIUM' ? 'warning' :
                             sig.severity === 'LOW' ? 'warning' : 'safe';
            const card = document.createElement('div');
            card.className = `content-signal-card ${sevClass}`;
            card.innerHTML = `
                <i class="fa-solid ${sig.icon || 'fa-circle-exclamation'} signal-icon"></i>
                <div class="signal-body">
                    <div class="signal-name">${sig.signal}</div>
                    <div class="signal-detail">${sig.detail}</div>
                </div>
                <span class="sev-tag ${sig.severity}">${sig.severity}</span>
            `;
            signalsGrid.appendChild(card);
        });
    }


    // ================= 5. CHART.JS RENDERING FUNCTIONS =================

    // Gauge Doughnut Chart
    function renderGaugeChart(score, colorHex) {
        const ctx = document.getElementById('gaugeChart').getContext('2d');
        if (gaugeChart) gaugeChart.destroy();

        gaugeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [colorHex, 'rgba(255, 255, 255, 0.06)'],
                    borderWidth: 0,
                    circumference: 240,
                    rotation: 240
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '82%',
                plugins: {
                    tooltip: { enabled: false }
                }
            }
        });
    }

    // Threat Radar Profile Chart
    function renderRadarChart(vectors, colorHex) {
        const ctx = document.getElementById('radarChart').getContext('2d');
        if (radarChart) radarChart.destroy();

        if (!vectors || Array.isArray(vectors) || typeof vectors !== 'object') {
            vectors = {
                'Lexical Anomaly': 0,
                'Keyword Threat': 0,
                'Domain Reputation': 0,
                'Entropy Randomness': 0,
                'Structural Risk': 0
            };
        }

        const labels = Object.keys(vectors);
        const values = Object.values(vectors);

        radarChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Risk Severity Profile',
                    data: values,
                    backgroundColor: colorHex === '#ff0055' ? 'rgba(255, 0, 85, 0.25)' : 'rgba(0, 242, 254, 0.25)',
                    borderColor: colorHex,
                    borderWidth: 2,
                    pointBackgroundColor: colorHex,
                    pointBorderColor: '#fff',
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
                        grid: { color: 'rgba(255, 255, 255, 0.08)' },
                        pointLabels: {
                            color: '#94a3b8',
                            font: { family: 'Outfit', size: 12, weight: '600' }
                        },
                        ticks: { display: false, beginAtZero: true, max: 100 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }


    // ================= 6. BATCH URL SCANNER =================
    if (btnRunBatch) {
        btnRunBatch.addEventListener('click', async () => {
            const rawText = batchUrlsInput.value.trim();
            if (!rawText) {
                alert('Please paste at least one URL into the batch text area.');
                return;
            }

            const urlList = rawText.split('\n')
                .map(u => u.trim())
                .filter(u => u.length > 0 && !u.startsWith('#') && !u.startsWith('//') && isValidUrlInput(u));

            if (urlList.length === 0) {
                alert('No valid URLs found in batch input. Comment lines starting with "#" or non-URL titles are automatically skipped.');
                return;
            }
            btnRunBatch.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auditing Batch...';
            btnRunBatch.disabled = true;

            try {
                const response = await fetch('/api/scan-batch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls: urlList })
                });

                const data = await response.json();
                renderBatchResults(data.results);
            } catch (err) {
                alert('Batch Scan Failed: ' + err.message);
            } finally {
                btnRunBatch.innerHTML = '<i class="fa-solid fa-play"></i> Run Batch Audit';
                btnRunBatch.disabled = false;
            }
        });
    }

    if (btnClearBatch) {
        btnClearBatch.addEventListener('click', () => {
            if (batchUrlsInput) batchUrlsInput.value = '';
            if (batchResultsContainer) batchResultsContainer.style.display = 'none';
        });
    }

    function renderBatchResults(results) {
        batchResultsContainer.style.display = 'block';
        batchTableBody.innerHTML = '';

        let dangerCnt = 0, warningCnt = 0, safeCnt = 0;

        results.forEach(res => {
            if (res.badge_class === 'danger') dangerCnt++;
            else if (res.badge_class === 'warning') warningCnt++;
            else if (res.badge_class === 'success') safeCnt++;

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 13px;">${res.url}</td>
                <td><span class="threat-badge ${res.badge_class}">${res.threat_level}</span></td>
                <td style="font-family: var(--font-mono); font-weight: 700;">${res.risk_score}%</td>
                <td>${res.xgb_score || res.rf_score}%</td>
                <td>${res.rf_score}%</td>
                <td>${res.mlp_score}%</td>
                <td>
                    <button class="btn-secondary btn-inspect-item" data-url="${res.url}">
                        <i class="fa-solid fa-magnifying-glass"></i> Inspect
                    </button>
                </td>
            `;
            batchTableBody.appendChild(tr);
        });

        document.getElementById('batch-count-total').textContent = results.length;
        document.getElementById('batch-count-danger').textContent = dangerCnt;
        document.getElementById('batch-count-warning').textContent = warningCnt;
        document.getElementById('batch-count-safe').textContent = safeCnt;

        document.querySelectorAll('.btn-inspect-item').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetUrl = btn.getAttribute('data-url');
                document.getElementById('tab-scanner').click();
                urlInput.value = targetUrl;
                btnClear.style.display = 'inline-block';
                triggerScan(targetUrl);
            });
        });
    }


    // ================= 7. AI MODEL INSIGHTS & RETRAIN =================
    async function loadModelStats() {
        try {
            const response = await fetch('/api/model-stats');
            const meta = await response.json();

            document.getElementById('meta-accuracy').textContent = `${meta.accuracy}%`;
            document.getElementById('meta-rf-acc').textContent = `${meta.rf_accuracy}%`;
            document.getElementById('meta-mlp-acc').textContent = `${meta.mlp_accuracy}%`;
            document.getElementById('meta-auc').textContent = meta.roc_auc;

            // Confusion Matrix
            if (meta.confusion_matrix && meta.confusion_matrix.length === 2) {
                document.getElementById('cm-tn').textContent = meta.confusion_matrix[0][0];
                document.getElementById('cm-fp').textContent = meta.confusion_matrix[0][1];
                document.getElementById('cm-fn').textContent = meta.confusion_matrix[1][0];
                document.getElementById('cm-tp').textContent = meta.confusion_matrix[1][1];
            }

            // Render Feature Importance Chart
            if (meta.feature_importances) {
                renderFeatureChart(meta.feature_importances);
            }
        } catch (err) {
            console.error('Failed to load model stats:', err);
        }
    }

    function renderFeatureChart(importances) {
        if (!importances || typeof importances !== 'object') return;

        const ctx = document.getElementById('featureChart').getContext('2d');
        if (featureChart) featureChart.destroy();

        const top10 = Object.entries(importances).slice(0, 10);
        const labels = top10.map(item => item[0].replace(/_/g, ' '));
        const values = top10.map(item => item[1]);

        featureChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Feature Weight Impact',
                    data: values,
                    backgroundColor: 'rgba(0, 242, 254, 0.6)',
                    borderColor: '#00f2fe',
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.08)' },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#f8fafc', font: { family: 'Outfit', size: 12 } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }




    // ================= 8. LOCAL STORAGE HISTORY & EXPORTS =================
    function saveToHistory(scanData) {
        let history = JSON.parse(localStorage.getItem('phishshield_history') || '[]');
        // Prepend new scan
        history.unshift(scanData);
        // Keep max 50 items
        if (history.length > 50) history = history.slice(0, 50);
        localStorage.setItem('phishshield_history', JSON.stringify(history));
    }

    function loadScanHistory() {
        const history = JSON.parse(localStorage.getItem('phishshield_history') || '[]');
        historyTableBody.innerHTML = '';

        if (history.length === 0) {
            historyTableBody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No scan history recorded yet. Perform a scan above!</td></tr>`;
            return;
        }

        history.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-size: 12px; color: var(--text-muted);">${item.timestamp}</td>
                <td style="font-family: var(--font-mono); font-size: 13px;">${item.url}</td>
                <td><span class="threat-badge ${item.badge_class}">${item.threat_level}</span></td>
                <td style="font-family: var(--font-mono); font-weight: 700;">${item.risk_score}%</td>
                <td>${item.rf_score}%</td>
                <td>${item.mlp_score}%</td>
                <td>
                    <button class="btn-secondary btn-inspect-item" data-url="${item.url}">
                        <i class="fa-solid fa-magnifying-glass"></i> Re-Scan
                    </button>
                </td>
            `;
            historyTableBody.appendChild(tr);
        });

        document.querySelectorAll('#history-table-body .btn-inspect-item').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetUrl = btn.getAttribute('data-url');
                document.getElementById('tab-scanner').click();
                urlInput.value = targetUrl;
                btnClear.style.display = 'inline-block';
                triggerScan(targetUrl);
            });
        });
    }

    function loadLiveLogs() {

        const terminal = document.getElementById('live-logs-terminal');
        const btnRefreshLogs = document.getElementById('btn-refresh-logs');
        if (!terminal) return;

        fetch('/api/logs')
            .then(res => res.json())
            .then(res => {
                if (res.status === 'success' && res.data && res.data.logs) {
                    terminal.innerHTML = res.data.logs.map(l => `<div>${l}</div>`).join('');
                    terminal.scrollTop = terminal.scrollHeight;
                }
            })
            .catch(err => {
                terminal.innerHTML = `<div>[ERROR] Failed to fetch system logs: ${err.message}</div>`;
            });
    }

    const btnRefreshLogs = document.getElementById('btn-refresh-logs');
    if (btnRefreshLogs) {
        btnRefreshLogs.addEventListener('click', () => {
            loadLiveLogs();
        });
    }

    btnClearHistory.addEventListener('click', () => {

        if (confirm('Are you sure you want to clear all scan history?')) {
            localStorage.removeItem('phishshield_history');
            loadScanHistory();
        }
    });

    btnExportCsv.addEventListener('click', () => {
        const history = JSON.parse(localStorage.getItem('phishshield_history') || '[]');
        if (history.length === 0) {
            alert('No history records available to export.');
            return;
        }

        let csvContent = 'data:text/csv;charset=utf-8,Timestamp,URL,Threat Level,Risk Score,RF Score,MLP Score\n';
        history.forEach(h => {
            csvContent += `"${h.timestamp}","${h.url}","${h.threat_level}",${h.risk_score},${h.rf_score},${h.mlp_score}\n`;
        });

        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', `phishshield_history_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    btnExportJson.addEventListener('click', () => {
        if (!lastScanResult) {
            alert('No active scan result to export.');
            return;
        }
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastScanResult, null, 2));
        const link = document.createElement('a');
        link.setAttribute('href', dataStr);
        link.setAttribute('download', `security_scan_${Date.now()}.json`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    if (btnPrintReport) {
        btnPrintReport.addEventListener('click', () => {
            if (!lastScanResult) {
                alert('No scan data available to generate report. Please scan a URL first.');
                return;
            }
            window.print();
        });
    }


    // ================= 7. EVENT HANDLERS & PRESETS =================


    // ================= 8. QR CODE QUISHING SCANNER LOGIC =================
    const qrDropzone = document.getElementById('qr-dropzone');
    const qrFileInput = document.getElementById('qr-file-input');
    const qrDropzoneContent = document.getElementById('qr-dropzone-content');
    const qrPreviewContainer = document.getElementById('qr-preview-container');
    const qrPreviewImg = document.getElementById('qr-preview-img');
    const qrDecodedStatus = document.getElementById('qr-decoded-status');
    const qrDecodedUrl = document.getElementById('qr-decoded-url');
    const btnQrScanNow = document.getElementById('btn-qr-scan-now');

    let decodedQrUrlTarget = '';

    if (qrDropzone && qrFileInput) {
        qrDropzone.addEventListener('click', (e) => {
            if (e.target.id !== 'btn-qr-scan-now' && !e.target.closest('#btn-qr-scan-now')) {
                qrFileInput.click();
            }
        });

        qrDropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            qrDropzone.style.borderColor = '#38bdf8';
            qrDropzone.style.background = 'rgba(56, 189, 248, 0.1)';
        });

        qrDropzone.addEventListener('dragleave', () => {
            qrDropzone.style.borderColor = 'rgba(255,255,255,0.15)';
            qrDropzone.style.background = 'rgba(0,0,0,0.2)';
        });

        qrDropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            qrDropzone.style.borderColor = 'rgba(255,255,255,0.15)';
            qrDropzone.style.background = 'rgba(0,0,0,0.2)';
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleQrFile(e.dataTransfer.files[0]);
            }
        });

        qrFileInput.addEventListener('change', () => {
            if (qrFileInput.files && qrFileInput.files[0]) {
                handleQrFile(qrFileInput.files[0]);
            }
        });
    }

    function handleQrFile(file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const imageSrc = e.target.result;
            if (qrPreviewImg) qrPreviewImg.src = imageSrc;
            if (qrDropzoneContent) qrDropzoneContent.style.display = 'none';
            if (qrPreviewContainer) qrPreviewContainer.style.display = 'flex';
            if (qrDecodedStatus) {
                qrDecodedStatus.textContent = 'Decoding QR payload...';
                qrDecodedStatus.style.color = '#38bdf8';
            }
            if (qrDecodedUrl) qrDecodedUrl.textContent = '';
            if (btnQrScanNow) btnQrScanNow.style.display = 'none';

            const img = new Image();
            img.src = imageSrc;
            img.onload = function() {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0, img.width, img.height);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

                let code = null;
                if (typeof jsQR !== 'undefined') {
                    code = jsQR(imageData.data, imageData.width, imageData.height);
                }

                if (code && code.data) {
                    decodedQrUrlTarget = code.data.trim();
                    if (qrDecodedStatus) {
                        qrDecodedStatus.textContent = '✓ QR Code Decoded Payload URL!';
                        qrDecodedStatus.style.color = '#34d399';
                    }
                    if (qrDecodedUrl) qrDecodedUrl.textContent = decodedQrUrlTarget;
                    if (btnQrScanNow) btnQrScanNow.style.display = 'inline-flex';
                    if (urlInput) urlInput.value = decodedQrUrlTarget;
                    triggerScan(decodedQrUrlTarget);
                } else {
                    scanQrOnBackend(file);
                }
            };
        };
        reader.readAsDataURL(file);
    }

    async function scanQrOnBackend(file) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/scan-qr', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            const payload = (data && data.data && (data.data.url || data.data.decoded_qr_url)) ? data.data : data;

            if (res.ok && (data.status === 'success' || data.success || payload.url || payload.decoded_qr_url)) {
                decodedQrUrlTarget = payload.decoded_qr_url || payload.url;
                if (qrDecodedStatus) {
                    qrDecodedStatus.textContent = '✓ QR Code Decoded (OpenCV Engine)!';
                    qrDecodedStatus.style.color = '#34d399';
                }
                if (qrDecodedUrl) qrDecodedUrl.textContent = decodedQrUrlTarget;
                if (btnQrScanNow) btnQrScanNow.style.display = 'inline-flex';
                if (urlInput) urlInput.value = decodedQrUrlTarget;
                
                lastScanResult = payload;
                renderResults(payload);
                saveToHistory(payload);
                updateAnalyticsBar();
            } else {
                if (qrDecodedStatus) {
                    qrDecodedStatus.textContent = '❌ ' + (data.error || 'Could not decode QR code in image.');
                    qrDecodedStatus.style.color = '#f87171';
                }
            }
        } catch (err) {
            if (qrDecodedStatus) {
                qrDecodedStatus.textContent = '❌ Failed to process QR image on server.';
                qrDecodedStatus.style.color = '#f87171';
            }
        }
    }

    if (btnQrScanNow) {
        btnQrScanNow.addEventListener('click', (e) => {
            e.stopPropagation();
            if (decodedQrUrlTarget) {
                if (urlInput) urlInput.value = decodedQrUrlTarget;
                triggerScan(decodedQrUrlTarget);
            }
        });
    }

    window.switchForensicsTab = function(tabName) {
        const subbtnXai = document.getElementById('subtab-btn-xai');
        const subbtnContent = document.getElementById('subtab-btn-content');
        const panelXai = document.getElementById('subpanel-xai');
        const panelContent = document.getElementById('subpanel-content');

        if (tabName === 'xai') {
            if (subbtnXai) subbtnXai.classList.add('active');
            if (subbtnContent) subbtnContent.classList.remove('active');
            if (panelXai) panelXai.style.display = 'block';
            if (panelContent) panelContent.style.display = 'none';
        } else {
            if (subbtnContent) subbtnContent.classList.add('active');
            if (subbtnXai) subbtnXai.classList.remove('active');
            if (panelContent) panelContent.style.display = 'block';
            if (panelXai) panelXai.style.display = 'none';
        }
    };

    window.runPresetScan = function(presetUrl) {
        if (!presetUrl) return;
        if (urlInput) {
            urlInput.value = presetUrl;
            if (btnClear) btnClear.style.display = 'block';
        }
        triggerScan(presetUrl);
    };

});





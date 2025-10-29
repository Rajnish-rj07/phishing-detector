document.addEventListener('DOMContentLoaded', function() {
    const statusEl = document.getElementById('status');
    const confidenceEl = document.getElementById('confidence');
    const spinnerEl = document.getElementById('loading-spinner');
    const currentUrlEl = document.getElementById('current-url');
    const phishingProbEl = document.getElementById('phishing-prob');
    const riskLevelEl = document.getElementById('risk-level');
    const lastCheckedEl = document.getElementById('last-checked');
    const threatDetailsEl = document.getElementById('threat-details');
    const threatDetailsContentEl = document.getElementById('threat-details-content');
    const certAnalysisEl = document.getElementById('cert-analysis');
    const certAnalysisContentEl = document.getElementById('cert-analysis-content');
    const externalApisEl = document.getElementById('external-apis');
    const externalApisContentEl = document.getElementById('external-apis-content');
    const modelExplanationEl = document.getElementById('model-explanation');
    const modelExplanationContentEl = document.getElementById('model-explanation-content');
    const recheckBtn = document.getElementById('recheck-btn');
    const reportBtn = document.getElementById('report-btn');
    const moreInfoBtn = document.getElementById('more-info-btn');
    const detailsBtn = document.getElementById('details-btn');
    const urlInput = document.getElementById('url-input');
    const checkBtn = document.getElementById('check-button');

    function getSeverityColor(severity) {
        switch (severity.toLowerCase()) {
            case 'high':
                return '#dc3545';
            case 'medium':
                return '#ffc107';
            case 'low':
                return '#28a745';
            default:
                return '#6c757d';
        }
    }

    function generateFeatureExplanation(features) {
        if (!features || typeof features !== 'object') {
            return '<p>No feature information available.</p>';
        }

        let html = '<div class="explanation-content">';
        html += '<p class="explanation-summary">Analysis based on URL characteristics:</p>';
        html += '<h4>Key Factors:</h4><ul class="feature-list">';

        const featureArray = [];

        if (features.url_length !== undefined) {
            featureArray.push({
                name: 'URL Length',
                value: features.url_length,
                importance: features.url_length > 75 ? 0.8 : features.url_length > 50 ? 0.5 : 0.2
            });
        }

        if (features.suspicious_tld !== undefined) {
            featureArray.push({
                name: 'Suspicious TLD',
                value: features.suspicious_tld ? 'Yes' : 'No',
                importance: features.suspicious_tld ? 0.9 : 0.1
            });
        }

        if (features.num_dots !== undefined) {
            featureArray.push({
                name: 'Number of Dots',
                value: features.num_dots,
                importance: features.num_dots > 3 ? 0.7 : 0.3
            });
        }

        if (features.has_ip !== undefined) {
            featureArray.push({
                name: 'Contains IP Address',
                value: features.has_ip ? 'Yes' : 'No',
                importance: features.has_ip ? 0.9 : 0.1
            });
        }

        if (features.has_https !== undefined) {
            featureArray.push({
                name: 'Uses HTTPS',
                value: features.has_https ? 'Yes' : 'No',
                importance: features.has_https ? 0.2 : 0.8
            });
        }

        if (features.suspicious_words !== undefined) {
            featureArray.push({
                name: 'Suspicious Words',
                value: features.suspicious_words ? 'Yes' : 'No',
                importance: features.suspicious_words ? 0.85 : 0.15
            });
        }

        if (features.domain_age !== undefined) {
            const age = features.domain_age;
            featureArray.push({
                name: 'Domain Age',
                value: age < 30 ? 'New (< 30 days)' : age < 180 ? 'Recent (< 6 months)' : 'Established',
                importance: age < 30 ? 0.9 : age < 180 ? 0.6 : 0.2
            });
        }

        featureArray.sort((a, b) => b.importance - a.importance);

        featureArray.slice(0, 5).forEach(feature => {
            const importanceClass = feature.importance > 0.7 ? 'high' : feature.importance > 0.4 ? 'medium' : 'low';
            html += `<li class="feature-item ${importanceClass}">
        <span class="feature-name">${feature.name}</span>: 
        <span class="feature-value">${feature.value}</span>
        <div class="importance-bar" style="width: ${feature.importance * 100}%; background-color: ${
          feature.importance > 0.7 ? '#dc3545' : feature.importance > 0.4 ? '#ffc107' : '#28a745'
        };"></div>
      </li>`;
        });

        html += '</ul></div>';
        return html;
    }

    function updateUI(response) {
        console.log("Updating UI with response:", response);

        spinnerEl.style.display = 'none';
        threatDetailsEl.style.display = 'none';
        certAnalysisEl.style.display = 'none';
        externalApisEl.style.display = 'none';
        modelExplanationEl.style.display = 'none';
        detailsBtn.textContent = '🔍 View Details';

        const isOfflineMode = response.isOfflineAnalysis === true || response.source === 'offline';
        const modeIndicator = document.getElementById('mode-indicator') || createModeIndicator();

        if (isOfflineMode) {
            modeIndicator.textContent = '🔌 Offline Mode - Limited Analysis';
            modeIndicator.style.backgroundColor = '#6c757d';
            modeIndicator.style.display = 'block';
            modeIndicator.title = 'API server is not available. Using local analysis with limited features.';
        } else {
            modeIndicator.style.display = 'none';
        }

        if (response.error) {
            statusEl.textContent = 'Error';
            statusEl.className = 'status-warning';
            confidenceEl.textContent = 'Unable to check: ' + response.error;
            phishingProbEl.textContent = 'N/A';
            riskLevelEl.textContent = 'UNKNOWN';
            return;
        }

        if (response.isPhishing) {
            statusEl.textContent = 'Dangerous';
            statusEl.className = 'status-danger';
        } else {
            statusEl.textContent = 'Safe';
            statusEl.className = 'status-safe';
        }

        const confidence = response.confidence || 0;
        confidenceEl.textContent = `${confidence}% confidence`;

        const phishingProb = response.probabilityPhishing || Math.round(confidence);
        phishingProbEl.textContent = `${phishingProb}%`;

        riskLevelEl.textContent = response.riskLevel || 'UNKNOWN';

        if (response.threatDetails && response.threatDetails.length > 0) {
            threatDetailsContentEl.innerHTML = '';
            response.threatDetails.forEach(threat => {
                const threatElement = document.createElement('div');
                threatElement.style.marginBottom = '8px';
                threatElement.style.padding = '4px';
                threatElement.style.borderLeft = '3px solid ' + getSeverityColor(threat.severity);
                threatElement.style.paddingLeft = '8px';
                threatElement.innerHTML = `
          <strong>${threat.type}</strong>: ${threat.description}
          <span style="display: inline-block; margin-left: 5px; padding: 2px 5px; border-radius: 3px; font-size: 10px; background: ${getSeverityColor(threat.severity)}; color: white;">${threat.severity}</span>
        `;
                threatDetailsContentEl.appendChild(threatElement);
            });
            threatDetailsEl.style.display = 'block';
        } else if (response.api_results && response.api_results.reputation_results) {
            threatDetailsContentEl.innerHTML = '';
            const repResults = response.api_results.reputation_results;
            const threats = [];

            if (repResults.virustotal && repResults.virustotal.malicious > 0) {
                threats.push({
                    type: 'VirusTotal',
                    description: `Flagged by ${repResults.virustotal.malicious} security vendors as malicious.`,
                    severity: 'HIGH'
                });
            }

            if (repResults.google_safe_browsing && repResults.google_safe_browsing.matches) {
                threats.push({
                    type: 'Google Safe Browsing',
                    description: 'This URL has been flagged as unsafe by Google Safe Browsing.',
                    severity: 'HIGH'
                });
            }

            if (repResults.urlscan && repResults.urlscan.malicious) {
                threats.push({
                    type: 'URLScan.io',
                    description: 'This URL has been identified as potentially malicious by URLScan.io.',
                    severity: 'MEDIUM'
                });
            }

            if (repResults.abuseipdb && repResults.abuseipdb.abuseConfidenceScore > 50) {
                threats.push({
                    type: 'AbuseIPDB',
                    description: `The IP address has an abuse confidence score of ${repResults.abuseipdb.abuseConfidenceScore}%.`,
                    severity: repResults.abuseipdb.abuseConfidenceScore > 80 ? 'HIGH' : 'MEDIUM'
                });
            }

            if (threats.length === 0 && response.probabilityPhishing > 70) {
                threats.push({
                    type: 'ML Detection',
                    description: 'Our machine learning model detected suspicious patterns in this URL.',
                    severity: response.probabilityPhishing > 90 ? 'HIGH' : 'MEDIUM'
                });
            }

            if (threats.length > 0) {
                threats.forEach(threat => {
                    const threatElement = document.createElement('div');
                    threatElement.style.marginBottom = '8px';
                    threatElement.style.padding = '4px';
                    threatElement.style.borderLeft = '3px solid ' + getSeverityColor(threat.severity);
                    threatElement.style.paddingLeft = '8px';
                    threatElement.innerHTML = `
            <strong>${threat.type}</strong>: ${threat.description}
            <span style="display: inline-block; margin-left: 5px; padding: 2px 5px; border-radius: 3px; font-size: 10px; background: ${getSeverityColor(threat.severity)}; color: white;">${threat.severity}</span>
          `;
                    threatDetailsContentEl.appendChild(threatElement);
                });
                threatDetailsEl.style.display = 'block';
            }
        }

        if (response.certificateAnalysis) {
            const cert = response.certificateAnalysis;
            let certStatus = 'Valid';
            let certColor = '#28a745';
            let securityLevel = cert.security_level || 'MEDIUM';
            let securityScore = cert.security_score || 0;

            if (!cert.valid || cert.is_expired || cert.is_self_signed) {
                certStatus = 'Invalid';
                certColor = '#dc3545';
            } else if (cert.is_short_lived) {
                certStatus = 'Suspicious';
                certColor = '#ffc107';
            }

            if (securityLevel === 'LOW' || securityScore < 50) {
                securityColor = '#dc3545';
            } else if (securityLevel === 'MEDIUM' || securityScore < 80) {
                securityColor = '#ffc107';
            }

            certAnalysisContentEl.innerHTML = `
        <div style="margin-bottom: 5px;">
          <strong>Status:</strong> <span style="color: ${certColor}">${certStatus}</span>
        </div>
        <div style="margin-bottom: 5px;">
          <strong>Security Score:</strong> <span style="color: ${securityColor}">${securityScore}/100 (${securityLevel})</span>
        </div>
        <div style="margin-bottom: 5px;">
          <strong>Issuer:</strong> ${cert.issuer || 'Unknown'}
        </div>
        <div style="margin-bottom: 5px;">
          <strong>Valid Until:</strong> ${cert.valid_until || 'Unknown'}
        </div>
        <div style="margin-bottom: 5px;">
          <strong>Remaining Days:</strong> ${cert.remaining_days || 'Unknown'}
        </div>
      `;

            if (cert.advanced_security) {
                const advanced = cert.advanced_security;
                certAnalysisContentEl.innerHTML += `
          <div style="margin-top: 10px; margin-bottom: 5px;">
            <strong>Advanced Security Features:</strong>
          </div>
          <div style="margin-bottom: 5px;">
            <strong>Extended Validation:</strong> ${advanced.extended_validation ?
                    '<span style="color: #28a745">Yes</span>' :
                    '<span style="color: #dc3545">No</span>'}
          </div>
          <div style="margin-bottom: 5px;">
            <strong>TLS Version:</strong> ${advanced.tls_version || 'Unknown'}
          </div>
          <div style="margin-bottom: 5px;">
            <strong>Certificate Transparency:</strong> ${advanced.has_sct ?
                    '<span style="color: #28a745">Yes</span>' :
                    '<span style="color: #dc3545">No</span>'}
          </div>
          <div style="margin-bottom: 5px;">
            <strong>OCSP Stapling:</strong> ${advanced.ocsp_stapling ?
                    '<span style="color: #28a745">Yes</span>' :
                    '<span style="color: #dc3545">No</span>'}
          </div>
        `;
            }
            certAnalysisEl.style.display = 'block';
        }

        if (response.externalApiResults && Object.keys(response.externalApiResults).length > 0) {
            const apis = response.externalApiResults;
            externalApisContentEl.innerHTML = '';

            if (apis.virustotal) {
                const vtElement = document.createElement('div');
                vtElement.style.marginBottom = '8px';
                vtElement.innerHTML = `
          <strong>VirusTotal:</strong> ${apis.virustotal.is_malicious ?
                    `<span style="color: #dc3545">Malicious (${apis.virustotal.malicious} detections)</span>` :
                    '<span style="color: #28a745">Clean</span>'}
        `;
                externalApisContentEl.appendChild(vtElement);
            }

            if (apis.phishtank) {
                const ptElement = document.createElement('div');
                ptElement.style.marginBottom = '8px';
                ptElement.innerHTML = `
          <strong>PhishTank:</strong> ${apis.phishtank.is_malicious ?
                    `<span style="color: #dc3545">Verified Phishing Site</span>` :
                    '<span style="color: #28a745">Not in Database</span>'}
        `;
                externalApisContentEl.appendChild(ptElement);
            }

            if (apis.google_safebrowsing) {
                const gsbElement = document.createElement('div');
                gsbElement.style.marginBottom = '8px';
                gsbElement.innerHTML = `
          <strong>Google Safe Browsing:</strong> ${apis.google_safebrowsing.is_malicious ?
                    `<span style="color: #dc3545">Flagged as ${apis.google_safebrowsing.threat_type || 'malicious'}</span>` :
                    '<span style="color: #28a745">Clean</span>'}
        `;
                externalApisContentEl.appendChild(gsbElement);
            }

            if (apis.urlscan) {
                const urlscanElement = document.createElement('div');
                urlscanElement.style.marginBottom = '8px';
                urlscanElement.innerHTML = `
          <strong>URLScan.io:</strong> ${apis.urlscan.is_malicious ?
                    `<span style="color: #dc3545">Malicious (${apis.urlscan.categories?.join(', ') || 'unknown'})</span>` :
                    '<span style="color: #28a745">Clean</span>'}
        `;
                externalApisContentEl.appendChild(urlscanElement);
            }

            if (apis.openphish) {
                const openphishElement = document.createElement('div');
                openphishElement.style.marginBottom = '8px';
                openphishElement.innerHTML = `
          <strong>OpenPhish:</strong> ${apis.openphish.is_malicious ?
                    `<span style="color: #dc3545">Listed as phishing site</span>` :
                    '<span style="color: #28a745">Not listed</span>'}
        `;
                externalApisContentEl.appendChild(openphishElement);
            }

            if (apis.abuseipdb) {
                const abuseipdbElement = document.createElement('div');
                abuseipdbElement.style.marginBottom = '8px';
                abuseipdbElement.innerHTML = `
          <strong>AbuseIPDB:</strong> ${apis.abuseipdb.is_malicious ?
                    `<span style="color: #dc3545">Malicious (Score: ${apis.abuseipdb.confidence_score}%)</span>` :
                    '<span style="color: #28a745">No abuse reports</span>'}
        `;
                externalApisContentEl.appendChild(abuseipdbElement);
            }

            if (apis.emailrep) {
                const emailrepElement = document.createElement('div');
                emailrepElement.style.marginBottom = '8px';
                emailrepElement.innerHTML = `
          <strong>EmailRep:</strong> ${apis.emailrep.is_malicious ?
                    `<span style="color: #dc3545">Suspicious (${apis.emailrep.reputation || 'unknown reputation'})</span>` :
                    '<span style="color: #28a745">Good reputation</span>'}
        `;
                externalApisContentEl.appendChild(emailrepElement);
            }
            externalApisEl.style.display = 'block';
        }

        if (response.modelExplanation && response.modelExplanation.length > 0) {
            modelExplanationContentEl.innerHTML = '';
            response.modelExplanation.forEach(item => {
                const explanationElement = document.createElement('div');
                explanationElement.style.marginBottom = '4px';
                explanationElement.innerHTML = `<strong>${item.feature}</strong>: ${item.weight.toFixed(4)}`;
                modelExplanationContentEl.appendChild(explanationElement);
            });
            modelExplanationEl.style.display = 'block';
        } else if (response.features || (response.api_results && response.api_results.features)) {
            const features = response.features || (response.api_results ? response.api_results.features : null) || {};
            modelExplanationContentEl.innerHTML = generateFeatureExplanation(features);
            modelExplanationEl.style.display = 'block';
        }
    }

    function checkUrl(url, tabId) {
        spinnerEl.style.display = 'block';

        if (url.startsWith('chrome://') ||
            url.startsWith('chrome-extension://') ||
            url.startsWith('about:') ||
            url.startsWith('edge://') ||
            url.startsWith('brave://') ||
            url.startsWith('opera://')) {
            updateUI({
                isPhishing: false,
                confidence: 100,
                probabilityPhishing: 0,
                riskLevel: 'SAFE',
                source: 'internal',
                isOfflineAnalysis: true
            });
            return;
        }

        chrome.runtime.sendMessage({
            action: 'checkUrl',
            url: url,
            tabId: tabId
        }, function(response) {
            if (chrome.runtime.lastError) {
                console.error('Error sending message:', chrome.runtime.lastError);
                updateUI({
                    error: 'Communication error with background script'
                });
                return;
            }

            if (!response) {
                updateUI({
                    error: 'No response from background script'
                });
                return;
            }

            updateUI(response);
        });
    }

    recheckBtn.addEventListener('click', function() {
        chrome.tabs.query({
            active: true,
            currentWindow: true
        }, function(tabs) {
            if (tabs.length === 0) {
                updateUI({
                    error: 'No active tab found'
                });
                return;
            }
            const currentUrl = tabs[0].url;
            const tabId = tabs[0].id;
            checkUrl(currentUrl, tabId);
        });
    });

    detailsBtn.addEventListener('click', function() {
        const sections = [threatDetailsEl, certAnalysisEl, externalApisEl, modelExplanationEl];
        const isVisible = sections.some(el => el.style.display === 'block');

        if (isVisible) {
            sections.forEach(el => el.style.display = 'none');
            this.textContent = '🔍 View Details';
        } else {
            sections.forEach(el => {
                if (el.innerHTML.trim() !== '') {
                    el.style.display = 'block';
                }
            });
            this.textContent = '🔍 Hide Details';
        }
    });

    checkBtn.addEventListener('click', function() {
        const url = urlInput.value.trim();
        if (url) {
            checkUrl(url, null);
        }
    });

    chrome.tabs.query({
        active: true,
        currentWindow: true
    }, function(tabs) {
        if (tabs.length === 0) {
            updateUI({
                error: 'No active tab found'
            });
            return;
        }
        const currentUrl = tabs[0].url;
        const tabId = tabs[0].id;
        currentUrlEl.textContent = currentUrl;
        checkUrl(currentUrl, tabId);
    });
});


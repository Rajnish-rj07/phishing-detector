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

    function createModeIndicator() {
        const indicator = document.createElement('div');
        indicator.id = 'mode-indicator';
        indicator.style.padding = '5px 10px';
        indicator.style.borderRadius = '4px';
        indicator.style.color = 'white';
        indicator.style.fontWeight = 'bold';
        indicator.style.fontSize = '12px';
        indicator.style.marginBottom = '10px';
        indicator.style.textAlign = 'center';
        indicator.style.display = 'none';
        document.querySelector('.risk-analysis').insertAdjacentElement('beforebegin', indicator);
        return indicator;
    }

    function updateUI(response) {
        console.log("Updating UI with response:", response);

        // Set default values for risk analysis
        phishingProbEl.textContent = '-';
        riskLevelEl.textContent = '-';
        lastCheckedEl.textContent = '-';
        
        spinnerEl.style.display = 'none';
        threatDetailsEl.style.display = 'none';
        certAnalysisEl.style.display = 'none';
        externalApisEl.style.display = 'none';
        modelExplanationEl.style.display = 'none';
        detailsBtn.textContent = '🔍 View Details';
        
        // Handle model not trained error
        if (response.message && response.message.includes("Model is not yet trained")) {
            statusEl.textContent = 'Warning';
            statusEl.className = 'status-warning';
            confidenceEl.textContent = 'Model is not yet trained. Using default values.';
            // Use the confidence values from the response even if model is not trained
            if (response.confidence_percent) {
                phishingProbEl.textContent = response.confidence_percent + '%';
            } else if (response.probabilityPhishing !== undefined) {
                phishingProbEl.textContent = response.probabilityPhishing + '%';
            }
            
            if (response.riskLevel) {
                riskLevelEl.textContent = response.riskLevel;
            } else {
                riskLevelEl.textContent = 'LOW';
            }
            
            lastCheckedEl.textContent = new Date().toLocaleString();
            return;
        }

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

        const phishingProb = Math.round(confidence);
        phishingProbEl.textContent = `${phishingProb}%`;

        riskLevelEl.textContent = response.riskLevel || 'LOW';
        lastCheckedEl.textContent = new Date().toLocaleString();

        // Updated threat details parsing
        if (response.threatDetails && response.threatDetails.length > 0) {
            threatDetailsContentEl.innerHTML = response.threatDetails.map(threat => `<p>${threat}</p>`).join('');
            threatDetailsEl.style.display = 'block';
        }

        // Display SSL certificate information
        if (response.externalApiResults && response.externalApiResults.ssl_certificate) {
            const cert = response.externalApiResults.ssl_certificate;
            let content = '';
            if (cert.error) {
                content = `<p class="error">SSL Certificate Error: ${cert.error}</p>`;
            } else {
                content = `
                    <p><strong>Issuer:</strong> ${cert.issuer}</p>
                    <p><strong>Subject:</strong> ${cert.subject}</p>
                    <p><strong>Valid From:</strong> ${new Date(cert.valid_from).toLocaleString()}</p>
                    <p><strong>Valid To:</strong> ${new Date(cert.valid_to).toLocaleString()}</p>
                    <p><strong>Expired:</strong> ${cert.is_expired ? 'Yes' : 'No'}</p>
                `;
            }
            certAnalysisContentEl.innerHTML = content;
            certAnalysisEl.style.display = 'block';
        }

        // Display external API results
        if (response.externalApiResults) {
            const apis = response.externalApiResults;
            let content = '';
            if (apis.virustotal && apis.virustotal.malicious) {
                content += `<p><strong>VirusTotal:</strong> ${apis.virustotal.malicious} vendors flagged as malicious.</p>`;
            }
            if (apis.google_safebrowsing && apis.google_safebrowsing.matches) {
                content += `<p><strong>Google Safe Browsing:</strong> Threats detected.</p>`;
            }
            if (apis.urlscan && apis.urlscan.malicious) {
                content += `<p><strong>URLScan:</strong> Malicious indicators found.</p>`;
            }
            if (apis.abuseipdb && apis.abuseipdb.abuseConfidenceScore) {
                content += `<p><strong>AbuseIPDB:</strong> Abuse confidence score of ${apis.abuseipdb.abuseConfidenceScore}%.</p>`;
            }
            if (content) {
                externalApisContentEl.innerHTML = content;
                externalApisEl.style.display = 'block';
            }
        }

        // Display model explanation
        if (response.model_prediction && response.model_prediction.message) {
            modelExplanationContentEl.textContent = response.model_prediction.message;
            modelExplanationEl.style.display = 'block';
        }

        detailsBtn.addEventListener('click', () => {
            const isHidden = threatDetailsEl.style.display === 'none';
            threatDetailsEl.style.display = isHidden ? 'block' : 'none';
            certAnalysisEl.style.display = isHidden ? 'block' : 'none';
            externalApisEl.style.display = isHidden ? 'block' : 'none';
            modelExplanationEl.style.display = isHidden ? 'block' : 'none';
            detailsBtn.textContent = isHidden ? '🔼 Hide Details' : '🔍 View Details';
        });
    }

    function checkUrl(url) {
        spinnerEl.style.display = 'block';
        statusEl.textContent = 'Checking...';
        confidenceEl.textContent = 'Analyzing...';

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

        // Set a timeout to show an error message if the API doesn't respond
        const timeoutId = setTimeout(() => {
            console.log("API request timed out");
            updateUI({
                error: "API request timed out. Please try again.",
                isPhishing: false,
                confidence: 0,
                riskLevel: 'UNKNOWN',
                source: 'error'
            });
        }, 15000); // 15 second timeout for API response

        chrome.runtime.sendMessage({
            action: 'checkUrl',
            url: url,
            tabId: tabId
        }, function(response) {
            clearTimeout(timeoutId); // Clear the timeout if we got a response
            
            if (chrome.runtime.lastError) {
                console.error('Error sending message:', chrome.runtime.lastError);
                updateUI({
                    error: 'Communication error with background script: ' + chrome.runtime.lastError.message
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
        // Show spinner while checking
        spinnerEl.style.display = 'block';
        statusEl.textContent = 'Checking...';
        statusEl.className = 'status-checking';
        
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
            
            // Force a fresh check by bypassing cache
            chrome.runtime.sendMessage({
                action: 'checkUrl',
                url: currentUrl,
                tabId: tabId,
                forceRefresh: true
            }, function(response) {
                if (chrome.runtime.lastError) {
                    console.error('Error sending message:', chrome.runtime.lastError);
                    updateUI({
                        error: 'Communication error with background script: ' + chrome.runtime.lastError.message
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
        });
    });

    // Add event listener for More Info button
    moreInfoBtn.addEventListener('click', function() {
        // Open the history page
        chrome.tabs.create({
            url: chrome.runtime.getURL('history.html')
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
                if (el.querySelector('.explanation-content, div') || (el.innerHTML && el.innerHTML.trim() !== '')) {
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


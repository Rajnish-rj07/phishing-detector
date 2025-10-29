// Helper function to get color based on severity level
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

// Function to update the UI with response data
function updateUI(response) {
  console.log("Updating UI with response:", response);
  // Reset advanced sections
  document.getElementById('threat-details').style.display = 'none';
  document.getElementById('cert-analysis').style.display = 'none';
  document.getElementById('external-apis').style.display = 'none';
  document.getElementById('model-explanation').style.display = 'none'; // Hide explanation section
  document.getElementById('details-btn').textContent = '🔍 View Details';
  document.getElementById('loading-spinner').style.display = 'none'; // Hide spinner when UI updates
  
  // Check if this is an offline analysis
  const isOfflineMode = response.isOfflineAnalysis === true || response.source === 'offline';
  
  // Add offline mode indicator if needed
  const modeIndicator = document.getElementById('mode-indicator') || createModeIndicator();
  if (isOfflineMode) {
    modeIndicator.textContent = '🔌 Offline Mode - Limited Analysis';
    modeIndicator.style.backgroundColor = '#6c757d';
    modeIndicator.style.display = 'block';
    // Add tooltip for offline mode
    modeIndicator.title = 'API server is not available. Using local analysis with limited features.';
  } else {
    modeIndicator.style.display = 'none';
  }
  
  if (response.error) {
    // Show error state
    document.getElementById('status').textContent = 'Error';
    document.getElementById('status').className = 'status-warning';
    document.getElementById('confidence').textContent = 'Unable to check: ' + response.error;
    document.getElementById('phishing-prob').textContent = 'N/A';
    document.getElementById('risk-level').textContent = 'UNKNOWN';
    return;
  }
  
  // Helper function to create mode indicator
  function createModeIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'mode-indicator';
    indicator.style.padding = '4px 8px';
    indicator.style.borderRadius = '4px';
    indicator.style.color = 'white';
    indicator.style.fontSize = '12px';
    indicator.style.fontWeight = 'bold';
    indicator.style.marginBottom = '10px';
    indicator.style.textAlign = 'center';
    
    // Insert at the top of the content
    const content = document.querySelector('.content');
    if (content) {
      // If content exists, insert as first child or append if no children
      if (content.firstChild) {
        content.insertBefore(indicator, content.firstChild);
      } else {
        content.appendChild(indicator);
      }
    } else {
      // If content container doesn't exist, add indicator to body
      document.body.appendChild(indicator);
    }
    
    return indicator;
  }
  
  // Show results
  if (response.isPhishing) {
    document.getElementById('status').textContent = 'Dangerous';
    document.getElementById('status').className = 'status-danger';
  } else {
    document.getElementById('status').textContent = 'Safe'; 
    document.getElementById('status').className = 'status-safe';
  }
    
  // Ensure confidence is a number and not undefined
  const confidence = response.confidence || 0;
  document.getElementById('confidence').textContent = `${confidence}% confidence`;
  
  // Ensure probability is a number and not undefined
  const phishingProb = response.probabilityPhishing || Math.round(confidence);
  document.getElementById('phishing-prob').textContent = `${phishingProb}%`;
  
  document.getElementById('risk-level').textContent = response.riskLevel || 'UNKNOWN';
    
  // Update threat details if available
  if (response.threatDetails && response.threatDetails.length > 0) {
    const threatDetailsContent = document.getElementById('threat-details-content');
    threatDetailsContent.innerHTML = '';
      
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
        
      threatDetailsContent.appendChild(threatElement);
    });
    document.getElementById('threat-details').style.display = 'block'; // Show section if content exists
  } else if (response.api_results && response.api_results.reputation_results) {
    // Extract threat details from reputation_results if available
    const threatDetailsContent = document.getElementById('threat-details-content');
    threatDetailsContent.innerHTML = '';
    const repResults = response.api_results.reputation_results;
    const threats = [];
    
    // Create threat items from reputation results
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
    
    // Add generic threat if phishing probability is high but no specific threats found
    if (threats.length === 0 && response.probabilityPhishing > 70) {
      threats.push({
        type: 'ML Detection',
        description: 'Our machine learning model detected suspicious patterns in this URL.',
        severity: response.probabilityPhishing > 90 ? 'HIGH' : 'MEDIUM'
      });
    }
    
    // Add threats to the display
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
          
        threatDetailsContent.appendChild(threatElement);
      });
      document.getElementById('threat-details').style.display = 'block';
    } else {
      document.getElementById('threat-details').style.display = 'none';
    }
  } else {
    document.getElementById('threat-details').style.display = 'none'; // Hide section if no content
  }
    
  // Update certificate analysis if available
  if (response.certificateAnalysis) {
    const cert = response.certificateAnalysis;
    const certContent = document.getElementById('cert-analysis-content');
      
    let certStatus = 'Valid';
    let certColor = '#28a745';
    let securityLevel = cert.security_level || 'MEDIUM';
    let securityScore = cert.security_score || 0;
    let securityColor = '#28a745';
    
    console.log('Certificate data:', cert); // Debug log
      
    if (!cert.valid || cert.is_expired || cert.is_self_signed) {
      certStatus = 'Invalid';
      certColor = '#dc3545';
    } else if (cert.is_short_lived) {
      certStatus = 'Suspicious';
      certColor = '#ffc107';
    }
    
    // Always show certificate section even with minimal data
    document.getElementById('cert-analysis').style.display = 'block';
    
    // Set security level color
    if (securityLevel === 'LOW' || securityScore < 50) {
      securityColor = '#dc3545';
    } else if (securityLevel === 'MEDIUM' || securityScore < 80) {
      securityColor = '#ffc107';
    }
      
    certContent.innerHTML = `
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
    
    // Add advanced security features if available
    if (cert.advanced_security) {
      const advanced = cert.advanced_security;
      
      certContent.innerHTML += `
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
    document.getElementById('cert-analysis').style.display = 'block'; // Show section if content exists
  } else {
    document.getElementById('cert-analysis').style.display = 'none'; // Hide section if no content
  }
    
  // Update external API results if available
  if (response.externalApiResults && Object.keys(response.externalApiResults).length > 0) {
    const apis = response.externalApiResults;
    const apisContent = document.getElementById('external-apis-content');
    apisContent.innerHTML = '';
    
    console.log('External API results:', apis); // Debug log
      
    // VirusTotal
    if (apis.virustotal) {
      const vtElement = document.createElement('div');
      vtElement.style.marginBottom = '8px';
      vtElement.innerHTML = `
        <strong>VirusTotal:</strong> ${apis.virustotal.is_malicious ? 
          `<span style="color: #dc3545">Malicious (${apis.virustotal.malicious} detections)</span>` : 
          '<span style="color: #28a745">Clean</span>'}
      `;
      apisContent.appendChild(vtElement);
    }
    
    // Always show external APIs section even with minimal data
    document.getElementById('external-apis').style.display = 'block';
    
    // PhishTank
    if (apis.phishtank) {
      const ptElement = document.createElement('div');
      ptElement.style.marginBottom = '8px';
      ptElement.innerHTML = `
        <strong>PhishTank:</strong> ${apis.phishtank.is_malicious ? 
          `<span style="color: #dc3545">Verified Phishing Site</span>` : 
          '<span style="color: #28a745">Not in Database</span>'}
      `;
      apisContent.appendChild(ptElement);
    }
      
    // Google Safe Browsing
    if (apis.google_safebrowsing) {
      const gsbElement = document.createElement('div');
      gsbElement.style.marginBottom = '8px';
      gsbElement.innerHTML = `
        <strong>Google Safe Browsing:</strong> ${apis.google_safebrowsing.is_malicious ? 
          `<span style="color: #dc3545">Flagged as ${apis.google_safebrowsing.threat_type || 'malicious'}</span>` : 
          '<span style="color: #28a745">Clean</span>'}
      `;
      apisContent.appendChild(gsbElement);
    }
      
    // URLScan
    if (apis.urlscan) {
      const urlscanElement = document.createElement('div');
      urlscanElement.style.marginBottom = '8px';
      urlscanElement.innerHTML = `
        <strong>URLScan.io:</strong> ${apis.urlscan.is_malicious ? 
          `<span style="color: #dc3545">Malicious (${apis.urlscan.categories?.join(', ') || 'unknown'})</span>` : 
          '<span style="color: #28a745">Clean</span>'}
      `;
      apisContent.appendChild(urlscanElement);
    }
    
    // OpenPhish
    if (apis.openphish) {
      const openphishElement = document.createElement('div');
      openphishElement.style.marginBottom = '8px';
      openphishElement.innerHTML = `
        <strong>OpenPhish:</strong> ${apis.openphish.is_malicious ? 
          `<span style="color: #dc3545">Listed as phishing site</span>` : 
          '<span style="color: #28a745">Not listed</span>'}
      `;
      apisContent.appendChild(openphishElement);
    }
    
    // AbuseIPDB
    if (apis.abuseipdb) {
      const abuseipdbElement = document.createElement('div');
      abuseipdbElement.style.marginBottom = '8px';
      abuseipdbElement.innerHTML = `
        <strong>AbuseIPDB:</strong> ${apis.abuseipdb.is_malicious ? 
          `<span style="color: #dc3545">Malicious (Score: ${apis.abuseipdb.confidence_score}%)</span>` : 
          '<span style="color: #28a745">No abuse reports</span>'}
      `;
      apisContent.appendChild(abuseipdbElement);
    }
    
    // EmailRep
    if (apis.emailrep) {
      const emailrepElement = document.createElement('div');
      emailrepElement.style.marginBottom = '8px';
      emailrepElement.innerHTML = `
        <strong>EmailRep:</strong> ${apis.emailrep.is_malicious ? 
          `<span style="color: #dc3545">Suspicious (${apis.emailrep.reputation || 'unknown reputation'})</span>` : 
          '<span style="color: #28a745">Good reputation</span>'}
      `;
      apisContent.appendChild(emailrepElement);
    }
    document.getElementById('external-apis').style.display = 'block'; // Show section if content exists
  } else {
    document.getElementById('external-apis').style.display = 'none'; // Hide section if no content
  }

  // Update model explanation if available
  if (response.modelExplanation && response.modelExplanation.length > 0) {
    const explanationContent = document.getElementById('model-explanation-content');
    explanationContent.innerHTML = '';

    response.modelExplanation.forEach(item => {
      const explanationElement = document.createElement('div');
      explanationElement.style.marginBottom = '4px';
      explanationElement.innerHTML = `<strong>${item.feature}</strong>: ${item.weight.toFixed(4)}`;
      explanationContent.appendChild(explanationElement);
    });
    document.getElementById('model-explanation').style.display = 'block'; // Show section if content exists
  } else if (response.features || (response.api_results && response.api_results.features)) {
    // Use features from response or api_results if modelExplanation is not available
    const features = response.features || (response.api_results ? response.api_results.features : null) || {};
    const explanationContent = document.getElementById('model-explanation-content');
    explanationContent.innerHTML = generateFeatureExplanation(features);
    document.getElementById('model-explanation').style.display = 'block';
  } else {
    document.getElementById('model-explanation').style.display = 'none'; // Hide section if no content
  }
  
  // Generate explanation from features when model explanation is not available
  function generateFeatureExplanation(features) {
    if (!features || typeof features !== 'object') {
      return '<p>No feature information available.</p>';
    }
    
    let html = '<div class="explanation-content">';
    html += '<p class="explanation-summary">Analysis based on URL characteristics:</p>';
    html += '<h4>Key Factors:</h4><ul class="feature-list">';
    
    // Convert features object to array of {name, value, importance} objects
    const featureArray = [];
    
    // Add URL length
    if (features.url_length !== undefined) {
      featureArray.push({
        name: 'URL Length',
        value: features.url_length,
        importance: features.url_length > 75 ? 0.8 : features.url_length > 50 ? 0.5 : 0.2
      });
    }
    
    // Add suspicious TLD
    if (features.suspicious_tld !== undefined) {
      featureArray.push({
        name: 'Suspicious TLD',
        value: features.suspicious_tld ? 'Yes' : 'No',
        importance: features.suspicious_tld ? 0.9 : 0.1
      });
    }
    
    // Add number of dots
    if (features.num_dots !== undefined) {
      featureArray.push({
        name: 'Number of Dots',
        value: features.num_dots,
        importance: features.num_dots > 3 ? 0.7 : 0.3
      });
    }
    
    // Add has IP
    if (features.has_ip !== undefined) {
      featureArray.push({
        name: 'Contains IP Address',
        value: features.has_ip ? 'Yes' : 'No',
        importance: features.has_ip ? 0.9 : 0.1
      });
    }
    
    // Add has HTTPS
    if (features.has_https !== undefined) {
      featureArray.push({
        name: 'Uses HTTPS',
        value: features.has_https ? 'Yes' : 'No',
        importance: features.has_https ? 0.2 : 0.8
      });
    }
    
    // Add suspicious words
    if (features.suspicious_words !== undefined) {
      featureArray.push({
        name: 'Suspicious Words',
        value: features.suspicious_words ? 'Yes' : 'No',
        importance: features.suspicious_words ? 0.85 : 0.15
      });
    }
    
    // Add domain age if available
    if (features.domain_age !== undefined) {
      const age = features.domain_age;
      featureArray.push({
        name: 'Domain Age',
        value: age < 30 ? 'New (< 30 days)' : age < 180 ? 'Recent (< 6 months)' : 'Established',
        importance: age < 30 ? 0.9 : age < 180 ? 0.6 : 0.2
      });
    }
    
    // Sort by importance (descending)
    featureArray.sort((a, b) => b.importance - a.importance);
    
    // Add top 5 features to HTML
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
}

// Toggle details section
document.getElementById('details-btn').addEventListener('click', function() {
  const detailsSection = document.getElementById('details-section');
  const isVisible = detailsSection.style.display === 'block';
  
  if (isVisible) {
    detailsSection.style.display = 'none';
    this.textContent = '🔍 View Details';
  } else {
    detailsSection.style.display = 'block';
    this.textContent = '🔍 Hide Details';
  }
});

// Function to request URL check from background script
function checkCurrentUrl() {
  // Show loading spinner
  document.getElementById('loading-spinner').style.display = 'block';
  
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs.length === 0) {
      updateUI({error: 'No active tab found'});
      return;
    }
    
    const currentUrl = tabs[0].url;
    const tabId = tabs[0].id;
    
    // Skip checking for browser internal pages
    if (currentUrl.startsWith('chrome://') || 
        currentUrl.startsWith('chrome-extension://') || 
        currentUrl.startsWith('about:') ||
        currentUrl.startsWith('edge://') ||
        currentUrl.startsWith('brave://') ||
        currentUrl.startsWith('opera://')) {
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
    
    // Request check from background script
    chrome.runtime.sendMessage(
      {action: 'checkUrl', url: currentUrl, tabId: tabId},
      function(response) {
        if (chrome.runtime.lastError) {
          console.error('Error sending message:', chrome.runtime.lastError);
          updateUI({error: 'Communication error with background script'});
          return;
        }
        
        if (!response) {
          updateUI({error: 'No response from background script'});
          return;
        }
        
        updateUI(response);
      }
    );
  });
}

// Initialize popup
document.addEventListener('DOMContentLoaded', function() {
  checkCurrentUrl();
  
  // Add refresh button functionality
  document.getElementById('refresh-btn').addEventListener('click', function() {
    checkCurrentUrl();
  });
});


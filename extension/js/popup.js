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
  // Reset advanced sections
  document.getElementById('threat-details').style.display = 'none';
  document.getElementById('cert-analysis').style.display = 'none';
  document.getElementById('external-apis').style.display = 'none';
  document.getElementById('model-explanation').style.display = 'none'; // Hide explanation section
  document.getElementById('details-btn').textContent = '🔍 View Details';
  document.getElementById('loading-spinner').style.display = 'none'; // Hide spinner when UI updates
  
  // Check if this is an offline analysis
  const isOfflineMode = response.isOfflineAnalysis === true;
  
  // Add offline mode indicator if needed
  const modeIndicator = document.getElementById('mode-indicator') || createModeIndicator();
  if (isOfflineMode) {
    modeIndicator.textContent = '🔌 Offline Mode';
    modeIndicator.style.backgroundColor = '#6c757d';
    modeIndicator.style.display = 'block';
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
    
  document.getElementById('confidence').textContent = `${response.confidence}% confidence`;
  document.getElementById('phishing-prob').textContent = `${response.probabilityPhishing}%`;
  document.getElementById('risk-level').textContent = response.riskLevel;
    
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
      
    if (!cert.valid || cert.is_expired || cert.is_self_signed) {
      certStatus = 'Invalid';
      certColor = '#dc3545';
    } else if (cert.is_short_lived) {
      certStatus = 'Suspicious';
      certColor = '#ffc107';
    }
    
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
  } else {
    document.getElementById('model-explanation').style.display = 'none'; // Hide section if no content
  }
  
  document.getElementById('last-checked').textContent = 'Just now';
}

// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
  try {
    // Get current tab URL and check it
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (!tabs || tabs.length === 0) {
        console.error('No active tab found');
        updateUI({error: 'No active tab found'});
        return;
      }
      
      const currentUrl = tabs[0].url;
      
      // Display current URL
      document.getElementById('current-url').textContent = currentUrl;
      
      // Show loading state and spinner
      document.getElementById('status').textContent = 'Checking...';
      document.getElementById('status').className = 'status-checking';
      document.getElementById('confidence').textContent = 'Analyzing URL security...';
      document.getElementById('loading-spinner').style.display = 'block'; // Show spinner
      
      // Set timeout for API response
      let responseTimeout = setTimeout(() => {
        console.log('Request timed out, using offline analysis');
        chrome.runtime.sendMessage({action: 'useOfflineMode', url: currentUrl}, function(offlineResponse) {
          updateUI(offlineResponse || {
            error: 'Request timed out. Using offline analysis.',
            isOfflineAnalysis: true
          });
        });
      }, 5000); // 5 second timeout
      
      // Check the URL and get explanation
      chrome.runtime.sendMessage({action: 'checkURL', url: currentUrl}, function(response) {
        clearTimeout(responseTimeout); // Clear the timeout
        console.log('Received response:', response);
        if (chrome.runtime.lastError) {
          console.error('Runtime error:', chrome.runtime.lastError);
          updateUI({
            error: chrome.runtime.lastError.message,
            isOfflineAnalysis: true
          });
        } else {
          // Fetch explanation
          fetch('https://phishing-detector-isnv.onrender.com/explain', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({url: currentUrl})
          })
          .then(response => response.json())
          .then(explanation => {
            response.modelExplanation = explanation;
            updateUI(response);
          })
          .catch(error => {
            console.error('Error fetching explanation:', error);
            updateUI(response); // Update UI without explanation if fetch fails
          });
        }
      });
    });
  } catch (error) {
    console.error('Popup initialization error:', error);
    updateUI({error: 'Popup initialization failed'});
  }
  
  // Handle recheck button
  document.getElementById('recheck-btn').addEventListener('click', function() {
    try {
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || tabs.length === 0) {
          updateUI({error: 'No active tab found'});
          return;
        }
        const currentUrl = tabs[0].url;
        
        // Show loading state and spinner
        document.getElementById('status').textContent = 'Checking...';
        document.getElementById('status').className = 'status-checking';
        document.getElementById('confidence').textContent = 'Analyzing URL security...';
        document.getElementById('loading-spinner').style.display = 'block'; // Show spinner

        chrome.runtime.sendMessage({action: 'checkURL', url: currentUrl}, function(response) {
          if (chrome.runtime.lastError) {
            updateUI({error: chrome.runtime.lastError.message});
          } else {
            // Fetch explanation
            fetch('https://phishing-detector-isnv.onrender.com/explain', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({url: currentUrl})
            })
            .then(response => response.json())
            .then(explanation => {
              response.modelExplanation = explanation;
              updateUI(response);
            })
            .catch(error => {
              console.error('Error fetching explanation:', error);
              updateUI(response); // Update UI without explanation if fetch fails
            });
          }
        });
      });
    } catch (error) {
      console.error('Recheck error:', error);
      updateUI({error: 'Recheck failed'});
    }
  });
  
  // Handle more info button - open history website
  document.getElementById('more-info-btn').addEventListener('click', function() {
    try {
      chrome.tabs.create({url: chrome.runtime.getURL('history.html')});
    } catch (error) {
      console.error('Failed to open history page:', error);
    }
  });
  
  // Handle details button - toggle advanced details
  document.getElementById('details-btn').addEventListener('click', function() {
    const threatDetails = document.getElementById('threat-details');
    const certAnalysis = document.getElementById('cert-analysis');
    const externalApis = document.getElementById('external-apis');
    const modelExplanation = document.getElementById('model-explanation');
    
    // Toggle visibility with forced display
    if (threatDetails.style.display === 'none') {
      // Force display block for all sections
      threatDetails.style.display = 'block';
      certAnalysis.style.display = 'block';
      externalApis.style.display = 'block';
      modelExplanation.style.display = 'block'; // Show model explanation
      
      // Ensure content is visible
      document.getElementById('threat-details-content').style.display = 'block';
      document.getElementById('cert-analysis-content').style.display = 'block';
      document.getElementById('external-apis-content').style.display = 'block';
      document.getElementById('model-explanation-content').style.display = 'block'; // Show model explanation content
      
      this.textContent = '🔍 Hide Details';
      this.style.backgroundColor = '#dc3545';
    } else {
      threatDetails.style.display = 'none';
      certAnalysis.style.display = 'none';
      externalApis.style.display = 'none';
      modelExplanation.style.display = 'none'; // Hide model explanation
      this.textContent = '🔍 View Details';
      this.style.backgroundColor = '#28a745';
    }
  });
  
  // Handle manual URL check
  document.getElementById('check-button').addEventListener('click', function() {
    try {
      const urlInput = document.getElementById('url-input');
      const url = urlInput.value.trim();
      
      if (!url) {
        updateUI({error: 'Please enter a URL'});
        return;
      }
      
      // Show loading state and spinner
      document.getElementById('status').textContent = 'Checking...';
      document.getElementById('status').className = 'status-checking';
      document.getElementById('confidence').textContent = 'Analyzing URL security...';
      document.getElementById('loading-spinner').style.display = 'block'; // Show spinner

      chrome.runtime.sendMessage({action: 'checkURL', url: url}, function(response) {
        if (chrome.runtime.lastError) {
          updateUI({error: chrome.runtime.lastError.message});
        } else {
          // Fetch explanation
          fetch('https://phishing-detector-isnv.onrender.com/explain', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({url: url})
          })
          .then(response => response.json())
          .then(explanation => {
            response.modelExplanation = explanation;
            updateUI(response);
          })
          .catch(error => {
            console.error('Error fetching explanation:', error);
            updateUI(response); // Update UI without explanation if fetch fails
          });
        }
      });
    } catch (error) {
      console.error('Manual URL check error:', error);
      updateUI({error: 'URL check failed'});
    }
  });
});


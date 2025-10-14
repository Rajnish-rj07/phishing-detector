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
  document.getElementById('details-btn').textContent = '🔍 View Details';
  
  if (response.error) {
    // Show error state
    document.getElementById('status').textContent = 'Error';
    document.getElementById('status').className = 'status-warning';
    document.getElementById('confidence').textContent = 'Unable to check: ' + response.error;
    document.getElementById('phishing-prob').textContent = 'N/A';
    document.getElementById('risk-level').textContent = 'UNKNOWN';
    return;
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
  }
    
  // Update certificate analysis if available
  if (response.certificateAnalysis) {
    const cert = response.certificateAnalysis;
    const certContent = document.getElementById('cert-analysis-content');
      
    let certStatus = 'Valid';
    let certColor = '#28a745';
      
    if (!cert.valid || cert.is_expired || cert.is_self_signed) {
      certStatus = 'Invalid';
      certColor = '#dc3545';
    } else if (cert.is_short_lived) {
      certStatus = 'Suspicious';
      certColor = '#ffc107';
    }
      
    certContent.innerHTML = `
      <div style="margin-bottom: 5px;">
        <strong>Status:</strong> <span style="color: ${certColor}">${certStatus}</span>
      </div>
      <div style="margin-bottom: 5px;">
        <strong>Issuer:</strong> ${cert.issuer || 'Unknown'}
      </div>
      <div style="margin-bottom: 5px;">
        <strong>Valid Until:</strong> ${cert.valid_until || 'Unknown'}
      </div>
    `;
  }
    
  // Update external API results if available
  if (response.externalApiResults) {
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
      
      // Check the URL
      chrome.runtime.sendMessage({action: 'checkURL', url: currentUrl}, function(response) {
        console.log('Received response:', response);
        if (chrome.runtime.lastError) {
          console.error('Runtime error:', chrome.runtime.lastError);
          updateUI({error: chrome.runtime.lastError.message});
        } else {
          updateUI(response);
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
        chrome.runtime.sendMessage({action: 'checkURL', url: tabs[0].url}, function(response) {
          if (chrome.runtime.lastError) {
            updateUI({error: chrome.runtime.lastError.message});
          } else {
            updateUI(response);
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
    
    // Toggle visibility
    if (threatDetails.style.display === 'none') {
      threatDetails.style.display = 'block';
      certAnalysis.style.display = 'block';
      externalApis.style.display = 'block';
      this.textContent = '🔍 Hide Details';
    } else {
      threatDetails.style.display = 'none';
      certAnalysis.style.display = 'none';
      externalApis.style.display = 'none';
      this.textContent = '🔍 View Details';
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
      
      chrome.runtime.sendMessage({action: 'checkURL', url: url}, function(response) {
        if (chrome.runtime.lastError) {
          updateUI({error: chrome.runtime.lastError.message});
        } else {
          updateUI(response);
        }
      });
    } catch (error) {
      console.error('Manual URL check error:', error);
      updateUI({error: 'URL check failed'});
    }
  });
});


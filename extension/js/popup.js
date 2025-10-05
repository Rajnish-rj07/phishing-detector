// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
  
  // Get current tab URL and check it
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const currentUrl = tabs[0].url;
    
    // Display current URL
    document.getElementById('current-url').textContent = currentUrl;
    
    // Check the URL
    chrome.runtime.sendMessage({action: 'checkURL', url: currentUrl}, function(response) {
      console.log('Received response:', response);
      updateUI(response);
    });
  });
  
  // Handle recheck button
  document.getElementById('recheck-btn').addEventListener('click', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.runtime.sendMessage({action: 'checkURL', url: tabs[0].url}, function(response) {
        updateUI(response);
      });
    });
  });
  
  // Handle more info button - open history website
  document.getElementById('more-info-btn').addEventListener('click', function() {
    chrome.tabs.create({url: chrome.runtime.getURL('history.html')});
  });
  
  // Handle manual URL check
  document.getElementById('check-button').addEventListener('click', function() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    
    if (!url) return;
    
    chrome.runtime.sendMessage({action: 'checkURL', url: url}, function(response) {
      updateUI(response);
    });
  });
  
  function updateUI(response) {
    if (response.error) {
      // Show error state
      document.getElementById('status').textContent = 'Error';
      document.getElementById('status').className = 'status-unknown';
      document.getElementById('confidence').textContent = 'Unable to check: ' + response.error;
      document.getElementById('phishing-prob').textContent = 'N/A';
      document.getElementById('risk-level').textContent = 'UNKNOWN';
    } else {
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
    }
    
    document.getElementById('last-checked').textContent = 'Just now';
  }
});

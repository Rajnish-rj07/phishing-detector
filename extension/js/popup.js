// Get current tab URL and check it
chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
  const currentUrl = tabs[0].url;
  
  // Display current URL
  document.getElementById('current-url').textContent = currentUrl;
  
  // Check the URL
  chrome.runtime.sendMessage({action: 'checkURL', url: currentUrl}, function(response) {
    console.log('Received response:', response);
    
    if (response.error) {
      // Show error state
      document.getElementById('status').textContent = 'Error';
      document.getElementById('status').className = 'error';
      document.getElementById('confidence').textContent = 'Unable to check';
      document.getElementById('phishing-prob').textContent = 'N/A';
      document.getElementById('risk-level').textContent = response.error;
    } else {
      // Show results
      if (response.isPhishing) {
        document.getElementById('status').textContent = 'Dangerous';
        document.getElementById('status').className = 'dangerous';
      } else {
        document.getElementById('status').textContent = 'Safe';
        document.getElementById('status').className = 'safe';
      }
      
      document.getElementById('confidence').textContent = `${response.confidence}% confidence`;
      document.getElementById('phishing-prob').textContent = `${response.probabilityPhishing}%`;
      document.getElementById('risk-level').textContent = response.riskLevel;
      document.getElementById('last-checked').textContent = 'Just now';
    }
  });
});

// Handle manual URL check
document.getElementById('check-button').addEventListener('click', function() {
  const urlInput = document.getElementById('url-input');
  const url = urlInput.value.trim();
  
  if (!url) return;
  
  chrome.runtime.sendMessage({action: 'checkURL', url: url}, function(response) {
    // Update UI with manual check results
    // Same logic as above
  });
});

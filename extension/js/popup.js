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

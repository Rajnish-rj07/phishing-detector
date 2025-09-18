// Update your extension to use new API features
const API_URL = 'https://phishing-detector-isnv.onrender.com';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(response => response.json())
    .then(data => {
      // Enhanced response handling
      const result = {
        url: data.url,
        isPhishing: data.prediction === 1,
        riskLevel: data.risk_level,
        confidence: data.confidence,
        reputationScore: data.reputation_score
      };
      sendResponse(result);
    })
    .catch(error => {
      console.error('API Error:', error);
      sendResponse({ error: error.message });
    });
    
    return true;
  }
});

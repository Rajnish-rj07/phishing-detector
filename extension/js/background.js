const API_URL = 'https://phishing-detector-isnv.onrender.com';  // Replace with your actual URL

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    console.log('Checking URL:', request.url);
    
    fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(response => {
      console.log('API Response status:', response.status);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('API Response data:', data);
      
      // Parse the API response properly
      const result = {
        url: data.url || request.url,
        isPhishing: data.prediction === 1,
        riskLevel: data.risk_level || 'UNKNOWN',
        confidence: Math.round((data.confidence || 0) * 100),
        probabilityPhishing: Math.round((data.probability_phishing || 0) * 100),
        probabilityLegitimate: Math.round((data.probability_legitimate || 0) * 100),
        timestamp: data.timestamp || new Date().toISOString()
      };
      
      console.log('Processed result:', result);
      sendResponse(result);
    })
    .catch(error => {
      console.error('API Error:', error);
      sendResponse({
        url: request.url,
        error: error.message,
        isPhishing: false,
        riskLevel: 'UNKNOWN',
        confidence: 0,
        probabilityPhishing: 0
      });
    });
    
    return true; // Keep message channel open for async response
  }
});

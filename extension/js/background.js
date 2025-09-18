const API_URL = 'https://phishing-detector-isnv.onrender.com'; // Replace with your URL
const TEST_MODE = false; // Set to true for testing

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    console.log('Checking URL:', request.url);
    
    // Test mode for debugging
    if (TEST_MODE) {
      const mockResponse = {
        url: request.url,
        isPhishing: request.url.includes('phishing') || request.url.includes('login'),
        riskLevel: 'HIGH',
        confidence: 85,
        probabilityPhishing: 85,
        probabilityLegitimate: 15
      };
      
      setTimeout(() => sendResponse(mockResponse), 1000);
      return true; // Keep message channel open
    }
    
    // Real API call
    fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('API Response:', data);
      
      const result = {
        url: data.url || request.url,
        isPhishing: data.prediction === 1,
        riskLevel: data.risk_level || 'UNKNOWN',
        confidence: Math.round((data.confidence || 0) * 100),
        probabilityPhishing: Math.round((data.probability_phishing || 0) * 100),
        probabilityLegitimate: Math.round((data.probability_legitimate || 0) * 100)
      };
      
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

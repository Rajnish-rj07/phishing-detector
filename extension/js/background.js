const API_URL = 'http://localhost:5000'; // Using local API server instead of remote server
const TEST_MODE = true; // Set to true for testing
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes cache for URLs
const urlCache = new Map(); // Cache for URL check results

// Function to check if a string is an email
function isEmail(text) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(text);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    console.log('Checking URL:', request.url);
    
    // Check cache first for faster response
    const cachedResult = checkCache(request.url);
    if (cachedResult) {
      console.log('Using cached result for:', request.url);
      sendResponse(cachedResult);
      return true;
    }
    
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
      
      // Cache the result for future quick access
      cacheResult(request.url, result);
      
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
  
  // Handle email phishing detection
  if (request.action === 'checkEmail') {
    console.log('Checking Email:', request.email);
    
    // Check cache first
    const cachedResult = checkCache(request.email);
    if (cachedResult) {
      console.log('Using cached result for email:', request.email);
      sendResponse(cachedResult);
      return true;
    }
    
    // Call the email detection API
    fetch(`${API_URL}/check_email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: request.email })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('Email API Response:', data);
      
      const result = {
        email: data.email || request.email,
        isPhishing: data.is_phishing,
        riskLevel: data.risk_level || 'UNKNOWN',
        confidence: Math.round((data.confidence || 0) * 100),
        reasons: data.reasons || []
      };
      
      // Cache the result
      cacheResult(request.email, result);
      
      sendResponse(result);
    })
    .catch(error => {
      console.error('Email API Error:', error);
      sendResponse({
        error: 'Email API Error',
        message: error.toString()
      });
    });
    
    return true; // Keep message channel open
  }
});

// Cache management functions
function checkCache(key) {
  if (urlCache.has(key)) {
    const { timestamp, data } = urlCache.get(key);
    if (Date.now() - timestamp < CACHE_DURATION) {
      return data;
    } else {
      // Cache expired
      urlCache.delete(key);
    }
  }
  return null;
}

function cacheResult(key, data) {
  urlCache.set(key, {
    timestamp: Date.now(),
    data: data
  });
  
  // Clean up old cache entries periodically
  if (urlCache.size > 100) {
    cleanCache();
  }
}

function cleanCache() {
  const now = Date.now();
  for (const [key, value] of urlCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      urlCache.delete(key);
    }
  }
}

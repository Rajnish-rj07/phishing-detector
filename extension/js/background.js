const API_URL = 'http://localhost:5000'; // Using local API server instead of remote server
const TEST_MODE = false; // Disabled test mode for real detection
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes cache for URLs
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second delay between retries
const urlCache = new Map(); // Cache for URL check results

// Function to check if a string is an email
function isEmail(text) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(text);
}

// Enhanced URL checking function that uses our new API features
async function checkUrlWithAPI(url) {
  let retries = 0;
  
  while (retries < MAX_RETRIES) {
    try {
      console.log(`Checking URL with enhanced API (attempt ${retries + 1}/${MAX_RETRIES}):`, url);
      
      // First check if API is available
      const healthCheck = await fetch(`${API_URL}/health`).catch(() => null);
      if (!healthCheck || !healthCheck.ok) {
        throw new Error('API server is not available');
      }
      
      // If health check passes, proceed with URL check
    
    // Proceed with URL check
    const response = await fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ 
        url: url,
        check_external_apis: true
      })
    });
    
    if (!response.ok) {
      if (retries === MAX_RETRIES - 1) {
        throw new Error(`API error: ${response.status} - ${response.statusText}`);
      }
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      retries++;
      continue;
    }
    
    const data = await response.json();
    console.log('API response:', data);
    
    // Transform API response to extension format
    return {
      url: url,
      isPhishing: data.prediction === 1,
      riskLevel: data.risk_level || 'UNKNOWN',
      confidence: Math.round((data.confidence || 0) * 100),
      probabilityPhishing: Math.round((data.probability_phishing || 0) * 100),
      probabilityLegitimate: Math.round((data.probability_legitimate || 1) * 100),
      threatDetails: data.threat_details || [],
      certificateAnalysis: data.certificate_analysis || null,
      externalApiResults: data.external_api_results || null
    };
  } catch (error) {
    console.error(`API check failed (attempt ${retries + 1}/${MAX_RETRIES}):`, error);
    
    if (retries < MAX_RETRIES - 1) {
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      retries++;
      continue;
    }

    // If all retries failed, return a fallback result
    return {
      url: url,
      isPhishing: false,
      riskLevel: 'UNKNOWN',
      confidence: 0,
      probabilityPhishing: 0,
      probabilityLegitimate: 100,
      error: 'API server is not available. Please ensure the API server is running.',
      details: error.message
    };
  }
}
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === 'checkURL') {
      console.log('Checking URL:', request.url);
      
      if (!request.url) {
        sendResponse({
          error: 'No URL provided',
          isPhishing: false,
          riskLevel: 'UNKNOWN',
          confidence: 0
        });
        return true;
      }
      
      // Check cache first for faster response
      const cachedResult = checkCache(request.url);
      if (cachedResult) {
        console.log('Using cached result for:', request.url);
        sendResponse(cachedResult);
        return true;
      }

      // Use enhanced API with external integrations
      checkUrlWithAPI(request.url)
        .then(result => {
          // Cache the result for future quick access
          cacheResult(request.url, result);
          
          // Store in history
          try {
            storeUrlHistory(result);
          } catch (historyError) {
            console.warn('Failed to store URL history:', historyError);
          }
          
          sendResponse(result);
        })
        .catch(error => {
          console.error('Detection Error:', error);
          const fallbackResult = {
            url: request.url,
            error: error.message || 'Detection failed',
            isPhishing: false,
            riskLevel: 'UNKNOWN',
            confidence: 0,
            probabilityPhishing: 0,
            probabilityLegitimate: 100
          };
          sendResponse(fallbackResult);
        });

      return true; // Keep message channel open
    }
    
    if (request.action === 'checkEmail') {
      console.log('Checking email:', request.email);
      
      if (!request.email) {
        sendResponse({
          error: 'No email provided',
          isPhishing: false,
          riskLevel: 'UNKNOWN',
          confidence: 0
        });
        return true;
      }
      
      // Check cache first
      const cachedResult = checkCache(request.email);
      if (cachedResult) {
        console.log('Using cached result for:', request.email);
        sendResponse(cachedResult);
        return true;
      }

      // Simple email validation and domain checking
      checkEmailSafety(request.email)
        .then(result => {
          // Cache the result
          cacheResult(request.email, result);
          
          // Store in email history
          try {
            storeEmailHistory(result);
          } catch (historyError) {
            console.warn('Failed to store email history:', historyError);
          }
          
          sendResponse(result);
        })
        .catch(error => {
          console.error('Email Check Error:', error);
          sendResponse({
            email: request.email,
            error: 'Email Check Error',
            message: error.toString(),
            isPhishing: false,
            riskLevel: 'UNKNOWN',
            confidence: 0
          });
        });
      
      return true; // Keep message channel open
    }
  } catch (globalError) {
    console.error('Global message handler error:', globalError);
    sendResponse({
      error: 'Internal error',
      message: globalError.toString(),
      isPhishing: false,
      riskLevel: 'UNKNOWN',
      confidence: 0
    });
  }
  
  return true;
});

// PhishTank integration function
async function checkUrlWithPhishTank(url) {
  try {
    console.log('Analyzing URL:', url);
    
    // First check against known safe domains
    const safeDomains = [
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
      'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
      'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com'
    ];
    
    // Parse URL and extract domain
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();
    const fullUrlLower = url.toLowerCase();
    
    // Check if it's a known safe domain
    const isKnownSafe = safeDomains.some(safeDomain => 
      domain === safeDomain || domain.endsWith('.' + safeDomain)
    );
    
    if (isKnownSafe) {
      return {
        url: url,
        isPhishing: false,
        riskLevel: 'LOW',
        confidence: 95,
        probabilityPhishing: 5,
        probabilityLegitimate: 95,
        source: 'Safe Domain List'
      };
    }
    
    // Known PhishTank patterns and domains
    const knownPhishingDomains = [
      'net-helps-gat.com', 'indeedacious.fboml.ru', 'customer-support-help.pages.dev',
      'customer-support-center.pages.dev', 'login-secure.pages.dev', 'comfortable-beginning-563461.framer.app',
      'allegrolokalnie.pl-oferta393521.eu', 'zj17a.share-nct.hdfcbank.com', 'meta-mail-gma.com',
      'dropbox.com/scl/fi/2zwuaof5ypf8r7idgzs', 'shorturl.at/crgdM'
    ];
    
    // Check if domain is in known phishing list
    if (knownPhishingDomains.some(phishDomain => domain.includes(phishDomain))) {
      return {
        url: url,
        isPhishing: true,
        riskLevel: 'HIGH',
        confidence: 95,
        probabilityPhishing: 95,
        probabilityLegitimate: 5,
        source: 'PhishTank Known Domain'
      };
    }
    
    // Enhanced suspicious patterns
    const suspiciousPatterns = [
      // IP address URLs
      /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      
      // Suspicious TLDs
      /\.(tk|ml|ga|cf|gq|xyz|top|club|work|date|racing|win|bid|stream|download|xin)$/i,
      
      // Common phishing keywords in domain
      /(secure|login|verify|update|confirm|account|signin|security|auth|webscr|session|checkout|purchase|payment|wallet|access|myaccount|recovery|unlock|reset)/i,
      
      // Brand impersonation
      /(paypal|apple|microsoft|google|amazon|facebook|instagram|twitter|netflix|bank|chase|wellsfargo|citibank|bankofamerica|barclays|hsbc|santander|lloyds|natwest|halifax|tsb|rbs|usbank|capitalone|amex|mastercard|visa)/i,
      
      // Suspicious URL patterns
      /(\.php\?email=|\.php\?account=|\.php\?id=|\.php\?token=|\.php\?session=|\.php\?user=|\.php\?login=|\.php\?password=|\.php\?verification=)/i,
      
      // Suspicious paths
      /(\/login\/|\/signin\/|\/account\/|\/secure\/|\/verify\/|\/auth\/|\/confirm\/|\/update\/|\/recovery\/|\/password\/|\/reset\/)/i,
      
      // URL shorteners (often used in phishing)
      /(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cli\.gs|ow\.ly|ht\.ly|tgr\.ph|tiny\.cc|cutt\.ly|shorturl\.at)/i,
      
      // Suspicious subdomains
      /^https?:\/\/(secure|login|signin|account|verify|update|confirm|webscr|session|checkout|purchase|payment|wallet|access|myaccount|recovery|unlock|reset)\./i,
      
      // Numeric or random subdomains
      /^https?:\/\/[a-z0-9]{8,}\./i,
      
      // Suspicious query parameters
      /\?(token|auth|session|account|user|email|password|login|verify|confirm|update|reset)=/i,
      
      // Pages hosted on document/file sharing sites
      /(docs\.google\.com|drive\.google\.com|dropbox\.com|box\.com|onedrive\.live\.com|1drv\.ms|scribd\.com)/i
    ];
    
    // Check for suspicious patterns in the full URL
    const matchedPatterns = suspiciousPatterns.filter(pattern => 
      pattern.test(fullUrlLower) || pattern.test(domain) || pattern.test(path)
    );
    
    // Calculate risk based on number of matched patterns
    if (matchedPatterns.length > 0) {
      // Calculate probability based on number of matches
      const probabilityPhishing = Math.min(95, 50 + (matchedPatterns.length * 15));
      const probabilityLegitimate = 100 - probabilityPhishing;
      
      // Determine risk level
      let riskLevel = 'MEDIUM';
      if (probabilityPhishing >= 75) riskLevel = 'HIGH';
      else if (probabilityPhishing <= 40) riskLevel = 'LOW';
      
      return {
        url: url,
        isPhishing: probabilityPhishing > 60,
        riskLevel: riskLevel,
        confidence: probabilityPhishing,
        probabilityPhishing: probabilityPhishing,
        probabilityLegitimate: probabilityLegitimate,
        source: 'Enhanced Pattern Analysis',
        matchedPatterns: matchedPatterns.length
      };
    }
    
    // Additional checks for PhishTank-like sites
    const phishingIndicators = [
      // Check for login forms in unexpected domains
      domain.includes('login') && !isKnownSafe,
      
      // Check for secure/bank/verify in domain
      domain.includes('secure') || domain.includes('bank') || domain.includes('verify'),
      
      // Check for suspicious paths
      path.includes('/login') || path.includes('/signin') || path.includes('/account'),
      
      // Check for suspicious TLDs
      domain.endsWith('.tk') || domain.endsWith('.ml') || domain.endsWith('.ga') || 
      domain.endsWith('.cf') || domain.endsWith('.gq') || domain.endsWith('.xyz'),
      
      // Check for hyphens (common in phishing domains)
      (domain.match(/-/g) || []).length >= 2,
      
      // Check for numeric characters (common in phishing domains)
      (domain.match(/\d/g) || []).length >= 3
    ];
    
    // Count how many indicators are true
    const indicatorCount = phishingIndicators.filter(Boolean).length;
    
    if (indicatorCount >= 2) {
      const probabilityPhishing = Math.min(90, 50 + (indicatorCount * 10));
      const probabilityLegitimate = 100 - probabilityPhishing;
      
      let riskLevel = 'MEDIUM';
      if (probabilityPhishing >= 75) riskLevel = 'HIGH';
      else if (probabilityPhishing <= 40) riskLevel = 'LOW';
      
      return {
        url: url,
        isPhishing: probabilityPhishing > 60,
        riskLevel: riskLevel,
        confidence: probabilityPhishing,
        probabilityPhishing: probabilityPhishing,
        probabilityLegitimate: probabilityLegitimate,
        source: 'PhishTank Heuristics',
        indicatorCount: indicatorCount
      };
    }
    
    // Default to low risk for other URLs
    return {
      url: url,
      isPhishing: false,
      riskLevel: 'LOW',
      confidence: 70,
      probabilityPhishing: 30,
      probabilityLegitimate: 70,
      source: 'Default Analysis'
    };
    
  } catch (error) {
    console.error('URL analysis error:', error);
    return {
      url: url,
      isPhishing: false,
      riskLevel: 'UNKNOWN',
      confidence: 0,
      probabilityPhishing: 0,
      probabilityLegitimate: 0,
      source: 'Error'
    };
  }
}

// Email safety checking function
async function checkEmailSafety(email) {
  try {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        email: email,
        isPhishing: true,
        riskLevel: 'HIGH',
        confidence: 90,
        reasons: ['Invalid email format']
      };
    }
    
    const domain = email.split('@')[1].toLowerCase();
    
    // Known safe email providers
    const safeProviders = [
      'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
      'protonmail.com', 'aol.com', 'live.com', 'msn.com'
    ];
    
    if (safeProviders.includes(domain)) {
      return {
        email: email,
        isPhishing: false,
        riskLevel: 'LOW',
        confidence: 85,
        reasons: ['Trusted email provider'],
        probabilityPhishing: 15,
        probabilityLegitimate: 85
      };
    }
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /[0-9]{5,}/, // Many numbers
      /[a-z]{20,}/, // Very long strings
      /(noreply|no-reply|donotreply)/i,
      /\.(tk|ml|ga|cf)$/,
      /secure|verify|account|update|confirm/i // Common phishing keywords
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(email));
    
    return {
      email: email,
      isPhishing: isSuspicious,
      riskLevel: isSuspicious ? 'MEDIUM' : 'LOW',
      confidence: isSuspicious ? 70 : 60,
      reasons: isSuspicious ? ['Suspicious email pattern'] : ['Standard email format'],
      probabilityPhishing: isSuspicious ? 70 : 40,
      probabilityLegitimate: isSuspicious ? 30 : 60
    };
    
  } catch (error) {
    console.warn('Email analysis error:', error);
    return {
      email: email,
      isPhishing: false,
      riskLevel: 'UNKNOWN',
      confidence: 0,
      reasons: ['Analysis error'],
      probabilityPhishing: 0,
      probabilityLegitimate: 0
    };
  }
}

// Local email check function that doesn't use fetch API
async function checkEmail(email) {
  try {
    // Analyze email locally
    const result = await checkEmailSafety(email);
    
    // Store in history
    try {
      const history = await getHistory();
      history.push({
        type: 'email',
        content: email,
        result: result,
        timestamp: new Date().toISOString()
      });
      await chrome.storage.local.set({ history });
    } catch (error) {
      console.warn('Failed to store in history:', error);
    }
    
    return result;
  } catch (error) {
    console.warn('Error checking email:', error);
    return { 
      isPhishing: false,
      confidence: 0,
      probabilityPhishing: 0,
      riskLevel: 'LOW'
    };
  }
}

// Get history helper function
async function getHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['history'], (result) => {
      resolve(result.history || []);
    });
  });
}

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

// History storage functions
function storeUrlHistory(result) {
  chrome.storage.local.get(['urlHistory'], (data) => {
    const urlHistory = data.urlHistory || [];
    
    // Add timestamp to result
    const historyItem = {
      ...result,
      timestamp: Date.now()
    };
    
    // Add to beginning of array (most recent first)
    urlHistory.unshift(historyItem);
    
    // Limit history to 100 items
    if (urlHistory.length > 100) {
      urlHistory.pop();
    }
    
    // Save updated history
    chrome.storage.local.set({urlHistory: urlHistory});
  });
}

function storeEmailHistory(result) {
  chrome.storage.local.get(['emailHistory'], (data) => {
    const emailHistory = data.emailHistory || [];
    
    // Add timestamp to result
    const historyItem = {
      ...result,
      timestamp: Date.now()
    };
    
    // Add to beginning of array (most recent first)
    emailHistory.unshift(historyItem);
    
    // Limit history to 100 items
    if (emailHistory.length > 100) {
      emailHistory.pop();
    }
    
    // Save updated history
    chrome.storage.local.set({emailHistory: emailHistory});
  });
}

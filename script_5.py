# Phase 5: Browser Extension Development

# Create manifest.json (Manifest V3)
manifest_json = '''{
  "manifest_version": 3,
  "name": "Phishing Shield - AI URL Protection",
  "version": "1.0.0",
  "description": "Real-time phishing website detection powered by machine learning",
  
  "permissions": [
    "activeTab",
    "storage"
  ],
  
  "host_permissions": [
    "http://localhost:5000/*",
    "https://your-api-domain.herokuapp.com/*"
  ],
  
  "background": {
    "service_worker": "js/background.js"
  },
  
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["js/content.js"],
      "css": ["css/content.css"],
      "run_at": "document_idle"
    }
  ],
  
  "action": {
    "default_popup": "popup.html",
    "default_title": "Phishing Shield",
    "default_icon": {
      "16": "icons/icon16.png",
      "32": "icons/icon32.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  
  "icons": {
    "16": "icons/icon16.png",
    "32": "icons/icon32.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  },
  
  "web_accessible_resources": [
    {
      "resources": ["css/warning-banner.css"],
      "matches": ["<all_urls>"]
    }
  ]
}'''

with open('phishing-detector/extension/manifest.json', 'w') as f:
    f.write(manifest_json)

print("✅ Created manifest.json")

# Create background.js (Service Worker)
background_js = '''
// Background Service Worker for Phishing Shield Extension

const API_URL = 'http://localhost:5000';  // Change this to your deployed API URL
const CACHE_DURATION = 5 * 60 * 1000;    // 5 minutes cache

class PhishingDetectionService {
  constructor() {
    this.cache = new Map();
    this.pendingRequests = new Map();
  }

  async checkURL(url) {
    try {
      // Check cache first
      const cached = this.getCachedResult(url);
      if (cached) {
        return cached;
      }

      // Check if request is already pending
      if (this.pendingRequests.has(url)) {
        return await this.pendingRequests.get(url);
      }

      // Make API request
      const requestPromise = this.makeAPIRequest(url);
      this.pendingRequests.set(url, requestPromise);

      const result = await requestPromise;
      
      // Cache result
      this.cacheResult(url, result);
      
      // Remove from pending requests
      this.pendingRequests.delete(url);

      return result;
    } catch (error) {
      console.error('Error checking URL:', error);
      this.pendingRequests.delete(url);
      return this.getDefaultResult(url, error.message);
    }
  }

  async makeAPIRequest(url) {
    const response = await fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    return await response.json();
  }

  getCachedResult(url) {
    const cached = this.cache.get(url);
    if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
      return cached.result;
    }
    this.cache.delete(url);
    return null;
  }

  cacheResult(url, result) {
    this.cache.set(url, {
      result: result,
      timestamp: Date.now()
    });
  }

  getDefaultResult(url, error) {
    return {
      url: url,
      prediction: 0,
      prediction_label: 'Unknown',
      confidence: 0.5,
      probability_phishing: 0.5,
      risk_level: 'UNKNOWN',
      error: error
    };
  }

  clearCache() {
    this.cache.clear();
    console.log('Cache cleared');
  }
}

// Initialize service
const phishingService = new PhishingDetectionService();

// Message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    phishingService.checkURL(request.url)
      .then(result => sendResponse(result))
      .catch(error => {
        console.error('Error in message handler:', error);
        sendResponse(phishingService.getDefaultResult(request.url, error.message));
      });
    return true; // Will respond asynchronously
  }
  
  if (request.action === 'clearCache') {
    phishingService.clearCache();
    sendResponse({ success: true });
  }
});

// Update badge based on current tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Only check HTTP/HTTPS URLs
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      phishingService.checkURL(tab.url)
        .then(result => updateBadge(tabId, result))
        .catch(error => console.error('Error updating badge:', error));
    }
  }
});

// Update extension badge
function updateBadge(tabId, result) {
  let badgeText = '';
  let badgeColor = '#4CAF50'; // Green for safe
  
  if (result.error) {
    badgeText = '?';
    badgeColor = '#9E9E9E'; // Gray for unknown
  } else if (result.prediction === 1) {
    badgeText = '!';
    badgeColor = '#F44336'; // Red for phishing
  } else if (result.probability_phishing > 0.6) {
    badgeText = '⚠';
    badgeColor = '#FF9800'; // Orange for suspicious
  }
  
  chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
}

console.log('Phishing Shield background service worker initialized');
'''

with open('phishing-detector/extension/js/background.js', 'w') as f:
    f.write(background_js)

print("✅ Created js/background.js")

# Create content.js (Content Script)
content_js = '''
// Content script for Phishing Shield Extension

class PhishingWarningManager {
  constructor() {
    this.currentWarning = null;
    this.isChecking = false;
    this.checkCurrentURL();
  }

  async checkCurrentURL() {
    if (this.isChecking) return;
    this.isChecking = true;

    try {
      const result = await this.sendMessageToBackground('checkURL', { url: window.location.href });
      this.handleResult(result);
    } catch (error) {
      console.error('Error checking URL:', error);
    } finally {
      this.isChecking = false;
    }
  }

  sendMessageToBackground(action, data) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action, ...data }, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
  }

  handleResult(result) {
    // Remove existing warning
    this.removeWarning();

    // Show warning if phishing detected
    if (result.prediction === 1 || result.probability_phishing > 0.6) {
      this.showWarning(result);
    }
  }

  showWarning(result) {
    // Create warning banner
    const warning = this.createWarningBanner(result);
    
    // Insert at top of page
    document.body.insertBefore(warning, document.body.firstChild);
    this.currentWarning = warning;

    // Scroll to top to ensure visibility
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  createWarningBanner(result) {
    const warning = document.createElement('div');
    warning.id = 'phishing-shield-warning';
    warning.className = 'phishing-shield-banner';
    
    const riskLevel = result.risk_level || 'HIGH';
    const confidence = Math.round(result.confidence * 100);
    const phishingProb = Math.round(result.probability_phishing * 100);

    warning.innerHTML = `
      <div class="warning-content">
        <div class="warning-header">
          <div class="warning-icon">🛡️⚠️</div>
          <div class="warning-title">
            <strong>PHISHING ALERT</strong>
          </div>
          <button class="close-btn" onclick="this.parentElement.parentElement.parentElement.remove()">×</button>
        </div>
        <div class="warning-body">
          <p><strong>This website may be attempting to steal your personal information!</strong></p>
          <div class="warning-details">
            <div class="detail-item">
              <span class="label">Risk Level:</span>
              <span class="value risk-${riskLevel.toLowerCase()}">${riskLevel}</span>
            </div>
            <div class="detail-item">
              <span class="label">Phishing Probability:</span>
              <span class="value">${phishingProb}%</span>
            </div>
            <div class="detail-item">
              <span class="label">Confidence:</span>
              <span class="value">${confidence}%</span>
            </div>
          </div>
        </div>
        <div class="warning-actions">
          <button class="btn-danger" onclick="window.history.back()">← Go Back</button>
          <button class="btn-secondary" onclick="this.parentElement.parentElement.parentElement.remove()">Continue Anyway</button>
          <button class="btn-primary" onclick="window.open('https://www.google.com', '_blank')">Go to Google</button>
        </div>
      </div>
    `;

    return warning;
  }

  removeWarning() {
    if (this.currentWarning) {
      this.currentWarning.remove();
      this.currentWarning = null;
    }
    
    // Also remove any existing warnings
    const existing = document.getElementById('phishing-shield-warning');
    if (existing) {
      existing.remove();
    }
  }
}

// Initialize warning manager when page is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new PhishingWarningManager();
  });
} else {
  new PhishingWarningManager();
}

// Check URL changes for single-page applications
let lastURL = window.location.href;
new MutationObserver(() => {
  const currentURL = window.location.href;
  if (currentURL !== lastURL) {
    lastURL = currentURL;
    setTimeout(() => new PhishingWarningManager(), 1000); // Delay to allow page to load
  }
}).observe(document, { subtree: true, childList: true });

console.log('Phishing Shield content script loaded');
'''

with open('phishing-detector/extension/js/content.js', 'w') as f:
    f.write(content_js)

print("✅ Created js/content.js")

# Create content.css (Content Script Styles)
content_css = '''
/* Phishing Shield Warning Banner Styles */

#phishing-shield-warning {
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  width: 100% !important;
  z-index: 2147483647 !important; /* Maximum z-index */
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
  font-size: 14px !important;
  line-height: 1.4 !important;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
  animation: slideDown 0.3s ease-out !important;
}

@keyframes slideDown {
  from { transform: translateY(-100%); }
  to { transform: translateY(0); }
}

.phishing-shield-banner {
  background: linear-gradient(135deg, #ff4444, #cc0000) !important;
  color: white !important;
  border: none !important;
  margin: 0 !important;
  padding: 0 !important;
}

.warning-content {
  max-width: 1200px !important;
  margin: 0 auto !important;
  padding: 16px 20px !important;
}

.warning-header {
  display: flex !important;
  align-items: center !important;
  justify-content: space-between !important;
  margin-bottom: 12px !important;
}

.warning-icon {
  font-size: 24px !important;
  margin-right: 12px !important;
  flex-shrink: 0 !important;
}

.warning-title {
  flex-grow: 1 !important;
  font-size: 18px !important;
  font-weight: bold !important;
  color: white !important;
}

.close-btn {
  background: rgba(255,255,255,0.2) !important;
  border: 1px solid rgba(255,255,255,0.3) !important;
  color: white !important;
  width: 32px !important;
  height: 32px !important;
  border-radius: 50% !important;
  font-size: 18px !important;
  font-weight: bold !important;
  cursor: pointer !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  transition: background 0.2s !important;
}

.close-btn:hover {
  background: rgba(255,255,255,0.3) !important;
}

.warning-body p {
  margin: 0 0 12px 0 !important;
  font-size: 16px !important;
  font-weight: 500 !important;
  color: white !important;
}

.warning-details {
  display: flex !important;
  gap: 20px !important;
  margin-bottom: 16px !important;
  flex-wrap: wrap !important;
}

.detail-item {
  display: flex !important;
  align-items: center !important;
  gap: 8px !important;
}

.detail-item .label {
  font-weight: 500 !important;
  color: rgba(255,255,255,0.9) !important;
}

.detail-item .value {
  font-weight: bold !important;
  color: white !important;
  padding: 2px 8px !important;
  background: rgba(255,255,255,0.2) !important;
  border-radius: 12px !important;
  font-size: 13px !important;
}

.risk-high { background: rgba(255,255,255,0.3) !important; }
.risk-medium { background: rgba(255,200,0,0.8) !important; color: black !important; }
.risk-low { background: rgba(255,255,0,0.8) !important; color: black !important; }

.warning-actions {
  display: flex !important;
  gap: 12px !important;
  flex-wrap: wrap !important;
}

.warning-actions button {
  padding: 10px 20px !important;
  border: none !important;
  border-radius: 6px !important;
  font-weight: 600 !important;
  cursor: pointer !important;
  transition: all 0.2s !important;
  font-size: 14px !important;
  text-decoration: none !important;
}

.btn-danger {
  background: #ffffff !important;
  color: #cc0000 !important;
  border: 2px solid white !important;
}

.btn-danger:hover {
  background: #f0f0f0 !important;
  transform: translateY(-1px) !important;
}

.btn-secondary {
  background: rgba(255,255,255,0.2) !important;
  color: white !important;
  border: 1px solid rgba(255,255,255,0.4) !important;
}

.btn-secondary:hover {
  background: rgba(255,255,255,0.3) !important;
}

.btn-primary {
  background: #2196F3 !important;
  color: white !important;
}

.btn-primary:hover {
  background: #1976D2 !important;
  transform: translateY(-1px) !important;
}

/* Mobile responsive */
@media (max-width: 768px) {
  .warning-content {
    padding: 12px 16px !important;
  }
  
  .warning-title {
    font-size: 16px !important;
  }
  
  .warning-details {
    flex-direction: column !important;
    gap: 8px !important;
  }
  
  .warning-actions {
    flex-direction: column !important;
  }
  
  .warning-actions button {
    width: 100% !important;
  }
}
'''

with open('phishing-detector/extension/css/content.css', 'w') as f:
    f.write(content_css)

print("✅ Created css/content.css")
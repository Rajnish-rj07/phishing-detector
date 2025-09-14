
// Background Service Worker for Phishing Shield Extension

const API_URL = 'https://phishing-detector-4-vele.onrender.com';
 // Change this to your deployed API URL
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

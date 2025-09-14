
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

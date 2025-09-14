# Create popup.js (Popup JavaScript)
popup_js = '''// Phishing Shield Popup JavaScript

class PhishingShieldPopup {
  constructor() {
    this.currentTabUrl = null;
    this.stats = { urlsChecked: 0, threatsBlocked: 0 };
    this.settings = { autoCheck: true, showWarnings: true };
    
    this.initializePopup();
  }

  async initializePopup() {
    // Load settings and stats
    await this.loadStoredData();
    
    // Get current tab URL
    await this.getCurrentTab();
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Check current URL if available
    if (this.currentTabUrl) {
      this.checkCurrentURL();
    }
    
    // Update UI
    this.updateStatsDisplay();
    this.updateSettingsDisplay();
  }

  async loadStoredData() {
    try {
      const result = await chrome.storage.local.get(['stats', 'settings']);
      
      if (result.stats) {
        this.stats = { ...this.stats, ...result.stats };
      }
      
      if (result.settings) {
        this.settings = { ...this.settings, ...result.settings };
      }
    } catch (error) {
      console.error('Error loading stored data:', error);
    }
  }

  async saveStats() {
    try {
      await chrome.storage.local.set({ stats: this.stats });
    } catch (error) {
      console.error('Error saving stats:', error);
    }
  }

  async saveSettings() {
    try {
      await chrome.storage.local.set({ settings: this.settings });
    } catch (error) {
      console.error('Error saving settings:', error);
    }
  }

  async getCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
        this.currentTabUrl = tab.url;
      }
    } catch (error) {
      console.error('Error getting current tab:', error);
    }
  }

  setupEventListeners() {
    // Recheck button
    const recheckBtn = document.getElementById('recheckBtn');
    if (recheckBtn) {
      recheckBtn.addEventListener('click', () => {
        this.checkCurrentURL(true);
      });
    }

    // Manual URL check
    const checkBtn = document.getElementById('checkBtn');
    const manualUrlInput = document.getElementById('manualUrl');
    
    if (checkBtn && manualUrlInput) {
      checkBtn.addEventListener('click', () => {
        const url = manualUrlInput.value.trim();
        if (url) {
          this.checkManualURL(url);
        }
      });

      manualUrlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          const url = manualUrlInput.value.trim();
          if (url) {
            this.checkManualURL(url);
          }
        }
      });
    }

    // Settings toggles
    const autoCheckToggle = document.getElementById('autoCheck');
    const showWarningsToggle = document.getElementById('showWarnings');

    if (autoCheckToggle) {
      autoCheckToggle.addEventListener('change', (e) => {
        this.settings.autoCheck = e.target.checked;
        this.saveSettings();
      });
    }

    if (showWarningsToggle) {
      showWarningsToggle.addEventListener('change', (e) => {
        this.settings.showWarnings = e.target.checked;
        this.saveSettings();
      });
    }

    // Report button
    const reportBtn = document.getElementById('reportBtn');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => {
        this.openReportPage();
      });
    }

    // Footer links
    document.getElementById('helpLink')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.openHelpPage();
    });

    document.getElementById('aboutLink')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.showAboutInfo();
    });
  }

  async checkCurrentURL(force = false) {
    if (!this.currentTabUrl) {
      this.showError('No valid URL to check');
      return;
    }

    this.showLoading();

    try {
      const result = await this.sendMessageToBackground('checkURL', { 
        url: this.currentTabUrl,
        force: force
      });

      this.displayResult(result, 'current');
      this.updateStats(result);
      
    } catch (error) {
      console.error('Error checking current URL:', error);
      this.showError('Failed to check URL');
    }
  }

  async checkManualURL(url) {
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    const checkBtn = document.getElementById('checkBtn');
    const originalText = checkBtn.textContent;
    checkBtn.textContent = 'Checking...';
    checkBtn.disabled = true;

    try {
      const result = await this.sendMessageToBackground('checkURL', { url: url });
      this.displayResult(result, 'manual');
      this.updateStats(result);
      
    } catch (error) {
      console.error('Error checking manual URL:', error);
      this.showManualError('Failed to check URL');
    } finally {
      checkBtn.textContent = originalText;
      checkBtn.disabled = false;
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

  showLoading() {
    const loadingIndicator = document.getElementById('loadingIndicator');
    const statusResult = document.getElementById('statusResult');
    const riskDetails = document.getElementById('riskDetails');

    if (loadingIndicator) loadingIndicator.style.display = 'flex';
    if (statusResult) statusResult.style.display = 'none';
    if (riskDetails) riskDetails.style.display = 'none';
  }

  displayResult(result, type = 'current') {
    if (type === 'current') {
      this.displayCurrentResult(result);
    } else {
      this.displayManualResult(result);
    }
  }

  displayCurrentResult(result) {
    const loadingIndicator = document.getElementById('loadingIndicator');
    const statusResult = document.getElementById('statusResult');
    const riskDetails = document.getElementById('riskDetails');

    // Hide loading
    if (loadingIndicator) loadingIndicator.style.display = 'none';

    // Show result
    if (statusResult) statusResult.style.display = 'block';
    if (riskDetails) riskDetails.style.display = 'block';

    // Update status
    const statusIcon = document.getElementById('statusIcon');
    const statusLabel = document.getElementById('statusLabel');
    const confidenceText = document.getElementById('confidenceText');
    const currentUrl = document.getElementById('currentUrl');

    if (result.error) {
      if (statusIcon) statusIcon.textContent = '❓';
      if (statusLabel) {
        statusLabel.textContent = 'Error';
        statusLabel.className = 'status-label status-unknown';
      }
      if (confidenceText) confidenceText.textContent = result.error;
    } else {
      const isPhishing = result.prediction === 1;
      const probability = Math.round((result.probability_phishing || 0) * 100);
      const confidence = Math.round((result.confidence || 0) * 100);

      if (statusIcon) {
        statusIcon.textContent = isPhishing ? '🚨' : '🔒';
      }

      if (statusLabel) {
        statusLabel.textContent = isPhishing ? 'Phishing Detected' : 'Safe';
        statusLabel.className = `status-label ${isPhishing ? 'status-danger' : 'status-safe'}`;
      }

      if (confidenceText) {
        confidenceText.textContent = `${confidence}% confidence`;
      }
    }

    if (currentUrl) {
      currentUrl.textContent = this.truncateUrl(this.currentTabUrl);
    }

    // Update risk details
    this.updateRiskDetails(result);
  }

  displayManualResult(result) {
    const manualResult = document.getElementById('manualResult');
    const manualResultContent = document.getElementById('manualResultContent');

    if (!manualResult || !manualResultContent) return;

    manualResult.style.display = 'block';

    if (result.error) {
      manualResultContent.innerHTML = `
        <div class="result-error">
          <span>❌</span>
          <div>Error: ${result.error}</div>
        </div>
      `;
      return;
    }

    const isPhishing = result.prediction === 1;
    const probability = Math.round((result.probability_phishing || 0) * 100);
    const confidence = Math.round((result.confidence || 0) * 100);
    const riskLevel = result.risk_level || 'UNKNOWN';

    const statusClass = isPhishing ? 'status-danger' : 'status-safe';
    const statusIcon = isPhishing ? '🚨' : '🔒';
    const statusText = isPhishing ? 'Phishing Detected' : 'Safe';

    manualResultContent.innerHTML = `
      <div class="result-header ${statusClass}">
        <span class="result-icon">${statusIcon}</span>
        <div class="result-text">
          <div class="result-status">${statusText}</div>
          <div class="result-confidence">${confidence}% confidence</div>
        </div>
      </div>
      <div class="result-details">
        <div class="result-detail">
          <span>Phishing Probability:</span>
          <span>${probability}%</span>
        </div>
        <div class="result-detail">
          <span>Risk Level:</span>
          <span class="risk-badge risk-${riskLevel.toLowerCase()}">${riskLevel}</span>
        </div>
      </div>
    `;
  }

  updateRiskDetails(result) {
    const phishingProb = document.getElementById('phishingProb');
    const riskLevel = document.getElementById('riskLevel');
    const lastChecked = document.getElementById('lastChecked');

    if (result.error) {
      if (phishingProb) phishingProb.textContent = 'Unknown';
      if (riskLevel) {
        riskLevel.textContent = 'ERROR';
        riskLevel.className = 'risk-badge status-unknown';
      }
    } else {
      const probability = Math.round((result.probability_phishing || 0) * 100);
      const risk = result.risk_level || 'UNKNOWN';

      if (phishingProb) phishingProb.textContent = `${probability}%`;
      if (riskLevel) {
        riskLevel.textContent = risk;
        riskLevel.className = `risk-badge risk-${risk.toLowerCase()}`;
      }
    }

    if (lastChecked) {
      lastChecked.textContent = 'Just now';
    }
  }

  updateStats(result) {
    this.stats.urlsChecked++;
    
    if (!result.error && result.prediction === 1) {
      this.stats.threatsBlocked++;
    }

    this.saveStats();
    this.updateStatsDisplay();
  }

  updateStatsDisplay() {
    const urlsCheckedElement = document.getElementById('urlsChecked');
    const threatsBlockedElement = document.getElementById('threatsBlocked');

    if (urlsCheckedElement) {
      urlsCheckedElement.textContent = this.stats.urlsChecked.toLocaleString();
    }

    if (threatsBlockedElement) {
      threatsBlockedElement.textContent = this.stats.threatsBlocked.toLocaleString();
    }
  }

  updateSettingsDisplay() {
    const autoCheckToggle = document.getElementById('autoCheck');
    const showWarningsToggle = document.getElementById('showWarnings');

    if (autoCheckToggle) {
      autoCheckToggle.checked = this.settings.autoCheck;
    }

    if (showWarningsToggle) {
      showWarningsToggle.checked = this.settings.showWarnings;
    }
  }

  showError(message) {
    const loadingIndicator = document.getElementById('loadingIndicator');
    const statusResult = document.getElementById('statusResult');

    if (loadingIndicator) loadingIndicator.style.display = 'none';
    if (statusResult) {
      statusResult.style.display = 'block';
      statusResult.innerHTML = `
        <div class="status-error">
          <span>❌</span>
          <div>Error: ${message}</div>
        </div>
      `;
    }
  }

  showManualError(message) {
    const manualResult = document.getElementById('manualResult');
    const manualResultContent = document.getElementById('manualResultContent');

    if (manualResult && manualResultContent) {
      manualResult.style.display = 'block';
      manualResultContent.innerHTML = `
        <div class="result-error">
          <span>❌</span>
          <div>Error: ${message}</div>
        </div>
      `;
    }
  }

  truncateUrl(url, maxLength = 35) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  openReportPage() {
    const reportUrl = 'https://github.com/your-username/phishing-detector/issues/new';
    chrome.tabs.create({ url: reportUrl });
    window.close();
  }

  openHelpPage() {
    const helpUrl = 'https://github.com/your-username/phishing-detector/wiki';
    chrome.tabs.create({ url: helpUrl });
    window.close();
  }

  showAboutInfo() {
    alert(`Phishing Shield v1.0

A machine learning-powered browser extension for real-time phishing detection.

Features:
• Real-time URL analysis
• ML-based threat detection
• Privacy-focused design
• Open source

Developed with ❤️ for safer browsing.`);
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PhishingShieldPopup();
});

// Handle extension icon clicks
chrome.action.onClicked?.addListener((tab) => {
  chrome.action.openPopup();
});'''

with open('phishing-detector/extension/js/popup.js', 'w') as f:
    f.write(popup_js)

print("✅ Created js/popup.js")

# Create a simple README for the extension
readme_extension = '''# Phishing Shield Browser Extension

## Installation (Development Mode)

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked" and select the `extension` folder
4. The extension should now appear in your extensions list

## Setup

1. Make sure your Flask API is running on `http://localhost:5000`
2. Update the API_URL in `js/background.js` if using a different endpoint
3. Test the extension by visiting various websites

## Features

- Real-time phishing detection
- Visual warning banners
- Popup interface with detailed analysis
- Manual URL checking
- Protection statistics
- Privacy-focused design

## Files Structure

- `manifest.json` - Extension configuration
- `popup.html` - Extension popup interface
- `css/popup.css` - Popup styling
- `js/popup.js` - Popup functionality
- `js/background.js` - Service worker
- `js/content.js` - Content script for page warnings
- `css/content.css` - Warning banner styles

## API Integration

The extension communicates with your Flask API to analyze URLs. Make sure the API is running before using the extension.
'''

with open('phishing-detector/extension/README.md', 'w') as f:
    f.write(readme_extension)

print("✅ Phase 5: Browser extension completed!")
print("📄 Extension files created:")

// Content script for Phishing Shield Extension

class PhishingWarningManager {
  constructor() {
    this.currentWarning = null;
    this.isChecking = false;
    this.emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    this.checkedEmails = new Set();
    
    // Check current URL immediately
    this.checkCurrentURL();
    
    // Set up email detection
    this.setupEmailDetection();
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
  
  setupEmailDetection() {
    // Scan for emails in the page content
    this.scanForEmails();
    
    // Set up mutation observer to detect new content
    const observer = new MutationObserver((mutations) => {
      this.scanForEmails();
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }
  
  async scanForEmails() {
    // Get all text content from the page
    const pageText = document.body.innerText;
    const emails = pageText.match(this.emailRegex) || [];
    
    // Check each email that hasn't been checked yet
    for (const email of emails) {
      if (!this.checkedEmails.has(email)) {
        this.checkedEmails.add(email);
        this.checkEmail(email);
      }
    }
  }
  
  async checkEmail(email) {
    try {
      const result = await this.sendMessageToBackground('checkEmail', { email });
      if (result.isPhishing) {
        this.highlightPhishingEmail(email, result);
      }
    } catch (error) {
      console.error('Error checking email:', error);
    }
  }
  
  highlightPhishingEmail(email, result) {
    // Find all instances of this email in the page
    const textNodes = this.findTextNodesWithEmail(email);
    
    textNodes.forEach(node => {
      const parent = node.parentNode;
      const text = node.nodeValue;
      
      // Create a highlighted version of the text
      const newHtml = text.replace(
        new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
        `<span class="phishing-email-warning" title="Risk Level: ${result.riskLevel}, Confidence: ${result.confidence}%">${email}</span>`
      );
      
      // Replace the text node with the highlighted version
      const tempDiv = document.createElement('div');
      tempDiv.innerHTML = newHtml;
      
      const fragment = document.createDocumentFragment();
      while (tempDiv.firstChild) {
        fragment.appendChild(tempDiv.firstChild);
      }
      
      parent.replaceChild(fragment, node);
    });
  }
  
  findTextNodesWithEmail(email) {
    const textNodes = [];
    const walk = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function(node) {
          return node.nodeValue.includes(email) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        }
      }
    );
    
    let node;
    while (node = walk.nextNode()) {
      textNodes.push(node);
    }
    
    return textNodes;
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

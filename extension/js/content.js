
// Content script for Phishing Shield Extension

// Initialize immediately when script loads
(function() {
  // Wait for DOM to be ready before initializing
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPhishingShield);
  } else {
    initPhishingShield();
  }
  
  // Also check when page is fully loaded (for all resources)
  window.addEventListener('load', function() {
    // If we already have a manager, just recheck the URL
    if (window.phishingManager) {
      window.phishingManager.checkCurrentURL();
    } else {
      initPhishingShield();
    }
  });
  
  function initPhishingShield() {
    // Only initialize once
    if (!window.phishingManager) {
      window.phishingManager = new PhishingWarningManager();
    }
  }
})();

class PhishingWarningManager {
  constructor() {
    this.currentWarning = null;
    this.isChecking = false;
    this.emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    this.checkedEmails = new Set();
    
    // Check URL immediately
    this.checkCurrentURL();
    
    // Set up email detection when DOM is ready
    if (document.body) {
      this.setupEmailDetection();
    } else {
      // Wait for body to be available
      const observer = new MutationObserver((mutations, obs) => {
        if (document.body) {
          this.setupEmailDetection();
          obs.disconnect();
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  }

  async checkCurrentURL() {
    if (this.isChecking) return;
    this.isChecking = true;

    try {
      console.log("Checking URL:", window.location.href);
      const result = await this.sendMessageToBackground('checkURL', { url: window.location.href });
      console.log("URL check result:", result);
      
      // Force display for testing - remove in production
      if (result) {
        // Always show warning for testing
        this.showWarning(result);
      }
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
      if (result && result.isPhishing) {
        this.highlightPhishingEmail(email, result);
      }
    } catch (error) {
      // Silently handle the error to prevent TypeError from showing in console
      console.warn('Email check handled:', email);
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
      try {
        // Add timeout to prevent hanging promises
        const timeoutId = setTimeout(() => {
          console.warn(`Message timeout (${action}): No response received`);
          resolve({}); // Resolve with empty object after timeout
        }, 5000); // 5 second timeout
        
        chrome.runtime.sendMessage({ action, ...data }, (response) => {
          if (chrome.runtime.lastError) {
            console.warn(`Message error (${action}):`, chrome.runtime.lastError.message);
            clearTimeout(timeoutId); // Clear timeout when error received
            resolve({}); // Return empty object instead of rejecting
            return; // Important: return early to prevent further execution
          }
          
          clearTimeout(timeoutId); // Clear timeout when response received
          resolve(response || {});
        });
      } catch (error) {
        console.warn(`Failed to send message (${action}):`, error);
        resolve({}); // Return empty object to prevent errors
      }
    });
  }

  handleResult(result) {
    // Remove existing warning
    this.removeWarning();

    // Show warning if phishing detected
    if (result && (result.isPhishing || (result.probabilityPhishing && result.probabilityPhishing > 60))) {
      this.showWarning(result);
    }
  }

  showWarning(result) {
    // Create warning banner
    const warning = this.createWarningBanner(result);

    // Make sure body exists before inserting
    if (document.body) {
      // Insert at top of page
      document.body.insertBefore(warning, document.body.firstChild);
      this.currentWarning = warning;

      // Ensure the banner is visible by adding inline styles
      warning.style.position = 'fixed';
      warning.style.top = '0';
      warning.style.left = '0';
      warning.style.width = '100%';
      warning.style.zIndex = '2147483647';
      
      // Scroll to top to ensure visibility
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      // If body doesn't exist yet, wait and try again
      setTimeout(() => this.showWarning(result), 100);
    }
  }

  createWarningBanner(result) {
    // Extract risk level, confidence, and probability
    const riskLevel = result && result.riskLevel ? result.riskLevel : 'LOW';
    const confidence = result && result.confidence ? result.confidence : 70;
    const phishingProb = result && result.probabilityPhishing ? result.probabilityPhishing : 30;
    
    // Determine risk class based on probability
    let riskClass = 'risk-level-low';
    let riskText = 'LOW';
    
    if (phishingProb >= 75 || riskLevel.toUpperCase() === 'HIGH') {
      riskClass = 'risk-level-high';
      riskText = 'HIGH';
    } else if (phishingProb > 30 && phishingProb < 75) {
      riskClass = 'risk-level-medium';
      riskText = 'MEDIUM';
    }

    // Create banner element
    const banner = document.createElement('div');
    banner.id = 'phishing-shield-warning';
    banner.className = 'phishing-shield-banner';
    
    // Add risk class to banner
    banner.classList.add(riskClass);
    
    banner.innerHTML = `
      <div class="phishing-shield-content">
        <div class="phishing-shield-header">
          <div class="shield-logo">
            <img src="${chrome.runtime.getURL('icons/phishing_shield_logo.svg')}" alt="Phishing Shield" width="32" height="32" />
            <h2>Phishing Shield</h2>
          </div>
          <div class="risk-indicator">
            <span>⚠️ Warning</span>
            <span class="risk-badge risk-badge-${riskText.toLowerCase()}">${riskText}</span>
          </div>
          <button id="phishing-shield-close" aria-label="Close">×</button>
        </div>
        <div class="phishing-shield-body">
          <p>This website has been detected as potentially malicious.</p>
          <div class="phishing-shield-details">
            <div class="phishing-shield-detail">
              <span class="detail-label">Risk Level:</span>
              <span class="detail-value">${riskText}</span>
            </div>
            <div class="phishing-shield-detail">
              <span class="detail-label">Confidence:</span>
              <span class="detail-value">${confidence}%</span>
            </div>
            <div class="phishing-shield-detail">
              <span class="detail-label">Probability:</span>
              <span class="detail-value">${phishingProb}%</span>
            </div>
          </div>
          <div class="phishing-shield-actions">
            <button id="phishing-shield-back" class="btn-primary">Go Back (Safe)</button>
            <button id="phishing-shield-proceed" class="btn-secondary">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;
    
    // Add event listeners immediately and with a backup timeout
    const addEventListeners = () => {
      const closeBtn = document.getElementById('phishing-shield-close');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          this.removeWarning();
        });
      }
      
      const proceedBtn = document.getElementById('phishing-shield-proceed');
      if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
          // Store in local storage that user proceeded for this domain
          const domain = window.location.hostname;
          // Check if chrome.storage is available before using it
          if (chrome && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({[`proceeded_${domain}`]: true});
          } else {
            console.log('Chrome storage API not available');
            // Use localStorage as fallback
            localStorage.setItem(`proceeded_${domain}`, 'true');
          }
          this.removeWarning();
        });
      }
      
      const backBtn = document.getElementById('phishing-shield-back');
      if (backBtn) {
        backBtn.addEventListener('click', () => {
          window.history.back();
        });
      }
    };
    
    // Try to add event listeners immediately
    addEventListeners();
    
    // Also try with a timeout as backup
    setTimeout(addEventListeners, 100);
    
    return banner;
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

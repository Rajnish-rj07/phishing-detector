# Create popup.html (Extension Popup Interface)
popup_html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing Shield</title>
  <link rel="stylesheet" href="css/popup.css">
</head>
<body>
  <div class="popup-container">
    <!-- Header -->
    <div class="header">
      <div class="logo">
        <span class="shield-icon">🛡️</span>
        <h1>Phishing Shield</h1>
      </div>
      <div class="version">v1.0</div>
    </div>

    <!-- Current URL Status -->
    <div class="url-status" id="urlStatus">
      <div class="loading" id="loadingIndicator">
        <div class="spinner"></div>
        <span>Analyzing current page...</span>
      </div>
      
      <div class="status-result" id="statusResult" style="display: none;">
        <div class="status-header">
          <span class="status-icon" id="statusIcon">🔒</span>
          <div class="status-text">
            <div class="status-label" id="statusLabel">Safe</div>
            <div class="confidence" id="confidenceText">95% confidence</div>
          </div>
        </div>
        <div class="url-display" id="urlDisplay">
          <span id="currentUrl">https://example.com</span>
        </div>
      </div>
    </div>

    <!-- Risk Details -->
    <div class="risk-details" id="riskDetails" style="display: none;">
      <h3>Risk Analysis</h3>
      <div class="risk-metrics">
        <div class="metric">
          <label>Phishing Probability:</label>
          <span id="phishingProb">5%</span>
        </div>
        <div class="metric">
          <label>Risk Level:</label>
          <span id="riskLevel" class="risk-badge">VERY_LOW</span>
        </div>
        <div class="metric">
          <label>Last Checked:</label>
          <span id="lastChecked">Just now</span>
        </div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="quick-actions">
      <button id="recheckBtn" class="btn btn-primary">
        <span>🔄</span> Recheck URL
      </button>
      <button id="reportBtn" class="btn btn-secondary">
        <span>⚠️</span> Report Issue
      </button>
    </div>

    <!-- Manual URL Check -->
    <div class="manual-check">
      <h3>Check Any URL</h3>
      <div class="input-group">
        <input type="text" id="manualUrl" placeholder="Enter URL to check..." />
        <button id="checkBtn" class="btn btn-check">Check</button>
      </div>
      <div class="manual-result" id="manualResult" style="display: none;">
        <div class="result-content" id="manualResultContent"></div>
      </div>
    </div>

    <!-- Statistics -->
    <div class="stats">
      <h3>Protection Stats</h3>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-number" id="urlsChecked">0</div>
          <div class="stat-label">URLs Checked</div>
        </div>
        <div class="stat-item">
          <div class="stat-number" id="threatsBlocked">0</div>
          <div class="stat-label">Threats Blocked</div>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div class="settings">
      <div class="setting-item">
        <label class="switch">
          <input type="checkbox" id="autoCheck" checked>
          <span class="slider"></span>
        </label>
        <span class="setting-label">Auto-check websites</span>
      </div>
      <div class="setting-item">
        <label class="switch">
          <input type="checkbox" id="showWarnings" checked>
          <span class="slider"></span>
        </label>
        <span class="setting-label">Show warning banners</span>
      </div>
    </div>

    <!-- Footer -->
    <div class="footer">
      <div class="footer-links">
        <a href="#" id="helpLink">Help</a>
        <a href="#" id="privacyLink">Privacy</a>
        <a href="#" id="aboutLink">About</a>
      </div>
    </div>
  </div>

  <script src="js/popup.js"></script>
</body>
</html>'''

with open('phishing-detector/extension/popup.html', 'w') as f:
    f.write(popup_html)

# Create popup.css (Popup Styles)
popup_css = '''/* Phishing Shield Popup Styles */

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  width: 380px;
  max-height: 600px;
  background: #f8f9fa;
  color: #333;
  font-size: 14px;
  line-height: 1.5;
}

.popup-container {
  display: flex;
  flex-direction: column;
}

/* Header */
.header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 16px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
}

.shield-icon {
  font-size: 24px;
}

.logo h1 {
  font-size: 18px;
  font-weight: 600;
}

.version {
  font-size: 12px;
  opacity: 0.8;
  background: rgba(255,255,255,0.2);
  padding: 2px 8px;
  border-radius: 12px;
}

/* URL Status */
.url-status {
  padding: 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
}

.loading {
  display: flex;
  align-items: center;
  gap: 12px;
  justify-content: center;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #f3f3f3;
  border-top: 2px solid #667eea;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.status-result {
  text-align: center;
}

.status-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.status-icon {
  font-size: 32px;
  flex-shrink: 0;
}

.status-text {
  flex-grow: 1;
  text-align: left;
}

.status-label {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 4px;
}

.confidence {
  font-size: 13px;
  color: #6c757d;
}

.url-display {
  background: #f8f9fa;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px solid #e9ecef;
  margin-top: 8px;
}

.url-display span {
  font-family: monospace;
  font-size: 12px;
  color: #495057;
  word-break: break-all;
}

/* Status Colors */
.status-safe { color: #28a745; }
.status-warning { color: #ffc107; }
.status-danger { color: #dc3545; }
.status-unknown { color: #6c757d; }

/* Risk Details */
.risk-details {
  padding: 16px 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
}

.risk-details h3 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 12px;
  color: #495057;
}

.risk-metrics {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.metric label {
  font-size: 13px;
  color: #6c757d;
}

.risk-badge {
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.risk-very_low { background: #d4edda; color: #155724; }
.risk-low { background: #fff3cd; color: #856404; }
.risk-medium { background: #f8d7da; color: #721c24; }
.risk-high { background: #f5c6cb; color: #721c24; }

/* Quick Actions */
.quick-actions {
  padding: 16px 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
  display: flex;
  gap: 8px;
}

/* Manual Check */
.manual-check {
  padding: 16px 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
}

.manual-check h3 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 12px;
  color: #495057;
}

.input-group {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.input-group input {
  flex-grow: 1;
  padding: 8px 12px;
  border: 1px solid #ced4da;
  border-radius: 4px;
  font-size: 13px;
}

.input-group input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.25);
}

/* Buttons */
.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
  text-decoration: none;
}

.btn-primary {
  background: #667eea;
  color: white;
  flex: 1;
}

.btn-primary:hover {
  background: #5a67d8;
  transform: translateY(-1px);
}

.btn-secondary {
  background: #6c757d;
  color: white;
  flex: 1;
}

.btn-secondary:hover {
  background: #545b62;
  transform: translateY(-1px);
}

.btn-check {
  background: #28a745;
  color: white;
  padding: 8px 16px;
}

.btn-check:hover {
  background: #218838;
}

/* Manual Result */
.manual-result {
  padding: 12px;
  background: #f8f9fa;
  border-radius: 6px;
  border: 1px solid #e9ecef;
}

/* Statistics */
.stats {
  padding: 16px 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
}

.stats h3 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 12px;
  color: #495057;
}

.stats-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.stat-item {
  text-align: center;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 6px;
}

.stat-number {
  font-size: 24px;
  font-weight: 700;
  color: #667eea;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 12px;
  color: #6c757d;
}

/* Settings */
.settings {
  padding: 16px 20px;
  background: white;
  border-bottom: 1px solid #e9ecef;
}

.setting-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.setting-item:last-child {
  margin-bottom: 0;
}

.setting-label {
  font-size: 13px;
  color: #495057;
}

/* Toggle Switch */
.switch {
  position: relative;
  display: inline-block;
  width: 44px;
  height: 24px;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #ccc;
  transition: .4s;
  border-radius: 24px;
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked + .slider {
  background-color: #667eea;
}

input:checked + .slider:before {
  transform: translateX(20px);
}

/* Footer */
.footer {
  padding: 12px 20px;
  background: #f8f9fa;
  border-top: 1px solid #e9ecef;
}

.footer-links {
  display: flex;
  justify-content: center;
  gap: 16px;
}

.footer-links a {
  font-size: 12px;
  color: #6c757d;
  text-decoration: none;
}

.footer-links a:hover {
  color: #495057;
}

/* Scrollbar */
.popup-container {
  max-height: 600px;
  overflow-y: auto;
}

.popup-container::-webkit-scrollbar {
  width: 6px;
}

.popup-container::-webkit-scrollbar-track {
  background: #f1f1f1;
}

.popup-container::-webkit-scrollbar-thumb {
  background: #c1c1c1;
  border-radius: 3px;
}

.popup-container::-webkit-scrollbar-thumb:hover {
  background: #a8a8a8;
}'''

with open('phishing-detector/extension/css/popup.css', 'w') as f:
    f.write(popup_css)

print("✅ Created popup.html and css/popup.css")
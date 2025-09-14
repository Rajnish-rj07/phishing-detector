# Phishing Shield Browser Extension

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

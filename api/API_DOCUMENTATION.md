# Phishing Detector API Documentation

## Overview

The Phishing Detector API provides advanced phishing detection capabilities with real-time model updates, certificate analysis, detailed threat reporting, and integration with external threat intelligence sources.

## Base URL

```
http://localhost:5000
```

## Endpoints

### Health Check

```
GET /health
```

Returns the current status of the API.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-07-01T12:00:00Z"
}
```

### URL Prediction

```
POST /predict
```

Analyzes a URL for phishing indicators using multiple detection methods.

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | Yes | The URL to analyze |
| check_external_apis | boolean | No | Whether to check external APIs (default: true) |

**Example Request:**
```json
{
  "url": "https://example.com",
  "check_external_apis": true
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "prediction": 0,
  "risk_level": "LOW",
  "confidence": 0.2,
  "probability_phishing": 0.2,
  "probability_legitimate": 0.8,
  "threat_details": [
    {
      "type": "suspicious_keywords",
      "description": "URL contains suspicious keywords often used in phishing",
      "severity": "high"
    }
  ],
  "certificate_analysis": {
    "valid": true,
    "issuer": "Let's Encrypt Authority X3",
    "valid_until": "2023-12-31T23:59:59Z",
    "is_expired": false,
    "is_self_signed": false,
    "is_short_lived": false
  },
  "external_api_results": {
    "virustotal": {
      "is_malicious": false,
      "malicious": 0,
      "suspicious": 0,
      "harmless": 67
    },
    "google_safebrowsing": {
      "is_malicious": false
    },
    "urlscan": {
      "is_malicious": false,
      "categories": []
    }
  },
  "analysis_timestamp": "2023-07-01T12:00:00Z"
}
```

### Email Safety Check

```
POST /check_email
```

Analyzes an email address for phishing indicators.

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | The email address to analyze |

**Example Request:**
```json
{
  "email": "example@example.com"
}
```

**Response:**
```json
{
  "email": "example@example.com",
  "prediction": 0,
  "risk_level": "LOW",
  "confidence": 0.1,
  "probability_phishing": 0.1,
  "probability_legitimate": 0.9,
  "analysis_timestamp": "2023-07-01T12:00:00Z"
}
```

## Risk Levels

The API returns one of the following risk levels:

- `VERY_LOW`: Minimal risk detected
- `LOW`: Some minor risk factors detected
- `MODERATE`: Several risk factors detected
- `HIGH`: Significant risk factors detected
- `VERY_HIGH`: Critical risk factors detected

## External API Integrations

The API integrates with the following external threat intelligence sources:

1. **VirusTotal** - Checks URL against multiple antivirus engines
2. **Google Safe Browsing** - Checks URL against Google's database of unsafe web resources
3. **URLScan.io** - Provides URL scanning and analysis

## Certificate Analysis

For HTTPS URLs, the API performs SSL/TLS certificate analysis, checking for:

- Certificate validity
- Expiration status
- Self-signed certificates
- Short-lived certificates (unusual validity periods)
- Certificate issuer information

## Real-time Model Updates

The API includes a mechanism for real-time model updates based on feedback data. The model is automatically updated at regular intervals to improve detection accuracy.
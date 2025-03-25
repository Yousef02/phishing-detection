# PhishGuard: Browser-Based Phishing Detection (under construction!)

PhishGuard is a Chrome extension developed as my senior project that provides real-time protection against phishing attempts through URL and content analysis.

## Features

- **URL Analysis**: Detects suspicious domain patterns, TLDs, encoded characters, and other common phishing indicators
- **Content Analysis**: Identifies sensitive form fields, suspicious submission targets, and urgency language
- **Browser History Integration**: Flags first-time domain visits as potential security risks
- **Real-time Alerts**: Displays color-coded warning banners based on risk severity
- **Detailed Analysis**: Provides comprehensive risk scoring and justification through the extension popup

## Technical Implementation

### Architecture

PhishGuard implements a dual-layer security approach:

1. **Background Service Worker (background.js)**
   - Analyzes URL characteristics
   - Checks browser history for domain familiarity
   - Coordinates communication between components
   - Maintains risk scoring system

2. **Content Script (content.js)**
   - Analyzes page DOM elements and content
   - Detects forms requesting sensitive information
   - Identifies brand impersonation attempts
   - Injects warning banners when needed

3. **User Interface (popup.html/js)**
   - Displays comprehensive risk analysis
   - Provides detailed breakdown of detected issues
   - Shows domain familiarity metrics

### Key Components

- **Risk Scoring System**: Weighted evaluation of multiple security indicators
- **History API Integration**: Detects first-time visits to domains
- **Content Analysis Engine**: DOM-based security evaluation
- **Real-time Notification System**: Contextual security alerts

## Installation

1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in upper right)
4. Click "Load unpacked" and select the extension directory
5. The PhishGuard icon should appear in your browser toolbar

## Usage

- PhishGuard runs automatically as you browse
- Warning banners appear on potentially dangerous sites
- Click the extension icon for detailed analysis
- Use the "Detailed Check" button for additional information

## Permissions

The extension requires the following permissions:
- `activeTab`: To analyze the current page
- `storage`: To store settings and historical data
- `webNavigation`: To detect when new pages are loaded
- `webRequest`: To monitor network requests
- `history`: To check if domains have been visited before

## Future Development

- External API connections to reputation databases
- Advanced visual element analysis
- Personalized protection based on user behavior

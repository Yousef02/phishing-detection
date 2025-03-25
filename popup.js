/**
 * PhishGuard Popup Script
 * 
 * This script controls the popup UI of the extension.
 * It displays the phishing analysis results and provides user controls.
 */

// DOM elements
let elements = {};

/**
 * Initialize the popup when the document is ready
 */
document.addEventListener('DOMContentLoaded', () => {
  // Get DOM references
  cacheElements();
  
  // Initialize the popup UI
  initializePopup();
  
  // Set up event listeners
  setupEventListeners();
});

/**
 * Cache DOM element references for better performance
 */
function cacheElements() {
  elements = {
    loading: document.getElementById('loading'),
    results: document.getElementById('results'),
    detailedResults: document.getElementById('detailed-results'),
    riskLevel: document.getElementById('risk-level'),
    riskScore: document.getElementById('risk-score'),
    summaryText: document.getElementById('summary-text'),
    issuesList: document.getElementById('issues-list'),
    detailedCheckBtn: document.getElementById('detailed-check'),
    reportSiteBtn: document.getElementById('report-site'),
    settingsLink: document.getElementById('settings-link')
  };
}

// In popup.js
function initializePopup() {
  // Show loading state
  showLoading(true);
  
  // Get the active tab
  chrome.tabs.query({active: true, currentWindow: true}, tabs => {
    if (tabs.length === 0) return;
    
    const currentTab = tabs[0];
    const url = currentTab.url;
    
    console.log("Popup requesting analysis for:", url);
    
    // Request analysis of the current URL
    chrome.runtime.sendMessage(
      {action: 'analyzeCurrentUrl', url},
      response => {
        console.log("Popup received response:", response);
        if (response && response.analysis) {
          displayAnalysisResults(response.analysis);
        } else {
          showError();
        }
      }
    );
  });
}

/**
 * Set up all UI event listeners
 */
function setupEventListeners() {
  // Detailed Check button
  elements.detailedCheckBtn.addEventListener('click', performDetailedCheck);
  
  // Report Site button
  elements.reportSiteBtn.addEventListener('click', reportSite);
  
  // Settings link
  elements.settingsLink.addEventListener('click', openSettings);
}

/**
 * Display the analysis results in the popup
 * @param {Object} analysis - The analysis results from the background script
 */
function displayAnalysisResults(analysis) {
  const { riskLevel, score, issues } = analysis;
  
  // Update risk level and score display
  elements.riskLevel.textContent = `Risk Level: ${riskLevel}`;
  elements.riskLevel.className = `risk-level ${riskLevel.toLowerCase()}`;
  elements.riskScore.textContent = `Score: ${score}`;
  
  // Set summary text based on risk level
  switch(riskLevel) {
    case 'SAFE':
      elements.summaryText.textContent = 'This site appears to be safe. No phishing indicators detected.';
      break;
    case 'LOW':
      elements.summaryText.textContent = 'This site has some minor suspicious characteristics, but is likely safe.';
      break;
    case 'MEDIUM':
      elements.summaryText.textContent = 'This site has multiple suspicious characteristics. Be careful with sensitive information.';
      break;
    case 'HIGH':
      elements.summaryText.textContent = 'WARNING: This site has strong phishing indicators. Avoid entering personal information.';
      break;
    default:
      elements.summaryText.textContent = 'Analysis complete.';
  }
  
  // Populate issues list if there are any
  if (issues && issues.length > 0) {
    elements.issuesList.innerHTML = '';
    elements.issuesList.classList.remove('hidden');
    
    issues.forEach(issue => {
      const li = document.createElement('li');
      li.textContent = issue;
      elements.issuesList.appendChild(li);
    });
  } else {
    elements.issuesList.classList.add('hidden');
  }
  
  // Hide loading and show results
  showLoading(false);
}

/**
 * Show browser internal page info
 */
function showBrowserPageInfo() {
  elements.riskLevel.textContent = 'Internal Browser Page';
  elements.riskLevel.className = 'risk-level safe';
  elements.riskScore.textContent = 'N/A';
  elements.summaryText.textContent = 'This is a browser internal page which cannot be analyzed.';
  elements.issuesList.classList.add('hidden');
  
  // Hide loading and show results
  showLoading(false);
}

/**
 * Show error state if analysis fails
 */
function showError() {
  elements.riskLevel.textContent = 'Analysis Error';
  elements.riskLevel.className = 'risk-level';
  elements.riskScore.textContent = 'Error';
  elements.summaryText.textContent = 'An error occurred while analyzing this page. Please try again.';
  elements.issuesList.classList.add('hidden');
  
  // Hide loading and show results
  showLoading(false);
}

/**
 * Toggle loading state
 * @param {boolean} isLoading - Whether to show loading state
 */
function showLoading(isLoading) {
  if (isLoading) {
    elements.loading.classList.remove('hidden');
    elements.results.classList.add('hidden');
    elements.detailedResults.classList.add('hidden');
  } else {
    elements.loading.classList.add('hidden');
    elements.results.classList.remove('hidden');
  }
}

/**
 * Perform a detailed check of the current site
 * This would connect to external APIs for more analysis
 */
function performDetailedCheck() {
  // Show loading state
  showLoading(true);
  
  // Get the current tab URL
  chrome.tabs.query({active: true, currentWindow: true}, tabs => {
    if (tabs.length === 0) return;
    
    const url = tabs[0].url;
    
    // Request detailed analysis
    chrome.runtime.sendMessage(
      {action: 'detailedCheck', url},
      response => {
        // Hide loading spinner
        showLoading(false);
        
        if (response) {
          // In a full implementation, you would display the detailed analysis here
          // using the additionalInfo property from the response
          
          // For now, we'll just show a mock detailed view
          showDetailedResults(response);
        } else {
          showError();
        }
      }
    );
  });
}

/**
 * Display detailed results in the popup
 * @param {Object} response - The detailed analysis response
 */
function showDetailedResults(response) {
  // Hide the main results and show detailed results
  elements.results.classList.add('hidden');
  elements.detailedResults.classList.remove('hidden');
  
  // Create detailed results content
  elements.detailedResults.innerHTML = `
    <div class="header">
      <div class="logo">
        <img src="images/icon48.png" alt="PhishGuard Logo">
        <h1>Detailed Analysis</h1>
      </div>
      <button id="back-button" style="background: transparent; color: white; font-size: 20px; padding: 0 5px;">←</button>
    </div>
    
    <div style="padding: 15px;">
      <h3 style="margin-bottom: 10px;">Advanced Security Analysis</h3>
      
      <div style="background-color: #f9f9f9; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
        <p><strong>Domain Age:</strong> ${response.additionalInfo.domainAge}</p>
        <p><strong>SSL Certificate:</strong> ${response.additionalInfo.sslValid}</p>
        <p><strong>In Known Database:</strong> ${response.additionalInfo.inPhishingDatabase}</p>
      </div>
      
      <p style="font-size: 12px; color: #666; margin-bottom: 15px;">
        Note: For a complete implementation, this would include WHOIS data, 
        SSL certificate validation, and checks against phishing databases.
      </p>
      
      <button id="back-to-summary" style="width: 100%; background-color: #2c3e50;">
        Back to Summary
      </button>
    </div>
  `;
  
  // Add event listener to back buttons
  document.getElementById('back-button').addEventListener('click', () => {
    elements.detailedResults.classList.add('hidden');
    elements.results.classList.remove('hidden');
  });
  
  document.getElementById('back-to-summary').addEventListener('click', () => {
    elements.detailedResults.classList.add('hidden');
    elements.results.classList.remove('hidden');
  });
}

/**
 * Report the current site to phishing databases
 */
function reportSite() {
  chrome.tabs.query({active: true, currentWindow: true}, tabs => {
    if (tabs.length === 0) return;
    
    const url = tabs[0].url;
    
    // Open PhishTank report page in a new tab
    // In a full implementation, you might send to your own backend or multiple services
    chrome.tabs.create({
      url: `https://www.phishtank.com/report.php?url=${encodeURIComponent(url)}`
    });
  });
}

/**
 * Open the settings page
 */
function openSettings() {
  // In a full implementation, you would have a dedicated settings page
  // For now, we'll just show an alert
  alert('Settings page would open here in a full implementation.');
  
  // Example of how to open a settings page:
  // chrome.runtime.openOptionsPage();
}
/**
 * PhishGuard Content Script
 * 
 * This script runs in the context of web pages and has access to DOM elements.
 * It analyzes page content for phishing indicators and can manipulate the DOM
 * to display warnings to users.
 * 
 * /* 
  * PHISHING DETECTION MARKERS IN THIS SCRIPT:
 * - Suspicious TLDs (.xyz, .tk, .ml, etc.)
 * - Unusually long domain names
 * - Excessive subdomains
 * - Multiple hyphens in domain
 * - Suspicious keywords (login, secure, verify, etc.)
 * - Security terms in domain (secure, security, etc.)
 * - Encoded characters in URL
 * - Extremely long alphanumeric strings
 */

// Elements commonly found in phishing pages
const SENSITIVE_FORM_FIELDS = [
  'password', 'pass', 'pwd', 'ssn', 'credit', 'card', 'cvv', 'pin', 'social'
];

// Track status to prevent duplicate warnings
let warningDisplayed = false;

/**
 * Creates and injects a warning banner at the top of the webpage
 * @param {Object} analysis - The analysis results from the background script
 */
function injectWarningBanner(analysis) {
  // Prevent duplicate warnings
  if (warningDisplayed) return;
  
  // Get the risk level from the analysis
  const { riskLevel, score, issues } = analysis;
  
  // Only warn for MEDIUM or HIGH risk levels
  if (riskLevel !== "MEDIUM" && riskLevel !== "HIGH") {
    return;
  }
  
  // Create the warning banner element
  const banner = document.createElement('div');
  banner.id = 'phishguard-warning';
  
  // Style the banner
  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    padding: '10px 15px',
    boxSizing: 'border-box',
    zIndex: '2147483647', // Maximum z-index value
    fontSize: '14px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
    fontFamily: 'Arial, sans-serif'
  });
  
  // Set banner color based on risk level
  if (riskLevel === "HIGH") {
    Object.assign(banner.style, {
      backgroundColor: '#ff3b30',
      color: 'white'
    });
  } else {
    Object.assign(banner.style, {
      backgroundColor: '#ff9500',
      color: 'white'
    });
  }
  
  // Create the content for the banner
  const warningText = document.createElement('div');
  warningText.innerHTML = `
    <strong>⚠️ PhishGuard Warning:</strong> 
    This site exhibits ${riskLevel.toLowerCase()} risk phishing characteristics.
    <span style="margin-left: 8px; font-size: 12px;">(Risk score: ${score})</span>
  `;
  
  // Create a close button
  const closeButton = document.createElement('button');
  closeButton.textContent = '✕';
  Object.assign(closeButton.style, {
    background: 'transparent',
    border: 'none',
    color: 'white',
    fontSize: '16px',
    cursor: 'pointer',
    marginLeft: '10px',
    padding: '0 5px'
  });
  
  // Add event listener to the close button
  closeButton.addEventListener('click', function() {
    banner.remove();
  });
  
  // Append elements to the banner
  banner.appendChild(warningText);
  banner.appendChild(closeButton);
  
  // Add the banner to the page
  document.body.prepend(banner);
  warningDisplayed = true;
  
  // Log the detection for debugging purposes
  console.log(`PhishGuard detected ${riskLevel} risk (${score}):`, issues);
}

/**
 * Scans the page for password fields to check for insecure forms
 * @return {Object} Form analysis results
 */
function scanForSensitiveFormFields() {
  const results = {
    hasPasswordField: false,
    hasSensitiveFields: false,
    submitURL: null,
    isSecure: window.location.protocol === 'https:',
    issues: []
  };
  
  // Find all forms on the page
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    // Check form action
    if (form.action) {
      results.submitURL = form.action;
      
      // Check if form submits to a different domain
      try {
        const formDomain = new URL(form.action).hostname;
        const pageDomain = window.location.hostname;
        
        if (formDomain !== pageDomain) {
          results.issues.push(`Form submits to different domain: ${formDomain}`);
        }
      } catch (e) {
        // Invalid URL in form action
        results.issues.push('Form has invalid submission URL');
      }
    }
    
    // Look for input fields
    const inputs = form.querySelectorAll('input');
    
    inputs.forEach(input => {
      const inputType = input.type.toLowerCase();
      const inputName = (input.name || '').toLowerCase();
      const inputId = (input.id || '').toLowerCase();
      
      // Check for password fields
      if (inputType === 'password') {
        results.hasPasswordField = true;
      }
      
      // Check for other sensitive fields
      SENSITIVE_FORM_FIELDS.forEach(term => {
        if (inputName.includes(term) || inputId.includes(term)) {
          results.hasSensitiveFields = true;
        }
      });
    });
  });
  
  // Password field on non-HTTPS is a major security issue
  if (results.hasPasswordField && !results.isSecure) {
    results.issues.push('Password field on non-HTTPS connection');
  }
  
  return results;
}

/**
 * Scans the page for common phishing content indicators
 * @return {Object} Content analysis results 
 */
function analyzePageContent() {
  const results = {
    suspiciousText: false,
    brandImpersonation: false,
    poorSpellingGrammar: false,
    urgencyLanguage: false,
    issues: []
  };
  
  // Get the visible text content from the page
  const pageText = document.body.innerText.toLowerCase();
  
  // Check for urgency language patterns
  const urgencyPhrases = [
    'act now', 'urgent', 'immediately', 'alert', 'attention', 'important', 
    'limited time', 'expire', 'suspended', 'verify now', 'verify your account',
    'unusual activity', 'suspicious activity', 'security alert'
  ];
  
  urgencyPhrases.forEach(phrase => {
    if (pageText.includes(phrase)) {
      results.urgencyLanguage = true;
      results.issues.push(`Urgency language: "${phrase}"`);
    }
  });
  
  // Check for common impersonated brands
  const commonBrands = [
    'paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 
    'bank of america', 'chase', 'wells fargo', 'citi', 'netflix'
  ];
  
  // Get all images on the page
  const images = document.querySelectorAll('img');
  let brandLogosFound = [];
  
  // Check for brand logos in images (by alt text or src)
  images.forEach(img => {
    const altText = (img.alt || '').toLowerCase();
    const src = (img.src || '').toLowerCase();
    
    commonBrands.forEach(brand => {
      if (altText.includes(brand) || src.includes(brand)) {
        brandLogosFound.push(brand);
      }
    });
  });
  
  // If logos found, check if domain matches
  if (brandLogosFound.length > 0) {
    const domain = window.location.hostname.toLowerCase();
    let brandInDomain = false;
    
    brandLogosFound.forEach(brand => {
      if (domain.includes(brand.replace(' ', ''))) {
        brandInDomain = true;
      }
    });
    
    // If brand logo found but not in domain, might be impersonation
    if (!brandInDomain) {
      results.brandImpersonation = true;
      results.issues.push(`Potential impersonation of: ${brandLogosFound.join(', ')}`);
    }
  }
  
  return results;
}

/**
 * Main function to analyze the page after it loads
 */
function analyzePage() {
  console.log("PhishGuard content script analyzing page...");
  
  // Wait for page to fully load
  if (document.readyState === 'complete') {
    runAnalysis();
  } else {
    window.addEventListener('load', runAnalysis);
  }
  
  function runAnalysis() {
    // Get form analysis
    const formAnalysis = scanForSensitiveFormFields();
    
    // Get content analysis
    const contentAnalysis = analyzePageContent();
    
    // Send results to background script
    chrome.runtime.sendMessage({
      action: 'contentAnalysis',
      url: window.location.href,
      data: {
        form: formAnalysis,
        content: contentAnalysis
      }
    });
    
    // If there are serious issues, contribute to the risk score
    const seriousIssues = [
      ...formAnalysis.issues,
      ...contentAnalysis.issues
    ];
    
    if (seriousIssues.length > 0) {
      console.log("PhishGuard detected potential issues:", seriousIssues);
    }
  }
}

/**
 * Listen for messages from the background script
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Process URL analysis results from background script
  if (message.action === 'analysisResult') {
    const analysis = message.data;
    
    // If analysis shows medium or high risk, show warning
    if (analysis.riskLevel === "MEDIUM" || analysis.riskLevel === "HIGH") {
      injectWarningBanner(analysis);
    }
    
    sendResponse({received: true});
  }
});

// Run the page analysis when script loads
analyzePage();
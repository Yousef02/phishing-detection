/**
 * PhishGuard Background Script
 * 
 * This script runs in the background and serves as the central processing unit
 * for the phishing detection extension. It analyzes URLs, communicates with the 
 * content script, and maintains the security state of visited pages.
 */

// Initialize score thresholds for risk levels
const RISK_THRESHOLDS = {
  LOW: 30,
  MEDIUM: 60,
  HIGH: 80
};

// Suspicious TLDs often used in phishing attacks
const SUSPICIOUS_TLDS = [
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'online', 'site', 'club', 'xin'
];

// Patterns commonly found in phishing URLs
const SUSPICIOUS_PATTERNS = [
  /secure/, /login/, /signin/, /verify/, /account/, /update/, /confirm/, /banking/,
  /paypal/, /apple/, /microsoft/, /google/, /facebook/, /amazon/, /netflix/,
  /\d{5,}/, // Matches 5 or more consecutive digits
  /^[a-zA-Z0-9]{25,}$/ // Extremely long alphanumeric strings
];

// Common security terms used to create fake sense of security
const SECURITY_TERMS = [
  'secure', 'security', 'authenticate', 'verification', 'confirm', 'validate', 'wallet'
];

/**
 * Analyzes a URL for potential phishing indicators
 * @param {string} url - The URL to analyze
 * @return {Object} An object containing the risk score and detected issues
 */
function analyzeUrl(url) {
  let score = 0;
  const issues = [];
  
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    
    // Check for IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      score += 40;
      issues.push("IP address used as hostname");
    }
    
    // Check TLD
    const tld = domain.split('.').pop().toLowerCase();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 15;
      issues.push(`Suspicious TLD: .${tld}`);
    }
    
    // Check domain length (extremely long domains are suspicious)
    if (domain.length > 30) {
      score += 15;
      issues.push("Unusually long domain name");
    }
    
    // Check for excessive subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 3) {
      score += 15;
      issues.push("Excessive number of subdomains");
    }
    
    // Check for hyphens (multiple hyphens often indicate typosquatting)
    if ((domain.match(/-/g) || []).length > 1) {
      score += 10;
      issues.push("Multiple hyphens in domain");
    }
    
    // Check for suspicious patterns in URL
    SUSPICIOUS_PATTERNS.forEach(pattern => {
      if (pattern.test(domain) || pattern.test(path)) {
        score += 10;
        issues.push(`Suspicious pattern detected: ${pattern}`);
      }
    });
    
    // Check for security terms in domain (often used to appear legitimate)
    SECURITY_TERMS.forEach(term => {
      if (domain.includes(term)) {
        score += 5;
        issues.push(`Security term in domain: "${term}"`);
      }
    });
    
    // Check for encoded characters in URL
    if (url.includes('%')) {
      score += 10;
      issues.push("URL contains encoded characters");
    }
    
  } catch (error) {
    console.error("Error analyzing URL:", error);
    score += 20; // Malformed URLs are suspicious
    issues.push("Malformed URL");
  }
  
  // Determine risk level based on score
  let riskLevel;
  if (score >= RISK_THRESHOLDS.HIGH) {
    riskLevel = "HIGH";
  } else if (score >= RISK_THRESHOLDS.MEDIUM) {
    riskLevel = "MEDIUM";
  } else if (score >= RISK_THRESHOLDS.LOW) {
    riskLevel = "LOW";
  } else {
    riskLevel = "SAFE";
  }
  
  return {
    score,
    issues,
    riskLevel
  };
}


/**
 * Checks browser history to determine if a site has been visited before
 * @param {string} url - The URL to check
 * @return {Promise<Object>} Visit statistics for the domain
 */
async function checkBrowserHistory(url) {
  try {
    const domain = new URL(url).hostname;
    console.log("Checking history for domain:", domain);
    
    // Search for visits to this domain in the last 90 days
    // We use a time range of 90 days (in microseconds)
    const startTime = Date.now() - (90 * 24 * 60 * 60 * 1000);
    
    // Create a query pattern for the domain
    // Note: History API uses simple string contains, so this will match 
    // any URL with this domain (including subdomains)
    const historyQuery = {
      text: domain,
      startTime: startTime,
      endTime: Date.now() - 5000, // Exclude very recent visits
      maxResults: 1000
    };
    
    // Query the browser history
    const historyItems = await chrome.history.search(historyQuery);
    
    // Filter for exact domain matches
    // This prevents example.com matching example.com.phishing.com
    const exactDomainMatches = historyItems.filter(item => {
      try {
        const itemDomain = new URL(item.url).hostname;
        const isMatch = itemDomain === domain || 
                       itemDomain.endsWith('.' + domain) ||
                       domain.endsWith('.' + itemDomain);
        
        if (isMatch) {
          console.log("Matched history item:", item.url);
        }
        
        return isMatch;
      } catch {
        return false; // Skip invalid URLs
      }
    });
    
    if (exactDomainMatches.length === 0) {
      return {
        familiar: false,
        firstVisit: true,
        visitCount: 0,
        daysSinceLastVisit: 0,
        familiarityScore: 0
      };
    }
    
    // Get most recent visit
    const visits = exactDomainMatches.map(item => item.lastVisitTime);
    const mostRecentVisit = Math.max(...visits);
    const daysSinceLastVisit = Math.floor((Date.now() - mostRecentVisit) / (24 * 60 * 60 * 1000));
    
    // Calculate a familiarity score (0-100)
    let familiarityScore = 0;
    
    // Visit count: 0-40 points (cap at 20 visits)
    const visitCount = Math.min(exactDomainMatches.length, 20);
    familiarityScore += visitCount * 2;
    
    // Recency: 0-60 points (inversely proportional to days since last visit)
    const recencyScore = daysSinceLastVisit === 0 ? 60 : Math.max(60 - daysSinceLastVisit * 2, 0);
    familiarityScore += recencyScore;
    
    return {
      familiar: true,
      firstVisit: false,
      visitCount: exactDomainMatches.length,
      daysSinceLastVisit,
      familiarityScore
    };
    
  } catch (error) {
    console.error("Error checking browser history:", error);
    return {
      familiar: false,
      firstVisit: true,
      visitCount: 0,
      error: true
    };
  }
}

/**
 * Analyzes URL with browser history information
 */
async function analyzeUrlWithHistory(url) {
  // Get the base URL analysis
  const baseAnalysis = analyzeUrl(url);
  
  // Get history data
  const familiarity = await checkBrowserHistory(url);
  
  // Adjust the score based on visit history
  let adjustedScore = baseAnalysis.score;
  
  if (familiarity.firstVisit) {
    // First visit to this site - slightly increase risk
    adjustedScore += 90; // FIXME: This is arbitrary, adjust as needed
    baseAnalysis.issues.push("First visit to this domain");
  } else {
    // Familiar site - reduce risk based on familiarity
    const reduction = Math.floor(familiarity.familiarityScore / 4);
    adjustedScore = Math.max(adjustedScore - reduction, 0);
    
    if (familiarity.familiarityScore > 70) {
      baseAnalysis.issues.push(`Frequently visited site (${familiarity.visitCount} visits)`);
    }
  }
  
  // Recalculate risk level based on adjusted score
  let riskLevel;
  if (adjustedScore >= RISK_THRESHOLDS.HIGH) {
    riskLevel = "HIGH";
  } else if (adjustedScore >= RISK_THRESHOLDS.MEDIUM) {
    riskLevel = "MEDIUM";
  } else if (adjustedScore >= RISK_THRESHOLDS.LOW) {
    riskLevel = "LOW";
  } else {
    riskLevel = "SAFE";
  }
  
  const result = {
    ...baseAnalysis,
    score: adjustedScore,
    riskLevel,
    familiarity
  };

  console.log("PhishGuard URL analysis result:", result);
  return result;
}


/**
 * Handles navigation to a new URL
 * Analyzes the URL and sends results to the content script
 */
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only process main frame navigations (not iframes)
  if (details.frameId !== 0) return;
  
  const tabId = details.tabId;
  const url = details.url;
  
  // Skip browser internal pages and extensions
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return;
  }
  
  // Analyze the URL for phishing indicators with history
  const analysis = await analyzeUrlWithHistory(url);
  
  // Store the analysis results
  chrome.storage.local.set({
    [url]: {
      analysis,
      timestamp: Date.now()
    }
  });
  
  // Send results to content script
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'analysisResult',
      data: analysis
    });
  } catch (error) {
    // Tab may not be ready yet or content script not loaded
    console.log("Error sending message to content script:", error);
  }
});

/**
 * Listen for messages from popup or content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  
  // Handle request to analyze current URL
  if (message.action === 'analyzeCurrentUrl') {
    const url = message.url;
    // With this (need to handle the Promise):
    analyzeUrlWithHistory(url).then(analysis => {
      console.log("Sending analysis to popup:", analysis);
      sendResponse({analysis});
    });
    return true; // Indicates we will respond asynchronously
  }
  
  // Handle request for detailed site check
  if (message.action === 'detailedCheck') {
    // In a full implementation, you might:
    // 1. Check domain age via WHOIS API
    // 2. Check against phishing databases
    // 3. Analyze SSL certificate information
    // 4. Check for redirects
    
    // For now, we'll just return the basic analysis
    const url = message.url;
    const analysis = analyzeUrl(url);
    
    // Add a simulated delay to represent a more detailed check
    setTimeout(() => {
      sendResponse({
        analysis,
        additionalInfo: {
          domainAge: "Unknown (API integration required)",
          sslValid: "Unknown (API integration required)",
          inPhishingDatabase: "Unknown (API integration required)"
        }
      });
    }, 1000);
    
    // Return true to indicate we'll respond asynchronously
    return true;
  }
});

/**
 * Initialize extension data on installation
 */
chrome.runtime.onInstalled.addListener(() => {
  // Set up initial storage
  chrome.storage.local.set({
    settings: {
      notificationsEnabled: true,
      autoBlockHigh: false,
      collectAnonymousStats: false
    },
    detectedSites: []
  });
  
  console.log("PhishGuard extension installed successfully");
});


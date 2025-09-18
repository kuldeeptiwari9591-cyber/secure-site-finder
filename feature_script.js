// Feature Script - Basic URL Analysis Features
// Client-side feature extraction functions

// 1. URL Length Check
function checkUrlLength(url) {
    // URLs longer than 75 characters are often suspicious
    return url.length > 75;
}

// 2. Presence of @ Symbol
function checkAtSymbol(url) {
    // @ symbol in URL can be used to trick users about the destination
    return url.includes('@');
}

// 3. Presence of // beyond protocol
function checkDoubleSlash(url) {
    // Count occurrences of //
    const matches = url.match(/\/\//g);
    // Should only appear once after protocol (http:// or https://)
    return matches && matches.length > 1;
}

// 4. Number of dots in domain
function checkDomainDots(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const dots = (hostname.match(/\./g) || []).length;
        // More than 3 dots in domain is suspicious (e.g., sub.sub.sub.domain.com)
        return dots > 3;
    } catch (e) {
        return true; // Invalid URL format is suspicious
    }
}

// 5. Hyphen count (-)
function checkHyphenCount(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const hyphens = (hostname.match(/-/g) || []).length;
        // More than 3 hyphens in domain is suspicious
        return hyphens > 3;
    } catch (e) {
        return true;
    }
}

// 6. Suspicious keywords in URL
function checkSuspiciousKeywords(url) {
    const suspiciousKeywords = [
        'login', 'secure', 'banking', 'paypal', 'ebay', 'amazon', 'microsoft',
        'google', 'facebook', 'twitter', 'instagram', 'netflix', 'apple',
        'verify', 'confirm', 'update', 'suspend', 'urgent', 'immediate',
        'click', 'here', 'now', 'limited', 'offer', 'free', 'winner',
        'congratulations', 'security', 'alert', 'warning', 'account'
    ];
    
    const lowerUrl = url.toLowerCase();
    return suspiciousKeywords.some(keyword => lowerUrl.includes(keyword));
}

// 7. URL Encoding Check
function checkUrlEncoding(url) {
    // Check for common URL encoding patterns that might hide malicious content
    const encodingPatterns = [
        /%20/g, // encoded space
        /%3D/g, // encoded =
        /%3F/g, // encoded ?
        /%26/g, // encoded &
        /%2F/g, // encoded /
        /%3A/g  // encoded :
    ];
    
    let encodingCount = 0;
    encodingPatterns.forEach(pattern => {
        const matches = url.match(pattern);
        if (matches) encodingCount += matches.length;
    });
    
    // More than 5 encoded characters is suspicious
    return encodingCount > 5;
}

// 8. URL Shortener Check
function checkUrlShortener(url) {
    const shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
        'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bl.ink',
        'lnkd.in', 'rebrand.ly', 'clck.ru', 'short.io',
        'tiny.cc', 'rb.gy', 'cutt.ly', 'bitly.com'
    ];
    
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        return shorteners.some(shortener => hostname.includes(shortener));
    } catch (e) {
        return false;
    }
}

// 9. Special Character Count in URL
function checkSpecialCharCount(url) {
    // Count special characters that might indicate obfuscation
    const specialChars = url.match(/[!@#$%^&*()_+=\[\]{}|;:,.<>?]/g);
    const count = specialChars ? specialChars.length : 0;
    
    // More than 10 special characters is suspicious
    return count > 10;
}

// 10. URL Path Length
function checkUrlPathLength(url) {
    try {
        const urlObj = new URL(url);
        const path = urlObj.pathname;
        // Paths longer than 100 characters are suspicious
        return path.length > 100;
    } catch (e) {
        return true;
    }
}

// 11. Excessive Parameters in URL
function checkExcessiveParams(url) {
    try {
        const urlObj = new URL(url);
        const params = urlObj.searchParams;
        const paramCount = Array.from(params).length;
        
        // More than 10 parameters is suspicious
        return paramCount > 10;
    } catch (e) {
        return true;
    }
}

// 12. Embedded HTTP inside HTTPS path
function checkEmbeddedHttp(url) {
    // Check if HTTP appears in the path of an HTTPS URL
    if (url.startsWith('https://')) {
        const pathPart = url.substring(8); // Remove https://
        return pathPart.includes('http://');
    }
    return false;
}

// 13. Presence of IP address in URL
function checkIpAddress(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        
        // IPv4 pattern
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        
        // IPv6 pattern (basic)
        const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
        
        return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
    } catch (e) {
        return false;
    }
}

// 14. Port usage in URL
function checkPortUsage(url) {
    try {
        const urlObj = new URL(url);
        const port = urlObj.port;
        
        // Check for non-standard ports
        if (port && port !== '') {
            const portNum = parseInt(port);
            // Standard ports: 80 (HTTP), 443 (HTTPS), 21 (FTP), 22 (SSH)
            const standardPorts = [21, 22, 80, 443];
            return !standardPorts.includes(portNum);
        }
        return false;
    } catch (e) {
        return false;
    }
}

// 15. HTTPS / SSL presence check
function checkHttpsPresence(url) {
    // Return true if HTTPS is NOT present (which is suspicious for sensitive sites)
    return !url.startsWith('https://');
}

// Additional utility functions

// Analyze domain age (requires external API - placeholder)
function getDomainAge(domain) {
    // This would typically call a WHOIS API
    // For now, return a placeholder
    return new Promise((resolve) => {
        // Simulate API call delay
        setTimeout(() => {
            resolve({
                ageInDays: Math.floor(Math.random() * 3650), // Random age up to 10 years
                isNew: Math.random() > 0.7 // 30% chance of being "new"
            });
        }, 1000);
    });
}

// Check if domain is in blacklist (requires external API - placeholder)
function checkDomainBlacklist(domain) {
    return new Promise((resolve) => {
        // Simulate API call
        setTimeout(() => {
            resolve({
                isBlacklisted: Math.random() > 0.9, // 10% chance of being blacklisted
                source: 'PhishTank'
            });
        }, 800);
    });
}

// Comprehensive URL analysis function
function analyzeUrlFeatures(url) {
    const features = {
        // Basic features (synchronous)
        urlLength: checkUrlLength(url),
        hasAtSymbol: checkAtSymbol(url),
        hasDoubleSlash: checkDoubleSlash(url),
        domainDots: checkDomainDots(url),
        hyphenCount: checkHyphenCount(url),
        suspiciousKeywords: checkSuspiciousKeywords(url),
        urlEncoding: checkUrlEncoding(url),
        isShortener: checkUrlShortener(url),
        specialCharCount: checkSpecialCharCount(url),
        pathLength: checkUrlPathLength(url),
        excessiveParams: checkExcessiveParams(url),
        embeddedHttp: checkEmbeddedHttp(url),
        hasIpAddress: checkIpAddress(url),
        hasPort: checkPortUsage(url),
        missingHttps: checkHttpsPresence(url)
    };
    
    return features;
}

// Calculate basic risk score
function calculateBasicRiskScore(features) {
    let riskFactors = 0;
    const totalFeatures = Object.keys(features).length;
    
    Object.values(features).forEach(value => {
        if (value === true) riskFactors++;
    });
    
    return Math.round((riskFactors / totalFeatures) * 100);
}

// Get risk assessment
function getRiskAssessment(riskScore) {
    if (riskScore < 20) {
        return {
            level: 'Low',
            color: 'green',
            message: 'This URL appears to have minimal risk factors.'
        };
    } else if (riskScore < 50) {
        return {
            level: 'Medium',
            color: 'yellow',
            message: 'This URL has some suspicious characteristics. Exercise caution.'
        };
    } else if (riskScore < 80) {
        return {
            level: 'High',
            color: 'orange',
            message: 'This URL shows multiple suspicious patterns. Avoid if possible.'
        };
    } else {
        return {
            level: 'Critical',
            color: 'red',
            message: 'This URL is highly suspicious and likely malicious. Do not visit.'
        };
    }
}

// Export functions for use in main script
if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = {
        checkUrlLength,
        checkAtSymbol,
        checkDoubleSlash,
        checkDomainDots,
        checkHyphenCount,
        checkSuspiciousKeywords,
        checkUrlEncoding,
        checkUrlShortener,
        checkSpecialCharCount,
        checkUrlPathLength,
        checkExcessiveParams,
        checkEmbeddedHttp,
        checkIpAddress,
        checkPortUsage,
        checkHttpsPresence,
        analyzeUrlFeatures,
        calculateBasicRiskScore,
        getRiskAssessment
    };
} else {
    // Browser environment - functions are already globally available
    window.FeatureAnalysis = {
        analyzeUrlFeatures,
        calculateBasicRiskScore,
        getRiskAssessment
    };
}
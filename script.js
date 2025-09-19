// PhishGuard - Main JavaScript File
// Handles UI interactions, quiz functionality, and API bridge

// Global Variables
let currentQuestionIndex = 0;
let currentSetIndex = 0;
let score = 0;
let userAnswers = [];
let analysisHistory = [];

// Quiz Data - 5 sets of 5 questions each
const quizSets = [
    // Set 1: Basic Phishing Recognition
    [
        {
            question: "Which of these is a common sign of a phishing email?",
            options: ["Professional formatting", "Urgent language demanding immediate action", "Personalized greeting", "Company logo"],
            correct: 1,
            explanation: "Phishing emails often use urgent language to pressure victims into acting quickly without thinking."
        },
        {
            question: "What should you do if you receive a suspicious email asking for your password?",
            options: ["Reply with your password", "Click the link to verify", "Delete the email and report it", "Forward it to friends"],
            correct: 2,
            explanation: "Never provide passwords via email. Delete suspicious emails and report them to your IT department."
        },
        {
            question: "A legitimate bank email will never:",
            options: ["Include their logo", "Ask for account verification via email", "Have proper grammar", "Include contact information"],
            correct: 1,
            explanation: "Legitimate financial institutions never ask for account verification or sensitive information via email."
        },
        {
            question: "What is the safest way to visit your bank's website?",
            options: ["Click links in emails", "Type the URL directly", "Use search engines", "Follow social media links"],
            correct: 1,
            explanation: "Always type the URL directly or use bookmarks to avoid malicious links."
        },
        {
            question: "Which URL looks most suspicious?",
            options: ["https://amazon.com", "https://microsoft.com", "https://bank-security-update.net", "https://google.com"],
            correct: 2,
            explanation: "The URL 'bank-security-update.net' is suspicious as it's not an official bank domain."
        }
    ],
    // Set 2: URL Analysis
    [
        {
            question: "Which URL element indicates a secure connection?",
            options: ["www", "http://", "https://", ".com"],
            correct: 2,
            explanation: "HTTPS indicates a secure, encrypted connection between your browser and the website."
        },
        {
            question: "What's wrong with this URL: http://paypal-security.tk/login?",
            options: ["Nothing wrong", "Wrong domain and no HTTPS", "Too long", "Has numbers"],
            correct: 1,
            explanation: "The URL uses an unofficial domain (.tk) and lacks HTTPS encryption for a financial site."
        },
        {
            question: "A URL with many redirects is:",
            options: ["Always safe", "Potentially suspicious", "Faster", "More secure"],
            correct: 1,
            explanation: "Multiple redirects can be used to hide the final malicious destination."
        },
        {
            question: "Which is more trustworthy?",
            options: ["bit.ly/secure-bank", "https://chase.com/login", "tinyurl.com/bank", "short.link/banking"],
            correct: 1,
            explanation: "Official bank domains are more trustworthy than shortened URLs which can hide the real destination."
        },
        {
            question: "IP addresses in URLs instead of domain names are:",
            options: ["More secure", "Faster", "Often suspicious", "Always legitimate"],
            correct: 2,
            explanation: "Legitimate websites rarely use IP addresses directly; this is often a sign of malicious activity."
        }
    ],
    // Set 3: Email Security
    [
        {
            question: "What indicates a potentially fake sender address?",
            options: ["@company.com", "@company-security.info", "@gmail.com", "@outlook.com"],
            correct: 1,
            explanation: "Fake domains often add words like 'security' to appear legitimate while using different TLDs."
        },
        {
            question: "Which attachment type is most dangerous?",
            options: [".pdf", ".txt", ".exe", ".jpg"],
            correct: 2,
            explanation: "Executable files (.exe) can install malware on your computer and should be treated with extreme caution."
        },
        {
            question: "A legitimate company email will typically:",
            options: ["Have spelling errors", "Use official domain", "Request passwords", "Threaten account closure"],
            correct: 1,
            explanation: "Legitimate companies use their official domains and maintain professional communication standards."
        },
        {
            question: "What should you verify before clicking email links?",
            options: ["Sender's name only", "Email subject", "Hover preview of destination", "Time received"],
            correct: 2,
            explanation: "Always hover over links to preview the actual destination URL before clicking."
        },
        {
            question: "Multi-factor authentication (MFA) helps prevent:",
            options: ["All cyberattacks", "Account compromise even with stolen passwords", "Email delivery", "Website loading"],
            correct: 1,
            explanation: "MFA adds an extra security layer, making it much harder for attackers to access accounts even with stolen passwords."
        }
    ],
    // Set 4: Social Engineering
    [
        {
            question: "Social engineering attacks primarily target:",
            options: ["Computer systems", "Network infrastructure", "Human psychology", "Software vulnerabilities"],
            correct: 2,
            explanation: "Social engineering exploits human psychology and trust rather than technical vulnerabilities."
        },
        {
            question: "What's a common pretext used in phishing calls?",
            options: ["Weather updates", "IT support needing access", "Recipe sharing", "Sports scores"],
            correct: 1,
            explanation: "Attackers often impersonate IT support to gain trust and convince victims to provide access credentials."
        },
        {
            question: "Which creates urgency to pressure victims?",
            options: ["'Review when convenient'", "'Account will be closed in 24 hours'", "'Optional update available'", "'Thank you for your business'"],
            correct: 1,
            explanation: "Creating false urgency pressures victims to act quickly without properly verifying the request."
        },
        {
            question: "Authority figures are impersonated because:",
            options: ["They have good fashion sense", "People are more likely to comply", "They know technology", "They work remotely"],
            correct: 1,
            explanation: "People tend to comply with requests from perceived authority figures without questioning them."
        },
        {
            question: "What should you do if someone claims to be from your bank?",
            options: ["Give them your account number", "Hang up and call the bank directly", "Provide your PIN for verification", "Transfer money immediately"],
            correct: 1,
            explanation: "Always verify identity through independent channels before providing any sensitive information."
        }
    ],
    // Set 5: Advanced Threats
    [
        {
            question: "What is spear phishing?",
            options: ["Fishing with spears", "Generic mass emails", "Targeted attacks using personal information", "Email encryption"],
            correct: 2,
            explanation: "Spear phishing uses personal information to create highly targeted and convincing attacks."
        },
        {
            question: "Business Email Compromise (BEC) typically targets:",
            options: ["Random consumers", "Financial departments and executives", "Social media users", "Online gamers"],
            correct: 1,
            explanation: "BEC attacks target employees who handle finances or have authority to approve transactions."
        },
        {
            question: "Watering hole attacks involve:",
            options: ["Contaminating water supplies", "Compromising websites that targets frequently visit", "Fishing near water holes", "Flooding networks"],
            correct: 1,
            explanation: "Attackers compromise legitimate websites that their targets are likely to visit."
        },
        {
            question: "What makes deepfake technology dangerous for phishing?",
            options: ["It's expensive", "Creates convincing fake audio/video", "Only works on computers", "Requires special software"],
            correct: 1,
            explanation: "Deepfakes can create convincing fake audio or video content to impersonate trusted individuals."
        },
        {
            question: "Zero-day phishing attacks exploit:",
            options: ["Old vulnerabilities", "Unknown vulnerabilities", "Password weaknesses", "Network slowness"],
            correct: 1,
            explanation: "Zero-day attacks exploit previously unknown vulnerabilities before patches are available."
        }
    ]
];

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadAnalysisHistory();
    displayThreatFeed();
});

// Initialize the application
function initializeApp() {
    initializeQuiz();
    setupEventListeners();
}

// Setup event listeners
function setupEventListeners() {
    // URL input enter key handler
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzeURL();
            }
        });
    }
}

// Scroll to detector section
function scrollToDetector() {
    document.getElementById('detector').scrollIntoView({ behavior: 'smooth' });
}

// Switch between tabs (though currently only using URL scanner)
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    const selectedTab = document.getElementById(tabName + '-tab');
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
    
    // Add active class to clicked button
    event.target.classList.add('active');
    
    // Load specific tab content
    if (tabName === 'history') {
        loadAnalysisHistory();
    } else if (tabName === 'quiz') {
        // Quiz content is handled by initializeQuiz
    }
}

// Main URL analysis function
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const resultsDiv = document.getElementById('urlResults');
    
    if (!urlInput || !resultsDiv) {
        console.error('Required DOM elements not found');
        return;
    }
    
    const url = urlInput.value.trim();
    
    if (!url) {
        resultsDiv.innerHTML = '<div style="color: #ef4444; text-align: center; padding: 20px;">Please enter a URL to analyze.</div>';
        return;
    }
    
    // Validate URL format
    try {
        new URL(url);
    } catch (e) {
        resultsDiv.innerHTML = '<div style="color: #ef4444; text-align: center; padding: 20px;">Please enter a valid URL (include http:// or https://)</div>';
        return;
    }
    
    // Show loading state
    resultsDiv.innerHTML = `
        <div style="text-align: center; padding: 40px;">
            <div class="loading-spinner"></div>
            <div style="margin-top: 15px; font-size: 18px; color: #667eea;">Analyzing URL...</div>
            <div style="margin-top: 10px; color: #6b7280;">This may take a few seconds</div>
        </div>
    `;
    
    try {
        // Check if URL exists in history first
        const historicalResult = checkUrlHistory(url);
        if (historicalResult) {
            displayAnalysisResults(historicalResult, resultsDiv);
            return;
        }
        
        // Perform new analysis
        const basicFeatures = await analyzeBasicFeatures(url);
        const advancedFeatures = await analyzeAdvancedFeatures(url);
        
        const result = {
            url: url,
            timestamp: new Date().toISOString(),
            basicFeatures: basicFeatures,
            advancedFeatures: advancedFeatures,
            riskScore: calculateRiskScore(basicFeatures, advancedFeatures),
            status: determineStatus(basicFeatures, advancedFeatures)
        };
        
        // Save to history
        saveToHistory(result);
        
        // Display results
        displayAnalysisResults(result, resultsDiv);
        
    } catch (error) {
        resultsDiv.innerHTML = `<div class="text-red-500">Error analyzing URL: ${error.message}</div>`;
    }
}

// Basic feature analysis (client-side)
async function analyzeBasicFeatures(url) {
    return new Promise((resolve) => {
        // Import feature analysis functions from feature_script.js
        const features = {
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
            hasHttps: checkHttpsPresence(url)
        };
        
        resolve(features);
    });
}

// Advanced feature analysis (server-side via Flask API)
async function analyzeAdvancedFeatures(url) {
    try {
        const response = await fetch('/api/analyze-advanced', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error('Advanced analysis failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Advanced analysis error:', error);
        // Return empty object if advanced analysis fails
        return {};
    }
}

// Calculate risk score based on features
function calculateRiskScore(basicFeatures, advancedFeatures) {
    let riskScore = 0;
    let totalFeatures = 0;
    
    // Basic features scoring (each suspicious feature adds points)
    Object.entries(basicFeatures).forEach(([key, value]) => {
        if (typeof value === 'boolean') {
            totalFeatures++;
            // Most features are suspicious when true, except hasHttps which is good when true
            if (key === 'hasHttps') {
                if (!value) riskScore += 2; // Missing HTTPS is very suspicious
            } else {
                if (value) riskScore++; // Suspicious features increase risk
            }
        }
    });
    
    // Advanced features scoring with weighted importance
    Object.entries(advancedFeatures).forEach(([key, value]) => {
        if (typeof value === 'boolean') {
            totalFeatures++;
            if (value) {
                // Weight critical security indicators more heavily
                if (key === 'google_safe_browsing_threat' || key === 'virustotal_high_risk') {
                    riskScore += 5; // Critical threats
                } else if (key === 'ssl_self_signed' || key === 'suspicious_content_patterns') {
                    riskScore += 3; // High risk indicators
                } else {
                    riskScore += 1; // Standard suspicious features
                }
            }
        } else if (key === 'virustotal_detections' && typeof value === 'number') {
            totalFeatures++;
            if (value > 0) {
                riskScore += Math.min(value, 10); // Cap at 10 points for VT detections
            }
        }
    });
    
    return totalFeatures > 0 ? Math.round((riskScore / Math.max(totalFeatures, 15)) * 100) : 0;
}

// Determine overall status
function determineStatus(basicFeatures, advancedFeatures) {
    // Check for immediate high-risk indicators
    if (advancedFeatures.google_safe_browsing_threat || 
        advancedFeatures.virustotal_high_risk ||
        (advancedFeatures.virustotal_detections && advancedFeatures.virustotal_detections > 5)) {
        return 'danger';
    }
    
    const score = calculateRiskScore(basicFeatures, advancedFeatures);
    
    if (score < 25) return 'safe';
    if (score < 60) return 'warning';
    return 'danger';
}

// Display analysis results
function displayAnalysisResults(result, container) {
    const statusClass = result.status === 'safe' ? 'safe-indicator' : 
                       result.status === 'warning' ? 'warning-indicator' : 'danger-indicator';
    
    const statusIcon = result.status === 'safe' ? 'shield-check' : 
                      result.status === 'warning' ? 'exclamation-triangle' : 'ban';
    
    const statusText = result.status === 'safe' ? 'Likely Safe' : 
                      result.status === 'warning' ? 'Potentially Suspicious' : 'Likely Malicious';
    
    const statusMessage = result.status === 'safe' ? 'This URL appears to be legitimate and safe to visit.' :
                         result.status === 'warning' ? 'This URL has some suspicious characteristics. Exercise caution.' :
                         'This URL shows multiple red flags. Avoid visiting this site.';
    
    container.innerHTML = `
        <div style="text-align: center; margin-bottom: 30px;">
            <i class="fas fa-${statusIcon}" style="font-size: 4em; margin-bottom: 20px;" class="${statusClass}"></i>
            <h3 style="font-size: 2em; font-weight: bold; margin-bottom: 10px;" class="${statusClass}">${statusText}</h3>
            <div style="font-size: 1.5em; font-weight: 600; margin-bottom: 10px;">Risk Score: <span class="${statusClass}">${result.riskScore}%</span></div>
            <p style="color: #6b7280; font-size: 1.1em; max-width: 600px; margin: 0 auto;">${statusMessage}</p>
        </div>
        
        <div class="feature-list">
            ${generateFeatureList(result.basicFeatures, 'Basic URL Analysis')}
            ${Object.keys(result.advancedFeatures || {}).length > 0 ? generateFeatureList(result.advancedFeatures, 'Advanced Security Analysis') : ''}
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <button onclick="shareResults('${encodeURIComponent(result.url)}')" class="btn-secondary" style="margin-right: 10px;">
                <i class="fas fa-share-alt"></i> Share Results
            </button>
            <button onclick="reportUrl('${encodeURIComponent(result.url)}')" class="btn-danger">
                <i class="fas fa-flag"></i> Report as Malicious
            </button>
        </div>
    `;
}

// Generate feature list HTML
function generateFeatureList(features, title) {
    if (!features || Object.keys(features).length === 0) {
        return '';
    }
    
    let html = `<div style="margin-bottom: 25px;">
        <h4 style="font-size: 1.3em; font-weight: bold; margin-bottom: 15px; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px;">${title}</h4>`;
    
    Object.entries(features).forEach(([key, value]) => {
        // Skip non-boolean values for display unless they're important numbers
        if (typeof value !== 'boolean' && !(key === 'virustotal_detections' && typeof value === 'number')) {
            return;
        }
        
        let status, icon, statusText, statusColor;
        
        if (typeof value === 'boolean') {
            // Special case for hasHttps - this should be true for safety
            if (key === 'hasHttps') {
                status = value ? 'pass' : 'fail';
                icon = value ? 'check' : 'times';
                statusText = value ? 'Secured with HTTPS' : 'Missing HTTPS';
                statusColor = value ? '#10b981' : '#ef4444';
            } else {
                status = value ? 'fail' : 'pass';
                icon = value ? 'times' : 'check';
                statusText = value ? 'Suspicious' : 'OK';
                statusColor = value ? '#ef4444' : '#10b981';
            }
        } else if (key === 'virustotal_detections') {
            status = value > 0 ? 'fail' : 'pass';
            icon = value > 0 ? 'times' : 'check';
            statusText = value > 0 ? `${value} detections` : 'Clean';
            statusColor = value > 0 ? '#ef4444' : '#10b981';
        }
        
        html += `
            <div class="feature-item ${status}" style="margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; padding: 12px 15px;">
                <span style="font-weight: 500;">${formatFeatureName(key)}</span>
                <span style="display: flex; align-items: center; color: ${statusColor}; font-weight: 600;">
                    <i class="fas fa-${icon}" style="margin-right: 8px;"></i>
                    ${statusText}
                </span>
            </div>
        `;
    });
    
    html += '</div>';
    return html;
}

// Format feature names for display
function formatFeatureName(key) {
    const names = {
        urlLength: 'URL Length',
        hasAtSymbol: 'Contains @ Symbol',
        hasDoubleSlash: 'Double Slash in Path',
        domainDots: 'Multiple Dots in Domain',
        hyphenCount: 'Excessive Hyphens',
        suspiciousKeywords: 'Suspicious Keywords',
        urlEncoding: 'URL Encoding',
        isShortener: 'URL Shortener',
        specialCharCount: 'Special Characters',
        pathLength: 'Long Path',
        excessiveParams: 'Excessive Parameters',
        embeddedHttp: 'Embedded HTTP',
        hasIpAddress: 'IP Address Used',
        hasPort: 'Non-standard Port',
        hasHttps: 'HTTPS Present'
    };
    
    return names[key] || key;
}

// Quiz Functions
function initializeQuiz() {
    displayQuestion();
    updateProgress();
}

function displayQuestion() {
    const currentSet = quizSets[currentSetIndex];
    const currentQuestion = currentSet[currentQuestionIndex];
    
    document.getElementById('questionText').textContent = currentQuestion.question;
    document.getElementById('currentQuestion').textContent = (currentSetIndex * 5) + currentQuestionIndex + 1;
    document.getElementById('totalQuestions').textContent = quizSets.length * 5;
    
    const optionsContainer = document.getElementById('optionsContainer');
    optionsContainer.innerHTML = '';
    
    currentQuestion.options.forEach((option, index) => {
        const optionDiv = document.createElement('div');
        optionDiv.className = 'quiz-option p-4 border rounded-lg';
        optionDiv.innerHTML = `
            <label class="flex items-center cursor-pointer">
                <input type="radio" name="quizOption" value="${index}" class="mr-3">
                <span>${option}</span>
            </label>
        `;
        optionsContainer.appendChild(optionDiv);
    });
    
    // Update button states
    document.getElementById('prevBtn').disabled = currentQuestionIndex === 0 && currentSetIndex === 0;
    document.getElementById('nextBtn').textContent = 
        (currentSetIndex === quizSets.length - 1 && currentQuestionIndex === 4) ? 'Finish' : 'Next';
}

function nextQuestion() {
    const selectedOption = document.querySelector('input[name="quizOption"]:checked');
    if (!selectedOption) {
        alert('Please select an answer before continuing.');
        return;
    }
    
    const currentSet = quizSets[currentSetIndex];
    const currentQuestion = currentSet[currentQuestionIndex];
    const selectedIndex = parseInt(selectedOption.value);
    
    // Store answer
    userAnswers.push({
        setIndex: currentSetIndex,
        questionIndex: currentQuestionIndex,
        selected: selectedIndex,
        correct: currentQuestion.correct
    });
    
    // Update score
    if (selectedIndex === currentQuestion.correct) {
        score++;
    }
    
    // Move to next question
    if (currentQuestionIndex < 4) {
        currentQuestionIndex++;
    } else if (currentSetIndex < quizSets.length - 1) {
        currentSetIndex++;
        currentQuestionIndex = 0;
    } else {
        // Quiz completed
        showQuizResults();
        return;
    }
    
    displayQuestion();
    updateProgress();
    document.getElementById('quizScore').textContent = score;
}

function previousQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
    } else if (currentSetIndex > 0) {
        currentSetIndex--;
        currentQuestionIndex = 4;
    }
    
    displayQuestion();
    updateProgress();
}

function updateProgress() {
    const totalQuestions = quizSets.length * 5;
    const currentQuestionNum = (currentSetIndex * 5) + currentQuestionIndex + 1;
    const progressPercent = (currentQuestionNum / totalQuestions) * 100;
    
    document.getElementById('progressBar').style.width = progressPercent + '%';
}

function showQuizResults() {
    document.getElementById('quizContainer').classList.add('hidden');
    document.getElementById('quizResults').classList.remove('hidden');
    
    const totalQuestions = quizSets.length * 5;
    const percentage = Math.round((score / totalQuestions) * 100);
    
    document.getElementById('scoreDisplay').textContent = `${score}/${totalQuestions}`;
    
    let message = '';
    if (percentage >= 90) {
        message = 'Excellent! You have a strong understanding of phishing detection.';
    } else if (percentage >= 70) {
        message = 'Good job! You have a solid grasp of phishing concepts.';
    } else if (percentage >= 50) {
        message = 'Not bad, but consider reviewing phishing detection techniques.';
    } else {
        message = 'Consider studying more about phishing threats and protection methods.';
    }
    
    document.getElementById('scoreMessage').textContent = message;
}

function restartQuiz() {
    currentQuestionIndex = 0;
    currentSetIndex = 0;
    score = 0;
    userAnswers = [];
    
    document.getElementById('quizContainer').classList.remove('hidden');
    document.getElementById('quizResults').classList.add('hidden');
    document.getElementById('quizScore').textContent = '0';
    
    displayQuestion();
    updateProgress();
}

// History Management
function saveToHistory(result) {
    let history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    history.unshift(result); // Add to beginning
    
    // Keep only last 50 results
    if (history.length > 50) {
        history = history.slice(0, 50);
    }
    
    localStorage.setItem('phishguard_history', JSON.stringify(history));
    analysisHistory = history;
}

function loadAnalysisHistory() {
    const history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    analysisHistory = history;
    displayHistory();
}

function checkUrlHistory(url) {
    return analysisHistory.find(item => item.url === url);
}

function displayHistory() {
    const historyContainer = document.getElementById('analysisHistory');
    if (!historyContainer) return;
    
    if (analysisHistory.length === 0) {
        historyContainer.innerHTML = '<p class="text-gray-500 text-center">No previous analyses found.</p>';
        return;
    }
    
    const historyHtml = analysisHistory.slice(0, 10).map(item => `
        <div class="history-card p-4 rounded-lg mb-3">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <div class="font-medium text-sm text-gray-800 truncate">${item.url}</div>
                    <div class="text-xs text-gray-500 mt-1">${new Date(item.timestamp).toLocaleString()}</div>
                </div>
                <span class="status-${item.status} px-2 py-1 rounded text-xs font-medium ml-2">
                    ${item.status.toUpperCase()}
                </span>
            </div>
            <div class="mt-2">
                <div class="text-xs text-gray-600">Risk Score: ${item.riskScore}%</div>
            </div>
        </div>
    `).join('');
    
    historyContainer.innerHTML = historyHtml;
}

// Threat Feed (Mock data for demo)
function displayThreatFeed() {
    const threatContainer = document.getElementById('threatFeed');
    if (!threatContainer) return;
    
    const mockThreats = [
        {
            type: 'Phishing Campaign',
            description: 'New Microsoft Office 365 credential harvesting campaign detected',
            time: '2 hours ago',
            severity: 'high'
        },
        {
            type: 'Malicious Domain',
            description: 'Domain \\'secure-bank-login.net\\' flagged for phishing',
            time: '4 hours ago',
            severity: 'medium'
        },
        {
            type: 'Social Engineering',
            description: 'Increase in fake IT support calls reported',
            time: '6 hours ago',
            severity: 'medium'
        }
    ];
    
    const threatHtml = mockThreats.map(threat => `
        <div class="border-l-4 border-${threat.severity === 'high' ? 'red' : 'yellow'}-500 pl-4 py-2">
            <div class="flex justify-between items-start">
                <div>
                    <div class="font-semibold text-gray-800">${threat.type}</div>
                    <div class="text-sm text-gray-600 mt-1">${threat.description}</div>
                </div>
                <div class="text-xs text-gray-500">${threat.time}</div>
            </div>
        </div>
    `).join('');
    
    threatContainer.innerHTML = threatHtml;
}

// Utility Functions
function shareResults(url) {
    if (navigator.share) {
        navigator.share({
            title: 'PhishGuard Analysis Results',
            text: `I analyzed ${url} for phishing threats using PhishGuard.`,
            url: window.location.href
        });
    } else {
        // Fallback for browsers without native sharing
        const shareText = `I analyzed ${url} for phishing threats using PhishGuard. Check it out at ${window.location.href}`;
        navigator.clipboard.writeText(shareText).then(() => {
            alert('Results copied to clipboard!');
        });
    }
}

function reportUrl(url) {
    // In a real implementation, this would report to threat intelligence services
    alert(`Thank you for reporting ${url}. This information helps improve our detection capabilities.`);
}

// Export functions for use in other scripts
window.PhishGuard = {
    analyzeURL,
    switchTab,
    scrollToDetector,
    nextQuestion,
    previousQuestion,
    restartQuiz,
    shareResults,
    reportUrl
};

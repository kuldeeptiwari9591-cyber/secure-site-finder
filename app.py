#!/usr/bin/env python3
"""
PhishGuard Flask Backend API
Handles advanced feature extraction and analysis using external APIs
"""

import os
import json
import requests
import time
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')
CORS(app)

# API Keys provided by user
GOOGLE_SAFE_BROWSING_API_KEY = 'AIzaSyC9JhAQgRUiMsvHDCl_h1K-3LxjKIkUJ9g'
WHOISXML_API_KEY = 'at_yHbGBEeBpmSAT5K5LMAYjUirsqTEh'
VIRUSTOTAL_API_KEY = '317c222ce390ea39dea87fc68ab82f45b411e7300bebc941ebb0c9ad3916d49f'

# Cache for API responses to avoid rate limiting
response_cache = {}
CACHE_DURATION = 3600  # 1 hour

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/analyze-advanced', methods=['POST'])
def analyze_advanced():
    """
    Perform advanced analysis on a URL using external APIs
    """
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Check cache first
        cache_key = f"advanced_{url}"
        if cache_key in response_cache:
            cached_data = response_cache[cache_key]
            if datetime.now() - cached_data['timestamp'] < timedelta(seconds=CACHE_DURATION):
                logger.info(f"Returning cached results for {url}")
                return jsonify(cached_data['data'])
        
        # Perform advanced analysis
        results = {}
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Domain and WHOIS analysis
        if WHOISXML_API_KEY:
            whois_data = get_whois_data(domain)
            results.update(whois_data)
        
        # Google Safe Browsing check
        if GOOGLE_SAFE_BROWSING_API_KEY:
            safe_browsing_data = check_google_safe_browsing(url)
            results.update(safe_browsing_data)
        
        # VirusTotal analysis
        if VIRUSTOTAL_API_KEY:
            vt_data = check_virustotal(url)
            results.update(vt_data)
        
        # SSL Certificate analysis
        ssl_data = analyze_ssl_certificate(url)
        results.update(ssl_data)
        
        # Content analysis
        content_data = analyze_content(url)
        results.update(content_data)
        
        # Cache results
        response_cache[cache_key] = {
            'data': results,
            'timestamp': datetime.now()
        }
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in advanced analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_whois_data(domain):
    """Get WHOIS information for domain"""
    if not WHOISXML_API_KEY:
        return {}
    
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            'apiKey': WHOISXML_API_KEY,
            'domainName': domain,
            'outputFormat': 'JSON'
        }
        
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            whois_record = data.get('WhoisRecord', {})
            
            # Extract relevant information
            creation_date = whois_record.get('createdDate', '')
            expiry_date = whois_record.get('expiresDate', '')
            registrar = whois_record.get('registrarName', '')
            
            # Calculate domain age
            domain_age_days = 0
            is_new_domain = True
            
            if creation_date:
                try:
                    created = datetime.strptime(creation_date[:10], '%Y-%m-%d')
                    domain_age_days = (datetime.now() - created).days
                    is_new_domain = domain_age_days < 90  # Less than 3 months
                except:
                    pass
            
            return {
                'domain_age_days': domain_age_days,
                'is_new_domain': is_new_domain,
                'has_whois_privacy': 'privacy' in registrar.lower() if registrar else False,
                'expires_soon': check_expiry_soon(expiry_date),
                'suspicious_registrar': check_suspicious_registrar(registrar)
            }
    
    except Exception as e:
        logger.error(f"WHOIS API error: {str(e)}")
    
    return {}

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {}
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            threat_matches = data.get('matches', [])
            
            return {
                'google_safe_browsing_threat': len(threat_matches) > 0,
                'threat_types': [match.get('threatType', '') for match in threat_matches]
            }
    
    except Exception as e:
        logger.error(f"Google Safe Browsing API error: {str(e)}")
    
    return {}

def check_virustotal(url):
    """Check URL against VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return {}
    
    try:
        # Submit URL for analysis
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        data = {'url': url}
        
        response = requests.post(
            'https://www.virustotal.com/vtapi/v2/url/scan',
            files=data,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get('scan_id', '')
            
            # Wait a moment and then get results
            time.sleep(2)
            
            # Get scan results
            params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                
                return {
                    'virustotal_detections': positives,
                    'virustotal_total_scans': total,
                    'virustotal_suspicious': positives > 0,
                    'virustotal_high_risk': positives > 5
                }
    
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
    
    return {}

def analyze_ssl_certificate(url):
    """Analyze SSL certificate information"""
    try:
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return {
                'has_ssl': False,
                'ssl_valid': False,
                'ssl_self_signed': False,
                'ssl_expires_soon': False
            }
        
        hostname = parsed.netloc
        port = 443
        
        # Get SSL certificate
        context = ssl.create_default_context()
        sock = socket.create_connection((hostname, port), timeout=10)
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        
        cert = ssock.getpeercert()
        ssock.close()
        
        if cert:
            # Check expiry
            not_after = cert.get('notAfter', '')
            expires_soon = False
            
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    expires_soon = days_until_expiry < 30
                except:
                    pass
            
            # Check issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            is_self_signed = cert.get('subject', []) == cert.get('issuer', [])
            
            return {
                'has_ssl': True,
                'ssl_valid': True,
                'ssl_self_signed': is_self_signed,
                'ssl_expires_soon': expires_soon,
                'ssl_issuer': issuer.get('organizationName', 'Unknown')
            }
    
    except Exception as e:
        logger.error(f"SSL analysis error: {str(e)}")
    
    return {
        'has_ssl': url.startswith('https://'),
        'ssl_valid': False,
        'ssl_self_signed': False,
        'ssl_expires_soon': False
    }

def analyze_content(url):
    """Analyze webpage content for suspicious patterns"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        if response.status_code == 200:
            content = response.text.lower()
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'login.*password',
                r'verify.*account',
                r'suspend.*account',
                r'click.*here.*immediately',
                r'urgent.*action.*required',
                r'congratulations.*winner',
                r'free.*money',
                r'invoice.*attached'
            ]
            
            pattern_matches = 0
            for pattern in suspicious_patterns:
                if re.search(pattern, content):
                    pattern_matches += 1
            
            # Check for external resources
            external_scripts = len(re.findall(r'<script.*src=["\']https?://(?!.*' + 
                                            urlparse(url).netloc + ').*["\']', content))
            
            # Check for iframes
            iframes = len(re.findall(r'<iframe', content))
            
            # Check for forms
            forms = len(re.findall(r'<form', content))
            login_forms = len(re.findall(r'<form.*password', content))
            
            # Check redirects
            redirect_count = len(response.history)
            
            return {
                'suspicious_content_patterns': pattern_matches > 2,
                'external_scripts': external_scripts > 5,
                'has_iframes': iframes > 0,
                'has_login_forms': login_forms > 0,
                'multiple_redirects': redirect_count > 2,
                'redirect_count': redirect_count,
                'content_type': response.headers.get('content-type', ''),
                'server_header': response.headers.get('server', '')
            }
    
    except Exception as e:
        logger.error(f"Content analysis error: {str(e)}")
    
    return {}

def check_expiry_soon(expiry_date):
    """Check if domain expires soon"""
    if not expiry_date:
        return False
    
    try:
        expiry = datetime.strptime(expiry_date[:10], '%Y-%m-%d')
        days_until_expiry = (expiry - datetime.now()).days
        return days_until_expiry < 90  # Less than 3 months
    except:
        return False

def check_suspicious_registrar(registrar):
    """Check if registrar is known to be used by malicious domains"""
    if not registrar:
        return False
    
    suspicious_registrars = [
        'privacy protect',
        'domains by proxy',
        'whois privacy',
        'perfect privacy'
    ]
    
    return any(suspicious in registrar.lower() for suspicious in suspicious_registrars)

@app.route('/api/save-analysis', methods=['POST'])
def save_analysis():
    """Save analysis results to local file"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        results = data.get('results', {})
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create analysis record
        analysis_record = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'results': results,
            'risk_score': calculate_overall_risk_score(results),
            'status': determine_overall_status(results)
        }
        
        # Save to file
        filename = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join('analysis_history', filename)
        
        # Create directory if it doesn't exist
        os.makedirs('analysis_history', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(analysis_record, f, indent=2)
        
        logger.info(f"Analysis saved to {filepath}")
        return jsonify({'message': 'Analysis saved successfully', 'filename': filename})
        
    except Exception as e:
        logger.error(f"Error saving analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-history', methods=['GET'])
def get_analysis_history():
    """Get analysis history from saved files"""
    try:
        history_dir = 'analysis_history'
        if not os.path.exists(history_dir):
            return jsonify([])
        
        history = []
        for filename in os.listdir(history_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(history_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        record = json.load(f)
                        history.append(record)
                except:
                    continue
        
        # Sort by timestamp, newest first
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify(history[:50])  # Return last 50 analyses
        
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        return jsonify({'error': str(e)}), 500

def calculate_overall_risk_score(results):
    """Calculate overall risk score from all analysis results"""
    risk_factors = 0
    total_factors = 0
    
    # Count risk factors
    for key, value in results.items():
        if isinstance(value, bool):
            total_factors += 1
            if value and not key.startswith('has_ssl'):  # SSL presence is good
                risk_factors += 1
        elif key == 'virustotal_detections' and isinstance(value, int):
            total_factors += 1
            if value > 0:
                risk_factors += 1
    
    return int((risk_factors / max(total_factors, 1)) * 100)

def determine_overall_status(results):
    """Determine overall threat status"""
    risk_score = calculate_overall_risk_score(results)
    
    # High priority threats
    if (results.get('google_safe_browsing_threat') or 
        results.get('virustotal_high_risk') or
        results.get('virustotal_detections', 0) > 10):
        return 'danger'
    
    if risk_score > 70:
        return 'danger'
    elif risk_score > 40:
        return 'warning'
    else:
        return 'safe'

if __name__ == '__main__':
    # Check for API keys
    if not any([GOOGLE_SAFE_BROWSING_API_KEY, WHOISXML_API_KEY, VIRUSTOTAL_API_KEY]):
        print("Warning: No API keys found. Set environment variables:")
        print("- GOOGLE_SAFE_BROWSING_API_KEY")
        print("- WHOISXML_API_KEY") 
        print("- VIRUSTOTAL_API_KEY")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
#!/usr/bin/env python3
"""
Advanced Feature Extractor for PhishGuard
Handles domain analysis, SSL checks, content analysis, and external API integrations
"""

import os
import re
import ssl
import json
import socket
import requests
import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import dns.resolver
import hashlib
import time

class AdvancedFeatureExtractor:
    def __init__(self):
        self.google_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.whoisxml_api_key = os.getenv('WHOISXML_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        
        # Known malicious patterns and indicators
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.ru', '.cn']
        self.phishing_keywords = [
            'verify', 'suspend', 'urgent', 'immediate', 'confirm', 'update',
            'security', 'alert', 'warning', 'expired', 'locked', 'limited'
        ]
        
        # Cache for API responses
        self.cache = {}
        self.cache_file = 'analysis_cache.json'
        self._load_cache()
    
    def _load_cache(self):
        """Load cached results from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
        except:
            self.cache = {}
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass
    
    def _get_cached_result(self, key, max_age_hours=24):
        """Get cached result if still valid"""
        if key in self.cache:
            cached_data = self.cache[key]
            cached_time = datetime.fromisoformat(cached_data.get('timestamp', '1970-01-01'))
            if datetime.now() - cached_time < timedelta(hours=max_age_hours):
                return cached_data.get('data')
        return None
    
    def _cache_result(self, key, data):
        """Cache a result with timestamp"""
        self.cache[key] = {
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        self._save_cache()
    
    def extract_all_features(self, url):
        """Extract all available features for a URL"""
        features = {}
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            print(f"Analyzing URL: {url}")
            print(f"Domain: {domain}")
            
            # Domain & WHOIS Features
            print("Extracting domain features...")
            domain_features = self.extract_domain_features(domain)
            features.update(domain_features)
            
            # SSL & Security Features
            print("Analyzing SSL certificate...")
            ssl_features = self.extract_ssl_features(url)
            features.update(ssl_features)
            
            # Content & Response Features
            print("Analyzing content...")
            content_features = self.extract_content_features(url)
            features.update(content_features)
            
            # External API checks
            print("Checking external threat databases...")
            api_features = self.extract_api_features(url, domain)
            features.update(api_features)
            
            # DNS Features
            print("Analyzing DNS records...")
            dns_features = self.extract_dns_features(domain)
            features.update(dns_features)
            
            print("Feature extraction complete.")
            
        except Exception as e:
            print(f"Error in feature extraction: {e}")
            features['extraction_error'] = str(e)
        
        return features
    
    def extract_domain_features(self, domain):
        """Extract domain and WHOIS related features"""
        features = {}
        cache_key = f"domain_{domain}"
        
        # Check cache first
        cached = self._get_cached_result(cache_key)
        if cached:
            return cached
        
        try:
            # Domain age using WHOIS
            if self.whoisxml_api_key:
                whois_data = self._get_whoisxml_data(domain)
                if whois_data:
                    features.update(whois_data)
            else:
                # Fallback to python-whois
                try:
                    w = whois.whois(domain)
                    if w.creation_date:
                        creation_date = w.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        
                        age_days = (datetime.now() - creation_date).days
                        features['domain_age_days'] = age_days
                        features['domain_age_months'] = age_days // 30
                        features['is_new_domain'] = age_days < 90
                        features['very_new_domain'] = age_days < 30
                    
                    if w.expiration_date:
                        exp_date = w.expiration_date
                        if isinstance(exp_date, list):
                            exp_date = exp_date[0]
                        
                        days_to_expiry = (exp_date - datetime.now()).days
                        features['domain_expires_soon'] = days_to_expiry < 90
                        features['domain_expires_very_soon'] = days_to_expiry < 30
                    
                    # Registrar information
                    if w.registrar:
                        registrar = str(w.registrar).lower()
                        features['has_privacy_protection'] = any(word in registrar for word in 
                                                               ['privacy', 'protect', 'proxy'])
                        features['suspicious_registrar'] = any(word in registrar for word in 
                                                             ['cheap', 'free', 'anonymous'])
                
                except Exception as e:
                    print(f"WHOIS lookup failed: {e}")
                    features['whois_lookup_failed'] = True
            
            # Domain structure analysis
            domain_parts = domain.split('.')
            features['subdomain_count'] = len(domain_parts) - 2  # Subtract domain and TLD
            features['has_multiple_subdomains'] = len(domain_parts) > 3
            features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in self.suspicious_tlds)
            
            # Domain name patterns
            features['domain_has_numbers'] = bool(re.search(r'\d', domain))
            features['domain_has_hyphens'] = '-' in domain
            features['excessive_hyphens'] = domain.count('-') > 3
            features['domain_length'] = len(domain)
            features['long_domain'] = len(domain) > 30
            
            # Suspicious domain patterns
            features['typosquatting_indicators'] = self._check_typosquatting(domain)
            features['homograph_attack'] = self._check_homograph_attack(domain)
            
        except Exception as e:
            print(f"Domain analysis error: {e}")
            features['domain_analysis_error'] = str(e)
        
        # Cache results
        self._cache_result(cache_key, features)
        return features
    
    def extract_ssl_features(self, url):
        """Extract SSL certificate related features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                features['has_ssl'] = False
                features['ssl_valid'] = False
                return features
            
            hostname = parsed.netloc
            port = parsed.port or 443
            
            # SSL certificate analysis
            context = ssl.create_default_context()
            sock = socket.create_connection((hostname, port), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            
            cert = ssock.getpeercert()
            ssock.close()
            
            if cert:
                features['has_ssl'] = True
                features['ssl_valid'] = True
                
                # Certificate expiry
                not_after = cert.get('notAfter')
                if not_after:
                    try:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        features['ssl_expires_soon'] = days_until_expiry < 30
                        features['ssl_expires_very_soon'] = days_until_expiry < 7
                        features['ssl_days_until_expiry'] = days_until_expiry
                    except:
                        features['ssl_expiry_parse_error'] = True
                
                # Certificate issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                features['ssl_issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Self-signed check
                features['ssl_self_signed'] = cert.get('subject') == cert.get('issuer')
                
                # Certificate validation
                subject = dict(x[0] for x in cert.get('subject', []))
                cert_common_name = subject.get('commonName', '')
                features['ssl_hostname_mismatch'] = hostname.lower() not in cert_common_name.lower()
                
        except ssl.SSLError as e:
            features['has_ssl'] = True
            features['ssl_valid'] = False
            features['ssl_error'] = str(e)
            features['ssl_self_signed'] = 'SELF_SIGNED' in str(e)
        
        except Exception as e:
            features['has_ssl'] = url.startswith('https://')
            features['ssl_valid'] = False
            features['ssl_connection_error'] = str(e)
        
        return features
    
    def extract_content_features(self, url):
        """Extract content and response related features"""
        features = {}
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            features['http_status_code'] = response.status_code
            features['response_time'] = response.elapsed.total_seconds()
            
            # Redirect analysis
            features['redirect_count'] = len(response.history)
            features['multiple_redirects'] = len(response.history) > 2
            features['excessive_redirects'] = len(response.history) > 5
            
            if response.history:
                # Check for suspicious redirect patterns
                redirect_domains = [urlparse(r.url).netloc for r in response.history]
                features['redirects_through_different_domains'] = len(set(redirect_domains)) > 1
            
            # Content type analysis
            content_type = response.headers.get('content-type', '').lower()
            features['content_type'] = content_type
            features['suspicious_content_type'] = 'application/octet-stream' in content_type
            
            # Server header analysis
            server = response.headers.get('server', '').lower()
            features['server_header'] = server
            features['suspicious_server'] = any(word in server for word in ['nginx/1.', 'apache/2.2'])
            
            # Content analysis
            if response.status_code == 200:
                content = response.text
                soup = BeautifulSoup(content, 'html.parser')
                
                # Form analysis
                forms = soup.find_all('form')
                features['form_count'] = len(forms)
                features['has_forms'] = len(forms) > 0
                
                login_forms = 0
                for form in forms:
                    form_text = str(form).lower()
                    if 'password' in form_text or 'login' in form_text:
                        login_forms += 1
                
                features['login_form_count'] = login_forms
                features['has_login_forms'] = login_forms > 0
                features['multiple_login_forms'] = login_forms > 1
                
                # Check for HTTP forms on HTTPS sites
                if url.startswith('https://'):
                    for form in forms:
                        action = form.get('action', '')
                        if action.startswith('http://'):
                            features['https_to_http_form'] = True
                            break
                    else:
                        features['https_to_http_form'] = False
                
                # External resource analysis
                scripts = soup.find_all('script', src=True)
                external_scripts = 0
                for script in scripts:
                    src = script.get('src', '')
                    if src.startswith('http') and urlparse(url).netloc not in src:
                        external_scripts += 1
                
                features['external_script_count'] = external_scripts
                features['excessive_external_scripts'] = external_scripts > 10
                
                # Iframe analysis
                iframes = soup.find_all('iframe')
                features['iframe_count'] = len(iframes)
                features['has_iframes'] = len(iframes) > 0
                
                # Check for suspicious iframe sources
                suspicious_iframes = 0
                for iframe in iframes:
                    src = iframe.get('src', '')
                    if src and urlparse(url).netloc not in src:
                        suspicious_iframes += 1
                
                features['suspicious_iframe_count'] = suspicious_iframes
                
                # Content pattern analysis
                content_lower = content.lower()
                
                # Phishing keywords
                keyword_count = 0
                for keyword in self.phishing_keywords:
                    keyword_count += content_lower.count(keyword)
                
                features['phishing_keyword_count'] = keyword_count
                features['excessive_phishing_keywords'] = keyword_count > 5
                
                # Suspicious patterns
                features['has_urgency_words'] = bool(re.search(r'\b(urgent|immediate|expire|suspend|lock)\b', content_lower))
                features['has_money_references'] = bool(re.search(r'\$\d+|\bmoney\b|\bcash\b|\bprize\b', content_lower))
                features['has_personal_info_requests'] = bool(re.search(r'\bssn\b|\bsocial security\b|\bcredit card\b|\bbank account\b', content_lower))
                
                # Favicon analysis
                favicon_links = soup.find_all('link', rel=lambda x: x and 'icon' in str(x).lower())
                features['favicon_count'] = len(favicon_links)
                
                external_favicon = False
                for link in favicon_links:
                    href = link.get('href', '')
                    if href.startswith('http') and urlparse(url).netloc not in href:
                        external_favicon = True
                        break
                
                features['external_favicon'] = external_favicon
                
                # Meta tag analysis
                meta_tags = soup.find_all('meta')
                features['meta_tag_count'] = len(meta_tags)
                
                # Check for suspicious meta redirects
                for meta in meta_tags:
                    if meta.get('http-equiv', '').lower() == 'refresh':
                        content_attr = meta.get('content', '')
                        if 'url=' in content_attr.lower():
                            features['has_meta_redirect'] = True
                            break
                else:
                    features['has_meta_redirect'] = False
        
        except requests.exceptions.RequestException as e:
            features['content_fetch_error'] = str(e)
            features['content_accessible'] = False
        
        except Exception as e:
            features['content_analysis_error'] = str(e)
        
        return features
    
    def extract_api_features(self, url, domain):
        """Extract features using external APIs"""
        features = {}
        
        # Google Safe Browsing
        if self.google_api_key:
            gsb_result = self._check_google_safe_browsing(url)
            features.update(gsb_result)
        
        # VirusTotal
        if self.virustotal_api_key:
            vt_result = self._check_virustotal(url)
            features.update(vt_result)
        
        return features
    
    def extract_dns_features(self, domain):
        """Extract DNS-related features"""
        features = {}
        
        try:
            # A record count
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                features['a_record_count'] = len(a_records)
                features['multiple_a_records'] = len(a_records) > 3
            except:
                features['a_record_count'] = 0
                features['dns_resolution_failed'] = True
            
            # MX record analysis
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                features['mx_record_count'] = len(mx_records)
                features['has_mx_records'] = len(mx_records) > 0
            except:
                features['mx_record_count'] = 0
                features['has_mx_records'] = False
            
            # NS record analysis
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                features['ns_record_count'] = len(ns_records)
                
                # Check for suspicious NS patterns
                ns_domains = [str(ns).lower() for ns in ns_records]
                features['suspicious_ns'] = any('free' in ns or 'cheap' in ns for ns in ns_domains)
            except:
                features['ns_record_count'] = 0
        
        except Exception as e:
            features['dns_analysis_error'] = str(e)
        
        return features
    
    def _get_whoisxml_data(self, domain):
        """Get WHOIS data from WhoisXML API"""
        try:
            url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                'apiKey': self.whoisxml_api_key,
                'domainName': domain,
                'outputFormat': 'JSON'
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})
                
                features = {}
                
                # Creation date
                creation_date = whois_record.get('createdDate')
                if creation_date:
                    created = datetime.strptime(creation_date[:10], '%Y-%m-%d')
                    age_days = (datetime.now() - created).days
                    features['domain_age_days'] = age_days
                    features['domain_age_months'] = age_days // 30
                    features['is_new_domain'] = age_days < 90
                    features['very_new_domain'] = age_days < 30
                
                # Expiry date
                expiry_date = whois_record.get('expiresDate')
                if expiry_date:
                    expires = datetime.strptime(expiry_date[:10], '%Y-%m-%d')
                    days_to_expiry = (expires - datetime.now()).days
                    features['domain_expires_soon'] = days_to_expiry < 90
                    features['domain_expires_very_soon'] = days_to_expiry < 30
                
                # Registrar
                registrar = whois_record.get('registrarName', '').lower()
                if registrar:
                    features['has_privacy_protection'] = 'privacy' in registrar
                    features['suspicious_registrar'] = any(word in registrar for word in 
                                                         ['cheap', 'free', 'anonymous'])
                
                return features
        
        except Exception as e:
            print(f"WhoisXML API error: {e}")
        
        return {}
    
    def _check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing"""
        cache_key = f"gsb_{hashlib.md5(url.encode()).hexdigest()}"
        cached = self._get_cached_result(cache_key, max_age_hours=1)
        if cached:
            return cached
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
            
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
                
                result = {
                    'gsb_threat_detected': len(threat_matches) > 0,
                    'gsb_threat_count': len(threat_matches),
                    'gsb_malware': any(m.get('threatType') == 'MALWARE' for m in threat_matches),
                    'gsb_social_engineering': any(m.get('threatType') == 'SOCIAL_ENGINEERING' for m in threat_matches),
                    'gsb_unwanted_software': any(m.get('threatType') == 'UNWANTED_SOFTWARE' for m in threat_matches)
                }
                
                self._cache_result(cache_key, result)
                return result
        
        except Exception as e:
            print(f"Google Safe Browsing error: {e}")
        
        return {}
    
    def _check_virustotal(self, url):
        """Check URL against VirusTotal"""
        cache_key = f"vt_{hashlib.md5(url.encode()).hexdigest()}"
        cached = self._get_cached_result(cache_key, max_age_hours=6)
        if cached:
            return cached
        
        try:
            # First submit URL
            headers = {'x-apikey': self.virustotal_api_key}
            data = {'url': url}
            
            response = requests.post(
                'https://www.virustotal.com/vtapi/v2/url/scan',
                files=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('scan_id')
                
                # Wait and get results
                time.sleep(3)
                
                params = {'apikey': self.virustotal_api_key, 'resource': scan_id}
                response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/url/report',
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    positives = data.get('positives', 0)
                    total = data.get('total', 0)
                    
                    result = {
                        'vt_detection_count': positives,
                        'vt_total_scans': total,
                        'vt_detection_ratio': positives / max(total, 1),
                        'vt_suspicious': positives > 0,
                        'vt_high_risk': positives > 5,
                        'vt_very_high_risk': positives > 10
                    }
                    
                    self._cache_result(cache_key, result)
                    return result
        
        except Exception as e:
            print(f"VirusTotal error: {e}")
        
        return {}
    
    def _check_typosquatting(self, domain):
        """Check for typosquatting indicators"""
        # Common legitimate domains to check against
        legitimate_domains = [
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'paypal.com', 'ebay.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'netflix.com', 'youtube.com'
        ]
        
        # Simple character substitution check
        for legit_domain in legitimate_domains:
            if self._calculate_similarity(domain.lower(), legit_domain) > 0.8:
                return True
        
        return False
    
    def _check_homograph_attack(self, domain):
        """Check for homograph attack indicators"""
        # Check for mixed scripts (basic check)
        has_latin = bool(re.search(r'[a-zA-Z]', domain))
        has_cyrillic = bool(re.search(r'[а-яё]', domain, re.IGNORECASE))
        
        return has_latin and has_cyrillic
    
    def _calculate_similarity(self, str1, str2):
        """Calculate simple string similarity"""
        if len(str1) == 0 or len(str2) == 0:
            return 0
        
        # Simple character-based similarity
        matches = sum(1 for a, b in zip(str1, str2) if a == b)
        return matches / max(len(str1), len(str2))
    
    def save_analysis_to_file(self, url, features):
        """Save analysis to local text file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"phishing_analysis_{timestamp}.txt"
            
            # Create directory if it doesn't exist
            os.makedirs('analysis_results', exist_ok=True)
            filepath = os.path.join('analysis_results', filename)
            
            analysis_data = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'features': features,
                'risk_score': self.calculate_risk_score(features),
                'classification': self.classify_url(features)
            }
            
            with open(filepath, 'w') as f:
                json.dump(analysis_data, f, indent=2, default=str)
            
            print(f"Analysis saved to: {filepath}")
            return filepath
        
        except Exception as e:
            print(f"Error saving analysis: {e}")
            return None
    
    def calculate_risk_score(self, features):
        """Calculate overall risk score from features"""
        risk_score = 0
        total_weight = 0
        
        # High risk features (weight: 10)
        high_risk_features = [
            'gsb_threat_detected', 'vt_high_risk', 'ssl_self_signed',
            'very_new_domain', 'excessive_phishing_keywords', 'has_login_forms'
        ]
        
        # Medium risk features (weight: 5)
        medium_risk_features = [
            'is_new_domain', 'multiple_redirects', 'has_suspicious_tld',
            'excessive_external_scripts', 'has_urgency_words', 'external_favicon'
        ]
        
        # Low risk features (weight: 2)
        low_risk_features = [
            'long_domain', 'excessive_hyphens', 'has_iframes',
            'phishing_keyword_count', 'has_forms', 'multiple_a_records'
        ]
        
        # Calculate weighted risk score
        for feature in high_risk_features:
            if features.get(feature, False):
                risk_score += 10
            total_weight += 10
        
        for feature in medium_risk_features:
            if features.get(feature, False):
                risk_score += 5
            total_weight += 5
        
        for feature in low_risk_features:
            if features.get(feature, False):
                risk_score += 2
            total_weight += 2
        
        # Normalize to 0-100 scale
        return int((risk_score / max(total_weight, 1)) * 100)
    
    def classify_url(self, features):
        """Classify URL based on features"""
        risk_score = self.calculate_risk_score(features)
        
        if risk_score >= 80:
            return 'malicious'
        elif risk_score >= 60:
            return 'suspicious'
        elif risk_score >= 40:
            return 'questionable'
        else:
            return 'safe'

def main():
    """Main function for command-line usage"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python feature_extractor.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    extractor = AdvancedFeatureExtractor()
    
    print(f"Analyzing URL: {url}")
    print("=" * 50)
    
    features = extractor.extract_all_features(url)
    risk_score = extractor.calculate_risk_score(features)
    classification = extractor.classify_url(features)
    
    print(f"\nRisk Score: {risk_score}/100")
    print(f"Classification: {classification.upper()}")
    print("\nFeatures detected:")
    print("-" * 30)
    
    for feature, value in sorted(features.items()):
        if value and not isinstance(value, str):
            print(f"✓ {feature}")
        elif isinstance(value, str) and 'error' not in feature.lower():
            print(f"  {feature}: {value}")
    
    # Save to file
    filepath = extractor.save_analysis_to_file(url, features)
    if filepath:
        print(f"\nDetailed analysis saved to: {filepath}")

if __name__ == "__main__":
    main()
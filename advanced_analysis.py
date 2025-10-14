"""
Advanced Analysis Module with External API Integration
Provides deep analysis of emails, URLs, IPs, domains, and files using security APIs

Supported APIs:
- VirusTotal: URL/File/IP/Domain reputation
- URLScan.io: URL screenshot and analysis
- AbuseIPDB: IP reputation
- Google Safe Browsing: URL safety check
- WHOIS: Domain age and registration info
- PhishTank: Known phishing URL database
- EmailRep.io: Email reputation and analysis
- Have I Been Pwned: Data breach checking
- Hybrid Analysis: File sandboxing
- GreyNoise: IP reputation
- URLhaus: Malicious URL database
"""

import requests
import hashlib
import time
import json
from urllib.parse import urlparse
import base64
import re
import requests
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple
from urllib.parse import urlparse, urljoin

# Add any other necessary imports here

# ==================== API CONFIGURATION ====================

class APIConfig:
    """Store API keys and endpoints"""
    
    # VirusTotal API (Free: 4 requests/min, 500/day)
    VIRUSTOTAL_API_KEY = "35c755941fde005d631efb8818c511992eaa02a1339fb426c0d258d23c0d0c23"  # Get from: https://www.virustotal.com/gui/join-us
    VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
    VIRUSTOTAL_FILE_SCAN = "https://www.virustotal.com/api/v3/files"
    VIRUSTOTAL_IP_REPORT = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VIRUSTOTAL_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/{domain}"
    
    # URLScan.io API (Free: 100 requests/day)
    URLSCAN_API_KEY = "0199a8c8-24d8-7778-b99e-cdcc25949636"  # Get from: https://urlscan.io/user/signup
    URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
    URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
    
    # AbuseIPDB API (Free: 1000 requests/day)
    ABUSEIPDB_API_KEY = "6d0c2a81233addb3a8ac244b3993b6741d257e18e2468b041356fb624568094c7991ce1f530dc771"  # Get from: https://www.abuseipdb.com/register
    ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
    
    # Google Safe Browsing API (Free: 10,000 requests/day)
    GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyC5ktexY3gnur3K1a-CZh3n1OiVNdJ6EUA"  # Get from: https://developers.google.com/safe-browsing
    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    # PhishTank API (Free, no key required)
    PHISHTANK_CHECK = "https://checkurl.phishtank.com/checkurl/"
    PHISHTANK_API_KEY = ""  # Optional, get from: https://www.phishtank.com/api_register.php
    
    # IPQualityScore API (Free: 5000 requests/month)
    IPQUALITYSCORE_API_KEY = ""  # Get from: https://www.ipqualityscore.com/create-account
    IPQUALITYSCORE_URL = "https://www.ipqualityscore.com/api/json/url/{api_key}/{url}"
    
    # WHOIS API (Free tier available)
    WHOIS_API_KEY = "at_95AvHuABoUos1W0Dds3oqXJwGXKS4"  # Get from: https://whoisxmlapi.com/
    WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    
    # Deep Analysis APIs
    EMAILREP_API_KEY = ""  # Get from: https://emailrep.io/signup
    HIBP_API_KEY = ""  # Get from: https://haveibeenpwned.com/API/Key
    HYBRID_ANALYSIS_API_KEY = ""  # Get from: https://www.hybrid-analysis.com/signup
    GREYNOISE_API_KEY = ""  # Get from: https://www.greynoise.io/viz/account/


# ==================== URL ANALYSIS ====================

class URLAnalyzer:
    """Analyze URLs using multiple security APIs"""
    
    @staticmethod
    def analyze_with_virustotal(url):
        """
        Analyze URL with VirusTotal
        Returns: dict with analysis results
        """
        if not APIConfig.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured", "available": False}
        
        try:
            headers = {
                "x-apikey": APIConfig.VIRUSTOTAL_API_KEY
            }
            
            # Submit URL for scanning
            data = {"url": url}
            response = requests.post(
                APIConfig.VIRUSTOTAL_URL_SCAN,
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                
                # Get analysis results
                time.sleep(2)  # Wait for analysis
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                    
                    return {
                        "available": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "undetected": stats.get('undetected', 0),
                        "total_scans": sum(stats.values()),
                        "verdict": "malicious" if stats.get('malicious', 0) > 0 else "clean",
                        "is_malicious": stats.get('malicious', 0) > 0,
                        "confidence": int((stats.get('malicious', 0) + (stats.get('suspicious', 0) * 0.5)) / max(1, sum(stats.values())) * 100) if stats else 0,
                        "permalink": f"https://www.virustotal.com/gui/url/{analysis_id}"
                    }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def analyze_with_urlscan(url):
        """
        Analyze URL with URLScan.io
        Returns: dict with screenshot and analysis
        """
        if not APIConfig.URLSCAN_API_KEY:
            return {"error": "URLScan.io API key not configured", "available": False}
        
        try:
            headers = {
                "API-Key": APIConfig.URLSCAN_API_KEY,
                "Content-Type": "application/json"
            }
            
            data = {
                "url": url,
                "visibility": "public"
            }
            
            response = requests.post(
                APIConfig.URLSCAN_SUBMIT,
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                uuid = result.get('uuid')
                
                # Wait for scan to complete
                time.sleep(10)
                
                result_url = APIConfig.URLSCAN_RESULT.format(uuid=uuid)
                result_response = requests.get(result_url, timeout=10)
                
                if result_response.status_code == 200:
                    scan_data = result_response.json()
                    
                    return {
                        "available": True,
                        "screenshot": scan_data.get('task', {}).get('screenshotURL'),
                        "verdict": scan_data.get('verdicts', {}).get('overall', {}).get('score', 0),
                        "malicious": scan_data.get('verdicts', {}).get('overall', {}).get('malicious', False),
                        "categories": scan_data.get('verdicts', {}).get('overall', {}).get('categories', []),
                        "report_url": result.get('result'),
                        "ip": scan_data.get('page', {}).get('ip'),
                        "country": scan_data.get('page', {}).get('country')
                    }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def check_google_safe_browsing(url):
        """
        Check URL with Google Safe Browsing
        Returns: dict with threat status
        """
        if not APIConfig.GOOGLE_SAFE_BROWSING_API_KEY:
            return {"error": "Google Safe Browsing API key not configured", "available": False}
        
        try:
            api_url = f"{APIConfig.GOOGLE_SAFE_BROWSING_URL}?key={APIConfig.GOOGLE_SAFE_BROWSING_API_KEY}"
            
            payload = {
                "client": {
                    "clientId": "phishguard-ai",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                matches = result.get('matches', [])
                
                if matches:
                    threat_types = [match.get('threatType') for match in matches]
                    return {
                        "available": True,
                        "is_threat": True,
                        "threat_types": threat_types,
                        "verdict": "malicious"
                    }
                else:
                    return {
                        "available": True,
                        "is_threat": False,
                        "verdict": "clean"
                    }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def check_phishtank(url):
        """
        Check URL against PhishTank database
        Returns: dict with phishing status
        """
        try:
            data = {
                "url": url,
                "format": "json"
            }
            
            if APIConfig.PHISHTANK_API_KEY:
                data["app_key"] = APIConfig.PHISHTANK_API_KEY
            
            response = requests.post(
                APIConfig.PHISHTANK_CHECK,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('results', {}).get('in_database'):
                    return {
                        "available": True,
                        "is_phishing": result['results']['valid'],
                        "phish_id": result['results'].get('phish_id'),
                        "verified": result['results'].get('verified'),
                        "verdict": "phishing" if result['results']['valid'] else "clean"
                    }
                else:
                    return {
                        "available": True,
                        "is_phishing": False,
                        "verdict": "not_in_database"
                    }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def is_suspicious_url(url):
        """Check for common phishing URL patterns with enhanced detection"""
        import re
        from urllib.parse import urlparse, parse_qs
        
        # List of suspicious keywords often found in phishing URLs (expanded list)
        suspicious_keywords = [
            # Account-related
            'login', 'signin', 'verify', 'account', 'update', 'security', 'password',
            'credential', 'confirm', 'billing', 'auth', 'authenticate', 'verification',
            'validate', 'identity', 'profile', 'settings', 'secure', 'unlock', 'reset',
            'change', 'recover', 'restore', 'access', 'authorize', 'validation',
            'passwordreset', 'changepassword', 'forgotpassword', 'accountrecovery',
            'accountverify', 'accountconfirm', 'accountsecurity', 'accountupdate',
            
            # Financial institutions (commonly spoofed)
            'paypal', 'banking', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
            'hsbc', 'barclays', 'santander', 'capitalone', 'americanexpress', 'visa',
            'mastercard', 'discover', 'amex', 'swift', 'routing', 'accountnumber',
            'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays',
            'santander', 'capitalone', 'americanexpress', 'visa', 'mastercard',
            
            # Government and tax related
            'irs', 'ssn', 'socialsecurity', 'taxrefund', 'taxreturn', 'incometax',
            'gov', 'government', 'irs-gov', 'ssa.gov', 'treasury', 'irsform',
            'socialsecurity', 'ssa', 'treasury', 'tax', 'irs', 'federal', 'state',
            
            # Common services (often phished)
            'amazon', 'ebay', 'paypal', 'netflix', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'instagram', 'linkedin', 'whatsapp', 'dropbox',
            'adobe', 'microsoftonline', 'office365', 'outlook', 'onedrive', 'teams',
            'skype', 'zoom', 'slack', 'discord', 'telegram', 'signal', 'whatsapp',
            
            # Urgency and warning words
            'urgent', 'immediate', 'actionrequired', 'suspended', 'verifynow',
            'securityalert', 'unauthorized', 'compromised', 'breach', 'hacked',
            'critical', 'important', 'warning', 'alert', 'attention', 'notice',
            'required', 'immediately', 'now', 'today', 'asap', 'final', 'last',
            
            # File and document related
            'document', 'invoice', 'statement', 'receipt', 'shipping', 'tracking',
            'order', 'purchase', 'transaction', 'payment', 'invoice', 'quotation',
            'bill', 'statement', 'receipt', 'shipping', 'tracking', 'order',
            'purchase', 'transaction', 'payment', 'invoice', 'quotation', 'bill'
        ]
        
        # Check for IP address in URL (often used in phishing)
        ip_match = re.search(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
        if ip_match:
            ip = ip_match.group(1)
            # Check if it's a private IP address (highly suspicious)
            if ip.startswith(('10.', '172.16.', '192.168.', '127.', '169.254.')):
                return True, f'URL contains private IP address ({ip}) - highly suspicious'
            return True, f'URL contains IP address ({ip}) instead of domain name'
            
        # Check for suspicious subdomains and paths
        domain_match = re.search(r'https?://([^/]+)', url.lower())
        if domain_match:
            domain = domain_match.group(1)
            
            # Check for suspicious subdomains
            for keyword in suspicious_keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', domain):
                    return True, f'Suspicious keyword in domain: {keyword} in {url}'
            
            # Check for domain impersonation (e.g., paypal-secure.com)
            for brand in ['paypal', 'ebay', 'amazon', 'bankofamerica', 'chase', 'wellsfargo']:
                if brand in domain and not domain.endswith(f'{brand}.com'):
                    return True, f'Potential brand impersonation: {brand} in {domain}'
        
        # Check for URL shorteners (often used to hide malicious URLs) - expanded list
        shorteners = [
            'bit\.ly', 'goo\.gl', 'tinyurl\.com', 't\.co', 'ow\.ly', 'is\.gd',
            'buff\.ly', 'tiny\.cc', 'cutt\.ly', 'short\.io', 'bit\.do', 'rebrand\.ly',
            'rb\.gy', 'cutt\.ly', 'shorturl\.at', 'shorte\.st', 'adf\.ly', 'bc\.vc',
            'v\.gd', 'tr\.im', 'soo\.gd', 's2r\.co', 'ity\.im', 'q\.gs', 'viralurl\.com',
            'x\.co', 'prettylinkpro\.com', 'adcraft\.co', 'adfoc\.us', 'adfly\.com'
        ]
        
        # Check for URL shorteners in the domain
        if any(re.search(shortener, url.lower()) for shortener in shorteners):
            # Check if the URL is trying to impersonate a legitimate service
            path = url.lower().split('?')[0]  # Remove query parameters
            if any(service in path for service in ['paypal', 'bank', 'login', 'signin']):
                return True, f'Suspicious: URL shortener used for {path} - potential phishing attempt'
            return True, f'URL uses a known URL shortener: {url}'
            
        # Check for non-standard ports (expanded list)
        if re.search(r':(8080|8443|2095|2096|2082|2083|2086|2087|2095|2096|81|82|83|84|85|86|88|8000|8081|8082|8083|8084|8085|8888|8880|8443|4433|4443|4444|4445|4446|4447|4448|4449|4450|8086|8087|8088|8089|8090|8091|8092|8093|8094|8095|9000|9001|9002|9003|9004|9005|9006|9007|9008|9009|9010)', url):
            return True, f'URL uses non-standard port: {url}'
            
        # Check for @ symbol in URL (potential credential phishing)
        if '@' in url:
            return True, 'URL contains @ symbol (potential credential phishing attempt)'
            
        # Check for hex-encoded characters (obfuscation)
        if '%' in url.lower() and re.search(r'%[0-9a-f]{2}', url.lower()):
            # Check if the URL is trying to hide a known domain
            decoded_url = requests.utils.unquote(url)
            for domain in ['paypal.com', 'ebay.com', 'amazon.com', 'bankofamerica.com']:
                if domain in decoded_url.lower() and domain not in url.lower():
                    return True, f'URL uses encoding to hide {domain} domain'
            return True, 'URL contains encoded characters (possible obfuscation)'
        
        # Check for HTTPS with suspicious patterns
        if url.lower().startswith('https'):
            # Check for HTTPS with IP address (uncommon for legitimate services)
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                return True, 'HTTPS used with IP address (uncommon for legitimate services)'
            
            # Check for HTTPS with non-standard port (can be used to bypass filters)
            if re.search(r'https://[^:]+:\d+', url):
                return True, 'HTTPS with non-standard port (potential bypass attempt)'
        
        # Check for excessive subdomains (common in phishing)
        if url.count('.') > 3:  # More than 3 dots is often suspicious
            domain_part = url.split('//')[-1].split('/')[0]
            if domain_part.count('.') > 3:
                return True, f'Excessive subdomains detected: {domain_part}'
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.icu', '.cyou', '.gdn']
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            return True, f'Suspicious TLD in URL: {url}'
        
        # Check for URL parameters that might be used for phishing
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Check for suspicious parameters
            suspicious_params = ['login', 'password', 'username', 'user', 'pass', 'pwd', 
                               'account', 'creditcard', 'ssn', 'dob', 'birthday', 'ccv', 'cvv']
            
            for param in query_params:
                if any(susp_param in param.lower() for susp_param in suspicious_params):
                    return True, f'Suspicious parameter in URL: {param}'
                    
        except Exception:
            pass
            
        return False, ''

    @staticmethod
    def analyze_url_comprehensive(url):
        """
        Run all URL checks and aggregate results with enhanced analysis
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Comprehensive analysis including results from all available sources
        """
        # Initialize results with default values
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "sources": [],
            "threats": [],
            "warnings": [],
            "scores": {
                "malicious": 0,
                "suspicious": 0,
                "clean": 0
            },
            "verdict": "clean",
            "is_malicious": False,
            "confidence": 0,
            "available": True,
            "details": {},
            "risk_factors": []
        }
        
        # Dictionary to store API results
        api_results = {}
        
        # First run heuristic analysis (most critical check)
        is_suspicious, reason = URLAnalyzer.is_suspicious_url(url)
        if is_suspicious:
            # Check if this is a high-severity indicator
            if 'highly suspicious' in reason.lower() or 'private IP' in reason:
                results['scores']['malicious'] += 2  # Higher weight for critical issues
                results['risk_factors'].append({
                    'factor': 'critical_heuristic',
                    'description': reason,
                    'severity': 'high'
                })
            else:
                results['scores']['suspicious'] += 1
                results['risk_factors'].append({
                    'factor': 'suspicious_heuristic',
                    'description': reason,
                    'severity': 'medium'
                })
            results['threats'].append(f'Heuristic Analysis: {reason}')
            results['sources'].append('Heuristic Analysis')
        
        # Check for URL shorteners (high risk for phishing)
        shorteners = [
            'bit\.ly', 'goo\.gl', 'tinyurl\.com', 't\.co', 'ow\.ly', 'is\.gd',
            'buff\.ly', 'tiny\.cc', 'cutt\.ly', 'short\.io', 'bit\.do', 'rebrand\.ly'
        ]
        if any(re.search(shortener, url.lower()) for shortener in shorteners):
            results['scores']['suspicious'] += 2  # Higher weight for URL shorteners
            results['risk_factors'].append({
                'factor': 'url_shortener',
                'description': 'URL uses a known URL shortening service',
                'severity': 'high'
            })
        
        # Check for IP address in URL (high risk)
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            results['scores']['malicious'] += 2  # High risk for IP-based URLs
            results['risk_factors'].append({
                'factor': 'ip_in_url',
                'description': 'URL contains an IP address instead of a domain name',
                'severity': 'high'
            })
        
        # Check for brand impersonation
        brand_keywords = ['paypal', 'ebay', 'amazon', 'bank', 'chase', 'wellsfargo', 'citibank']
        domain = url.split('//')[-1].split('/')[0].lower()
        for brand in brand_keywords:
            if brand in domain and not domain.endswith(f'{brand}.com'):
                results['scores']['suspicious'] += 1
                results['risk_factors'].append({
                    'factor': 'brand_impersonation',
                    'description': f'Possible {brand} brand impersonation in domain',
                    'severity': 'high'
                })
        
        # VirusTotal Analysis
        if APIConfig.VIRUSTOTAL_API_KEY:
            try:
                vt_result = URLAnalyzer.analyze_with_virustotal(url)
                api_results['virustotal'] = vt_result
                
                if vt_result.get('available', False):
                    if vt_result.get('verdict') == 'malicious':
                        results['scores']['malicious'] += 3  # High weight for VirusTotal malicious
                        results['threats'].append(f"VirusTotal: {vt_result.get('malicious', 0)} security vendors flagged this as malicious")
                        results['risk_factors'].append({
                            'factor': 'virustotal_malicious',
                            'description': f"{vt_result.get('malicious', 0)} security vendors flagged this as malicious",
                            'severity': 'critical'
                        })
                    elif vt_result.get('verdict') == 'suspicious':
                        results['scores']['suspicious'] += 2
                        results['risk_factors'].append({
                            'factor': 'virustotal_suspicious',
                            'description': 'URL flagged as suspicious by security vendors',
                            'severity': 'high'
                        })
                    else:
                        results['scores']['clean'] += 1
                    results['sources'].append('VirusTotal')
            except Exception as e:
                api_results['virustotal'] = {'error': str(e), 'available': False}
        
        # URLScan Analysis
        if APIConfig.URLSCAN_API_KEY:
            try:
                urlscan_result = URLAnalyzer.analyze_with_urlscan(url)
                api_results['urlscan'] = urlscan_result
                
                if urlscan_result.get('available', False):
                    if urlscan_result.get('malicious', False):
                        results['scores']['malicious'] += 2  # Medium weight for URLScan
                        results['threats'].append('URLScan: Suspicious activity detected')
                        results['risk_factors'].append({
                            'factor': 'urlscan_malicious',
                            'description': 'Suspicious activity detected by URLScan',
                            'severity': 'high'
                        })
                    else:
                        results['scores']['clean'] += 1
                    results['sources'].append('URLScan.io')
            except Exception as e:
                api_results['urlscan'] = {'error': str(e), 'available': False}
        
        # Google Safe Browsing
        if APIConfig.GOOGLE_SAFE_BROWSING_API_KEY:
            try:
                gsb_result = URLAnalyzer.check_google_safe_browsing(url)
                api_results['google_safe_browsing'] = gsb_result
                
                if gsb_result.get('available', False):
                    if gsb_result.get('is_threat', False):
                        results['scores']['malicious'] += 3  # High weight for Google Safe Browsing
                        threats = gsb_result.get('threats', ['Google Safe Browsing: Unsafe URL'])
                        results['threats'].extend(threats)
                        results['risk_factors'].append({
                            'factor': 'google_safe_browsing',
                            'description': 'URL flagged by Google Safe Browsing',
                            'severity': 'critical',
                            'details': threats
                        })
                    else:
                        results['scores']['clean'] += 1
                    results['sources'].append('Google Safe Browsing')
            except Exception as e:
                api_results['google_safe_browsing'] = {'error': str(e), 'available': False}
        
        # PhishTank (no API key required)
        try:
            phishtank_result = URLAnalyzer.check_phishtank(url)
            api_results['phishtank'] = phishtank_result
            
            if phishtank_result.get('available', False):
                if phishtank_result.get('is_phishing', False):
                    results['scores']['malicious'] += 1
                    results['threats'].append('PhishTank: Known phishing URL')
                else:
                    results['scores']['clean'] += 1
                results['sources'].append('PhishTank')
        except Exception as e:
            api_results['phishtank'] = {'error': str(e), 'available': False}
        
        # Add all API results to the main results
        results.update(api_results)
        
        # Check for suspicious URL patterns
        is_suspicious, reason = URLAnalyzer.is_suspicious_url(url)
        if is_suspicious:
            results['scores']['suspicious'] += 2  # Medium weight for suspicious patterns
            results['threats'].append(f'Suspicious URL pattern: {reason}')
            results['risk_factors'].append({
                'factor': 'suspicious_pattern',
                'description': f'Suspicious URL pattern: {reason}',
                'severity': 'high' if 'highly suspicious' in reason.lower() else 'medium'
            })
        
        # Calculate final verdict based on scores and risk factors
        total_checks = sum(results['scores'].values())
        print(f"\nURL Analysis Scores: {results['scores']}")
        print(f"Total checks: {total_checks}")
        
        if total_checks > 0:
            # Calculate weighted scores (malicious counts more than suspicious)
            malicious_weight = 3  # Each malicious flag is worth 3 points
            suspicious_weight = 2  # Each suspicious flag is worth 2 points
            clean_weight = 1  # Each clean flag is worth 1 point
            
            weighted_malicious = results['scores']['malicious'] * malicious_weight
            weighted_suspicious = results['scores']['suspicious'] * suspicious_weight
            weighted_clean = results['scores']['clean'] * clean_weight
            
            total_weighted_score = weighted_malicious + weighted_suspicious + weighted_clean
            
            # Calculate confidence based on the ratio of malicious/suspicious to total weighted score
            if total_weighted_score > 0:
                # Calculate threat ratio (0-1) where higher means more threatening
                threat_ratio = (weighted_malicious * 0.8 + weighted_suspicious * 0.5) / total_weighted_score
                
                # Adjust confidence based on number of checks (more checks = higher confidence)
                num_checks = sum(1 for source in results['sources'] if source != 'Heuristic Analysis')
                confidence_boost = min(0.3, num_checks * 0.05)  # Up to 30% confidence boost
                
                # Determine final verdict and confidence
                if weighted_malicious > 0 or threat_ratio >= 0.7:
                    results['verdict'] = 'malicious'
                    results['is_malicious'] = True
                    # Confidence is based on threat ratio and number of sources
                    results['confidence'] = min(100, int((threat_ratio + confidence_boost) * 100))
                    print(f"Verdict: MALICIOUS (Confidence: {results['confidence']}%)")
                elif threat_ratio >= 0.4 or weighted_suspicious > 0:
                    results['verdict'] = 'suspicious'
                    results['is_malicious'] = True  # Treat suspicious as malicious for safety
                    results['confidence'] = min(90, int((threat_ratio + confidence_boost) * 100))
                    print(f"Verdict: SUSPICIOUS (Confidence: {results['confidence']}%)")
                else:
                    results['verdict'] = 'clean'
                    results['is_malicious'] = False
                    results['confidence'] = min(100, int((1 - threat_ratio + confidence_boost) * 50 + 50))
                    print(f"Verdict: CLEAN (Confidence: {results['confidence']}%)")
            else:
                # Default to clean if no checks were performed
                results['verdict'] = 'clean'
                results['is_malicious'] = False
                results['confidence'] = 0
                print("Verdict: CLEAN (No checks performed)")
            
            # Special case: If we have any critical risk factors, mark as malicious
            critical_risks = [r for r in results.get('risk_factors', []) 
                            if r.get('severity') == 'critical']
            if critical_risks and results['verdict'] != 'malicious':
                results['verdict'] = 'malicious'
                results['is_malicious'] = True
                results['confidence'] = max(results['confidence'], 85)  # At least 85% confidence
                results['threats'].append('Critical risk factors detected')
                print("Verdict: MALICIOUS (Critical risk factors detected)")
            
            # Add summary of risk factors
            if results.get('risk_factors'):
                risk_summary = {
                    'critical': len([r for r in results['risk_factors'] if r.get('severity') == 'critical']),
                    'high': len([r for r in results['risk_factors'] if r.get('severity') == 'high']),
                    'medium': len([r for r in results['risk_factors'] if r.get('severity') == 'medium']),
                    'low': len([r for r in results['risk_factors'] if r.get('severity') == 'low'])
                }
                # Calculate suspicious score based on risk factors
                suspicious_score = min(1.0, (risk_summary['critical'] * 0.5 + 
                                           risk_summary['high'] * 0.3 + 
                                           risk_summary['medium'] * 0.15 + 
                                           risk_summary['low'] * 0.05))
                
                results['risk_summary'] = risk_summary
                print(f"Risk Summary: {risk_summary}")
                results['confidence'] = int(min(100, suspicious_score * 100))
                print(f"Verdict: SUSPICIOUS (Confidence: {results['confidence']}%)")
            else:
                # Calculate malicious score based on threat indicators
                malicious_score = min(1.0, len(results.get('threats', [])) * 0.2)
                results['verdict'] = 'clean'
                results['is_malicious'] = False
                results['confidence'] = 100 - int(malicious_score * 100)
                print(f"Verdict: CLEAN (Confidence: {results['confidence']}%)")
        
        # Ensure all required fields are present
        required_fields = ['url', 'timestamp', 'scores', 'verdict', 'is_malicious', 'confidence', 'available', 'details']
        for field in required_fields:
            if field not in results:
                results[field] = None
        # Add detailed analysis summary
        results['details'] = {
            'total_checks': total_checks,
            'malicious_indicators': len(results['threats']),
            'analysis_time': datetime.now().isoformat()
        }
        
        return results


# ==================== IP ANALYSIS ====================

class IPAnalyzer:
    """Analyze IP addresses for reputation and geolocation"""
    
    @staticmethod
    def analyze_with_virustotal(ip):
        """Get IP reputation from VirusTotal"""
        if not APIConfig.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured", "available": False}
        
        try:
            headers = {"x-apikey": APIConfig.VIRUSTOTAL_API_KEY}
            url = APIConfig.VIRUSTOTAL_IP_REPORT.format(ip=ip)
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "available": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "country": attributes.get('country'),
                    "asn": attributes.get('asn'),
                    "as_owner": attributes.get('as_owner'),
                    "verdict": "malicious" if stats.get('malicious', 0) > 0 else "clean"
                }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def check_abuseipdb(ip):
        """Check IP reputation with AbuseIPDB"""
        if not APIConfig.ABUSEIPDB_API_KEY:
            return {"error": "AbuseIPDB API key not configured", "available": False}
        
        try:
            headers = {
                "Key": APIConfig.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            
            response = requests.get(
                APIConfig.ABUSEIPDB_CHECK,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                
                return {
                    "available": True,
                    "abuse_confidence_score": ip_data.get('abuseConfidenceScore', 0),
                    "total_reports": ip_data.get('totalReports', 0),
                    "country": ip_data.get('countryCode'),
                    "is_whitelisted": ip_data.get('isWhitelisted', False),
                    "verdict": "malicious" if ip_data.get('abuseConfidenceScore', 0) > 50 else "clean"
                }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def analyze_ip_comprehensive(ip):
        """Run all IP checks"""
        results = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "virustotal": IPAnalyzer.analyze_with_virustotal(ip),
            "abuseipdb": IPAnalyzer.check_abuseipdb(ip)
        }
        
        # Calculate overall verdict
        malicious_count = 0
        total_checks = 0
        
        for service, data in results.items():
            if service in ['ip', 'timestamp']:
                continue
            if data.get('available'):
                total_checks += 1
                if data.get('verdict') == 'malicious':
                    malicious_count += 1
        
        results['overall_verdict'] = {
            "is_malicious": malicious_count > 0,
            "malicious_sources": malicious_count,
            "total_sources": total_checks,
            "confidence": (malicious_count / total_checks * 100) if total_checks > 0 else 0
        }
        
        return results


# ==================== DOMAIN ANALYSIS ====================

class DomainAnalyzer:
    """Analyze domains for age, reputation, and WHOIS info"""
    
    @staticmethod
    def get_whois_info(domain):
        """Get WHOIS information for domain"""
        if not APIConfig.WHOIS_API_KEY:
            return {"error": "WHOIS API key not configured", "available": False}
        
        try:
            params = {
                "apiKey": APIConfig.WHOIS_API_KEY,
                "domainName": domain,
                "outputFormat": "JSON"
            }
            
            response = requests.get(APIConfig.WHOIS_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})
                
                created_date = whois_record.get('createdDate', '')
                if created_date:
                    created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                    age_days = (datetime.now(created.tzinfo) - created).days
                else:
                    age_days = None
                
                return {
                    "available": True,
                    "created_date": created_date,
                    "age_days": age_days,
                    "registrar": whois_record.get('registrarName'),
                    "registrant": whois_record.get('registrant', {}).get('organization'),
                    "country": whois_record.get('registrant', {}).get('country'),
                    "is_recently_registered": age_days < 30 if age_days else False
                }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def analyze_with_virustotal(domain):
        """Get domain reputation from VirusTotal"""
        if not APIConfig.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured", "available": False}
        
        try:
            headers = {"x-apikey": APIConfig.VIRUSTOTAL_API_KEY}
            url = APIConfig.VIRUSTOTAL_DOMAIN_REPORT.format(domain=domain)
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "available": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "categories": attributes.get('categories', {}),
                    "verdict": "malicious" if stats.get('malicious', 0) > 0 else "clean"
                }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}
    
    @staticmethod
    def analyze_domain_comprehensive(domain):
        """Run all domain checks with enhanced malicious domain detection"""
        print(f"\n=== Starting analysis for domain: {domain} ===")
        domain = domain.lower().strip()
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "whois": DomainAnalyzer.get_whois_info(domain),
            "virustotal": DomainAnalyzer.analyze_with_virustotal(domain)
        }
        print(f"Initial results: {json.dumps(results, indent=2, default=str)}")
        
        
        # Initialize risk assessment
        risk_score = 0
        risk_factors = []
        
        # Extract domain parts for analysis
        domain_parts = domain.split('.')
        domain_name = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain
        
        # Check WHOIS information
        whois_data = results.get('whois', {})
        print(f"WHOIS data: {json.dumps(whois_data, indent=2, default=str)}")
        
        if whois_data.get('available'):
            # Penalize recently registered domains (more aggressive for very new domains)
            age_days = whois_data.get('age_days')
            print(f"Domain age: {age_days} days")
            
            if age_days is not None:
                if age_days < 7:  # Less than a week old
                    risk_score += 40
                    risk_factors.append({
                        'severity': 'high',
                        'description': f'Domain was registered very recently (only {age_days} days ago)'
                    })
                    print(f"Added 40 points for very recent domain (age: {age_days} days)")
                elif age_days < 30:  # Less than a month old
                    risk_score += 25
                    risk_factors.append({
                        'severity': 'medium',
                        'description': f'Domain was registered recently ({age_days} days ago)'
                    })
                    print(f"Added 25 points for recently registered domain (age: {age_days} days)")
            
            # Check for suspicious TLDs (expanded list)
            suspicious_tlds = [
                # Free domains
                '.xyz', '.top', '.gq', '.ml', '.cf', '.ga', '.tk', '.pw', '.club', '.info',
                '.biz', '.online', '.site', '.webcam', '.work', '.party', '.gdn', '.cyou',
                # Country TLDs with high abuse rates
                '.ru', '.cn', '.br', '.in', '.uk', '.pl', '.br', '.ro', '.nl', '.fr',
                # Newer TLDs often used for abuse
                '.guru', '.expert', '.services', '.support', '.accountant', '.win', '.bid',
                '.download', '.stream', '.gratis', '.loan', '.men', '.pics', '.sexy', '.top',
                '.cricket', '.date', '.faith', '.review', '.science', '.trade', '.party'
            ]
            
            tld_matches = [tld for tld in suspicious_tlds if domain.endswith(tld)]
            if tld_matches:
                risk_score += 25  # Increased from 20
                risk_factors.append({
                    'severity': 'medium',
                    'description': f'Domain uses a TLD ({tld_matches[0]}) commonly associated with malicious activity'
                })
                print(f"Added 25 points for suspicious TLD: {tld_matches[0]}")
            else:
                print("No suspicious TLDs found")
        
        # Check VirusTotal reputation
        vt_data = results.get('virustotal', {})
        print(f"VirusTotal data: {json.dumps(vt_data, indent=2, default=str)}")
        
        if vt_data.get('available'):
            # More aggressive scoring for VirusTotal detections
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            
            print(f"VirusTotal - Malicious: {malicious}, Suspicious: {suspicious}")
            
            if malicious > 0:
                vt_score = 60 + (min(malicious, 10) * 5)  # 60-110 points for malicious
                risk_score += vt_score
                risk_factors.append({
                    'severity': 'critical',
                    'description': f'Domain flagged as malicious by {malicious} security vendors on VirusTotal'
                })
                print(f"Added {vt_score} points for {malicious} malicious detections on VirusTotal")
            elif suspicious > 0:  # Only consider suspicious if no malicious flags
                vt_score = 30 + (min(suspicious, 5) * 6)  # 30-60 points for suspicious
                risk_score += vt_score
                risk_factors.append({
                    'severity': 'high',
                    'description': f'Domain flagged as suspicious by {suspicious} security vendors on VirusTotal'
                })
                print(f"Added {vt_score} points for {suspicious} suspicious detections on VirusTotal")
            else:
                print("No malicious or suspicious detections on VirusTotal")
        
        # Enhanced domain name analysis with aggressive keyword detection
        suspicious_keywords = [
            # Account/security related (high risk)
            'login', 'logon', 'signin', 'signon', 'verify', 'verification', 'authenticate', 'authentication',
            'account', 'profile', 'billing', 'payment', 'invoice', 'transaction', 'statement', 'purchase',
            'password', 'credential', 'security', 'secure', 'ssl', 'encrypt', 'validation', 'confirmation',
            'update', 'change', 'reset', 'recover', 'restore', 'unlock', 'verifyaccount', 'accountupdate',
            
            # Financial institutions (high risk)
            'bank', 'paypal', 'venmo', 'cashapp', 'zelle', 'chase', 'wellsfargo', 'bankofamerica', 
            'citibank', 'hsbc', 'barclays', 'santander', 'capitalone', 'americanexpress', 'amex', 'visa', 
            'mastercard', 'discover', 'swift', 'routing', 'accountnumber', 'card', 'debit', 'credit',
            
            # Government and tax related (high risk)
            'irs', 'ssn', 'socialsecurity', 'tax', 'refund', 'incometax', 'gov', 'government', 'treasury',
            
            # Common services (often phished)
            'amazon', 'ebay', 'netflix', 'microsoft', 'apple', 'google', 'facebook', 'twitter', 'instagram',
            'linkedin', 'whatsapp', 'dropbox', 'adobe', 'microsoftonline', 'office365', 'outlook', 'onedrive',
            
            # Urgency and warning words (medium risk)
            'urgent', 'immediate', 'actionrequired', 'suspended', 'verifynow', 'securityalert', 'unauthorized',
            'compromised', 'breach', 'hacked', 'limitedtime', 'expire', 'expiring', 'expiration', 'warning',
            
            # Free/prize related (medium risk)
            'free', 'win', 'winner', 'won', 'prize', 'reward', 'gift', 'bonus', 'offer', 'discount', 'coupon',
            
            # Document related (medium risk)
            'document', 'file', 'attachment', 'download', 'view', 'open', 'click', 'here', 'now', 'see', 'watch',
            
            # Common typos and variations (very high risk)
            'paypa1', 'paypaI', 'paypal1', 'micr0soft', 'micosoft', 'facebo0k', 'tw1tter', 'g00gle', 'app1e',
            '1ogin', 'secure-', '-secure', 'account-', '-account', 'verify-', '-verify', 'update-', '-update'
        ]
        
        
        # Aggressive keyword matching with weighted scoring
        matched_keywords = []
        keyword_scores = {
            'high': 30,     # High risk keywords (financial, security, etc.)
            'medium': 15,   # Medium risk (urgency, documents, etc.)
            'low': 5        # Low risk (common words that could be legitimate)
        }
        
        # Categorize keywords by risk level
        high_risk_kws = [
            'login', 'logon', 'signin', 'signon', 'verify', 'verification', 'authenticate', 'authentication',
            'account', 'password', 'credential', 'security', 'secure', 'bank', 'paypal', 'venmo', 'cashapp',
            'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'santander', 'visa',
            'mastercard', 'amex', 'americanexpress', 'discover', 'swift', 'routing', 'ssn', 'socialsecurity',
            'irs', 'tax', 'refund', 'creditcard', 'debitcard', 'card', 'paypa1', 'paypaI', 'micr0soft', '1ogin'
        ]
        
        medium_risk_kws = [
            'update', 'change', 'reset', 'recover', 'restore', 'unlock', 'billing', 'payment', 'invoice',
            'urgent', 'immediate', 'actionrequired', 'suspended', 'verifynow', 'securityalert', 'unauthorized',
            'compromised', 'breach', 'hacked', 'limitedtime', 'expire', 'expiring', 'expiration', 'warning',
            'free', 'win', 'winner', 'won', 'prize', 'reward', 'gift', 'bonus', 'offer', 'document', 'file',
            'attachment', 'download', 'click', 'micosoft', 'facebo0k', 'tw1tter', 'g00gle', 'app1e'
        ]
        
        # Check for high risk keywords
        high_risk_matches = [kw for kw in high_risk_kws if kw in domain]
        if high_risk_matches:
            risk_score += keyword_scores['high'] * min(3, len(high_risk_matches))  # Max 90 points
            matched_keywords.extend(high_risk_matches)
            risk_factors.append({
                'severity': 'high',
                'description': f'High risk keywords detected: {", ".join(high_risk_matches[:3])}'
            })
        
        # Check for medium risk keywords (only if no high risk found)
        if not high_risk_matches:
            medium_risk_matches = [kw for kw in medium_risk_kws if kw in domain]
            if medium_risk_matches:
                risk_score += keyword_scores['medium'] * min(2, len(medium_risk_matches))  # Max 30 points
                matched_keywords.extend(medium_risk_matches)
                risk_factors.append({
                    'severity': 'medium',
                    'description': f'Medium risk keywords detected: {", ".join(medium_risk_matches[:3])}'
                })
        
        # Check for suspicious patterns (typosquatting, etc.)
        suspicious_patterns = [
            (r'[0-9]{4,}', 'Contains suspicious number sequence'),  # 4+ digit numbers
            (r'[^a-z0-9.-]', 'Contains special characters'),        # Unusual characters
            (r'([a-z])\1{2,}', 'Repeated characters'),              # aaa, bbbb, etc.
            (r'\d+[a-z]\d+', 'Number-letter-number pattern')       # 1a2, 3b4, etc.
        ]
        
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, domain):
                risk_score += 15
                risk_factors.append({
                    'severity': 'medium',
                    'description': desc
                })
                break  # Only count one pattern match to avoid excessive scoring
        
        # Check for IP address in domain (more comprehensive check)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', domain.split('/')[0]):
            risk_score += 50  # Increased from 40
            risk_factors.append({
                'severity': 'high',
                'description': 'Domain is an IP address, which is highly unusual for legitimate services'
            })
        
        # Check for typosquatting (common misspellings of popular domains)
        popular_domains = [
            'paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
            'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays',
            'ebay', 'whatsapp', 'linkedin', 'twitter', 'instagram', 'dropbox', 'adobe'
        ]
        
        for popular in popular_domains:
            if popular in domain and domain != popular + '.com':
                # Check for character omissions/additions/substitutions
                if len(domain) <= len(popular) + 5:  # Only check if length is similar
                    if any(domain == popular[:i] + popular[i+1:] + '.com' for i in range(len(popular))) or \
                       any(domain == popular[:i] + popular[i+1:] + x + '.com' for i in range(len(popular)) for x in 'abcdefghijklmnopqrstuvwxyz'):
                        risk_score += 60  # Very high risk for typosquatting
                        risk_factors.append({
                            'severity': 'critical',
                            'description': f'Domain appears to be a typosquatting attempt on {popular}.com'
                        })
                        break
        
        # Check for subdomain count (too many subdomains can be suspicious)
        if domain.count('.') > 3:  # More than 3 dots indicates multiple subdomains
            risk_score += 15
            risk_factors.append({
                'severity': 'low',
                'description': 'Multiple subdomains detected, which can be used for phishing'
            })
        
        # Check for domain reputation using additional sources (if available)
        # This is a placeholder - in a real implementation, you would call additional APIs here
        
        # Lower thresholds to catch more potential threats
        is_malicious = risk_score >= 50  # Lowered from 60
        is_suspicious = risk_score >= 25  # Lowered from 35
        
        # Cap confidence at 100%
        confidence = min(100, risk_score + 20)  # Add 20 to confidence to make it more aggressive
        
        verdict = "malicious" if is_malicious else "suspicious" if is_suspicious else "clean"
        
        print("\n=== Final Risk Assessment ===")
        print(f"Total Risk Score: {risk_score}")
        print(f"Thresholds - Malicious: >=60, Suspicious: >=35")
        print(f"Final Verdict: {verdict} (Confidence: {confidence}%)")
        print("Risk Factors:")
        for factor in risk_factors:
            print(f"- {factor['severity'].upper()}: {factor['description']}")
        
        # Add overall verdict to results
        results['overall_verdict'] = {
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "confidence": confidence,
            "verdict": verdict
        }
        
        print("\n=== Analysis Complete ===\n")
        
        return results


# ==================== FILE ANALYSIS ====================

class FileAnalyzer:
    """Analyze file hashes and attachments"""
    
    @staticmethod
    def calculate_file_hash(file_content):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest()
        }
    
    @staticmethod
    def check_virustotal_hash(file_hash):
        """Check file hash against VirusTotal"""
        if not APIConfig.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured", "available": False}
        
        try:
            headers = {"x-apikey": APIConfig.VIRUSTOTAL_API_KEY}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "available": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "file_type": attributes.get('type_description'),
                    "file_size": attributes.get('size'),
                    "verdict": "malicious" if stats.get('malicious', 0) > 0 else "clean",
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                return {
                    "available": True,
                    "verdict": "not_found",
                    "message": "File not in VirusTotal database"
                }
            
            return {"error": f"API returned status {response.status_code}", "available": False}
            
        except Exception as e:
            return {"error": str(e), "available": False}


class DeepEmailAnalyzer:
    """Advanced email analysis with comprehensive threat detection
    
    Features:
    1.1 - Header forensics and authentication analysis
    1.2 - Advanced content analysis with NLP and pattern matching
    1.3 - Dynamic link analysis and redirection tracking
    1.4 - Attachment and embedded content analysis
    1.6 - Threat intelligence correlation
    1.8 - Sender identity and reputation analysis
    """
    
    def __init__(self):
        # Initialize free API endpoints
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
        self.haveibeenpwned_api = "https://haveibeenpwned.com/api/v3/"
        self.haveibeenpwned_api_key = APIConfig.HIBP_API_KEY
        
        # Initialize analysis caches
        self._url_cache = {}
        self._domain_cache = {}
        self._ip_cache = {}
        
        # Common phishing keywords and patterns
        self.phishing_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'action required',
            'login', 'password', 'security', 'alert', 'unauthorized',
            'update', 'confirm', 'limited time', 'offer', 'prize',
            'win', 'free', 'bank', 'paypal', 'amazon', 'microsoft',
            'apple', 'netflix', 'credit card', 'ssn', 'social security'
        ]
        
        # Known legitimate domains that are often spoofed
        self.common_spoofed_domains = [
            'paypal.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'netflix.com', 'bankofamerica.com', 'wellsfargo.com', 'chase.com'
        ]
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = ['.xyz', '.top', '.gq', '.ml', '.cf', '.ga', '.tk']
    
    # ==================== 1.1 Header Analysis ====================
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze email headers for signs of spoofing and anomalies"""
        analysis = {
            'anomalies': [],
            'spf': self._check_spf(headers),
            'dkim': self._check_dkim(headers),
            'dmarc': self._check_dmarc(headers),
            'from_domain': self._extract_domain(headers.get('From', '')),
            'return_path': self._extract_domain(headers.get('Return-Path', '')),
            'verdict': 'clean'
        }
        
        # Check for mismatches in sender domains
        if analysis['from_domain'] and analysis['return_path']:
            if analysis['from_domain'] != analysis['return_path']:
                analysis['anomalies'].append('from_return_path_mismatch')
        
        # Check for suspicious email clients
        mailer = headers.get('X-Mailer', '').lower()
        suspicious_clients = ['phpmail', 'microsoft smtp', 'outlook express']
        if any(client in mailer for client in suspicious_clients):
            analysis['anomalies'].append('suspicious_mailer')
        
        # Set overall verdict
        if analysis['anomalies'] or not all([analysis['spf'], analysis['dkim'], analysis['dmarc']]):
            analysis['verdict'] = 'suspicious'
            
        return analysis
    
    def _check_spf(self, headers: Dict[str, str]) -> bool:
        """Check SPF record for the sending domain"""
        auth_results = headers.get('Authentication-Results', '').lower()
        return 'spf=pass' in auth_results
    
    def _check_dkim(self, headers: Dict[str, str]) -> bool:
        """Verify DKIM signature if present"""
        auth_results = headers.get('Authentication-Results', '').lower()
        return 'dkim=pass' in auth_results
    
    def _check_dmarc(self, headers: Dict[str, str]) -> bool:
        """Check DMARC policy for the sending domain"""
        auth_results = headers.get('Authentication-Results', '').lower()
        return 'dmarc=pass' in auth_results
    
    def _extract_domain(self, email_header: str) -> str:
        """Extract domain from email header"""
        if not email_header:
            return ''
        # Extract email from header if in format "Name <email@domain.com>"
        email_match = re.search(r'<([^>]+)>', email_header)
        if email_match:
            email = email_match.group(1)
        else:
            email = email_header
        # Extract domain part
        if '@' in email:
            return email.split('@')[1].lower()
        return ''
    
    # ==================== 1.2 Content Analysis ====================
    
    def analyze_content(self, email_body: str, content_type: str = 'text/plain') -> Dict[str, Any]:
        """Analyze email content for phishing indicators"""
        analysis = {
            'suspicious_keywords': [],
            'suspicious_patterns': [],
            'verdict': 'clean',
            'score': 0
        }
        
        # Convert HTML to text if needed
        if content_type == 'text/html':
            text_content = self._html_to_text(email_body)
        else:
            text_content = email_body
        
        # Check for suspicious keywords
        text_lower = text_content.lower()
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                analysis['suspicious_keywords'].append(keyword)
        
        # Check for common phishing patterns
        patterns = [
            (r'\b(?:verify|update|confirm)\s+your\s+account\b', 'account_verification_request'),
            (r'\b(?:urgent|immediate|action\s+required)\b', 'urgency_indicators'),
            (r'\b(?:click\s+here|login|password|credentials)\b', 'credential_request')
        ]
        
        for pattern, pattern_name in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                analysis['suspicious_patterns'].append(pattern_name)
        
        # Calculate score
        analysis['score'] = len(analysis['suspicious_keywords']) + (len(analysis['suspicious_patterns']) * 2)
        if analysis['score'] > 5:
            analysis['verdict'] = 'high_risk'
        elif analysis['score'] > 2:
            analysis['verdict'] = 'medium_risk'
        
        return analysis
    
    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text for analysis"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.extract()
            return soup.get_text(separator=' ')
        except:
            return html
    
    # ==================== 1.3 Link Analysis ====================
    
    def analyze_links(self, email_body: str, content_type: str = 'text/plain') -> Dict[str, Any]:
        """Analyze all links in the email body"""
        results = {
            'links': [],
            'suspicious_links': [],
            'verdict': 'clean'
        }
        
        # Extract links based on content type
        if content_type == 'text/html':
            links = self._extract_links_from_html(email_body)
        else:
            links = self._extract_links_from_text(email_body)
        
        # Analyze each link
        for link in links:
            link_analysis = self._analyze_single_link(link['url'], link.get('text', ''))
            results['links'].append(link_analysis)
            
            if link_analysis['is_suspicious']:
                results['suspicious_links'].append(link_analysis)
        
        # Set overall verdict
        if results['suspicious_links']:
            results['verdict'] = 'suspicious'
            
        return results
    
    def _extract_links_from_html(self, html: str) -> List[Dict]:
        """Extract links from HTML content"""
        links = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                links.append({
                    'url': a['href'],
                    'text': a.get_text().strip(),
                    'element': 'a'
                })
        except Exception as e:
            print(f"Error extracting links from HTML: {e}")
        return links
    
    def _extract_links_from_text(self, text: str) -> List[Dict]:
        """Extract links from plain text using regex"""
        import re
        url_pattern = r'https?://[^\s\n<>"]+'
        return [{'url': url, 'text': '', 'element': 'text'} 
               for url in re.findall(url_pattern, text)]
    
    def _analyze_single_link(self, url: str, display_text: str = '') -> Dict:
        """Analyze a single URL for suspicious characteristics"""
        analysis = {
            'url': url,
            'display_text': display_text,
            'domain': self._extract_domain_from_url(url),
            'is_suspicious': False,
            'issues': []
        }
        
        # Check for mismatched display text
        if display_text and url != display_text and not display_text.startswith('http'):
            analysis['issues'].append('mismatched_display_text')
        
        # Check for IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            analysis['issues'].append('ip_in_url')
        
        # Check for suspicious TLDs
        domain = analysis['domain']
        if domain and any(domain.endswith(tld) for tld in self.suspicious_tlds):
            analysis['issues'].append('suspicious_tld')
        
        # Check if domain is commonly spoofed
        if domain in self.common_spoofed_domains:
            analysis['issues'].append('commonly_spoofed_domain')
        
        # Set overall suspicious flag if any issues found
        if analysis['issues']:
            analysis['is_suspicious'] = True
            
        return analysis
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            # Remove port number if present
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain.lower()
        except:
            return ''
    
    # ==================== 1.4 Attachment Analysis ====================
    
    def analyze_attachment(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Analyze email attachment for potential threats"""
        analysis = {
            'filename': filename,
            'file_size': len(file_content),
            'file_type': self._detect_file_type(filename, file_content),
            'is_executable': False,
            'is_archive': False,
            'contains_macros': False,
            'verdict': 'clean',
            'warnings': []
        }
        
        # Check file extension vs actual content
        ext_mismatch = self._check_extension_mismatch(filename, file_content)
        if ext_mismatch:
            analysis['warnings'].append(f'File extension mismatch: {ext_mismatch}')
        
        # Check for executable files
        if self._is_potentially_executable(filename, file_content):
            analysis['is_executable'] = True
            analysis['verdict'] = 'high_risk'
            analysis['warnings'].append('File appears to be executable')
        
        # Check for Office documents with macros
        if self._has_potential_macros(filename, file_content):
            analysis['contains_macros'] = True
            analysis['warnings'].append('Document may contain macros')
            if analysis['verdict'] != 'high_risk':
                analysis['verdict'] = 'medium_risk'
        
        return analysis
    
    def _detect_file_type(self, filename: str, content: bytes) -> str:
        """Detect file type using magic numbers and extension"""
        # This is a simplified version - in production, use python-magic or similar
        file_signatures = {
            b'\x50\x4B\x03\x04': 'zip',
            b'\x52\x61\x72\x21': 'rar',
            b'\x25\x50\x44\x46': 'pdf',
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'doc',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'docx',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'xlsx',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'pptx',
        }
        
        # Check magic numbers
        for signature, file_type in file_signatures.items():
            if content.startswith(signature):
                return file_type
        
        # Fall back to extension
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        return ext if ext else 'unknown'
    
    def _check_extension_mismatch(self, filename: str, content: bytes) -> Optional[str]:
        """Check if file extension matches actual content"""
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        detected_type = self._detect_file_type('', content[:100])  # Check first 100 bytes
        
        if detected_type and ext and detected_type != ext:
            return f'Extension .{ext} does not match detected type {detected_type}'
        return None
    
    def _is_potentially_executable(self, filename: str, content: bytes) -> bool:
        """Check if file is potentially executable"""
        executable_extensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'jar']
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        
        # Check extension
        if ext in executable_extensions:
            return True
            
        # Check for shebang in text files
        if ext in ['sh', 'py', 'pl', 'rb'] and content.startswith(b'#!'):
            return True
            
        # Check for PE header (Windows executables)
        if content.startswith(b'MZ'):
            return True
            
        return False
    
    def _has_potential_macros(self, filename: str, content: bytes) -> bool:
        """Check if Office document might contain macros"""
        office_extensions = ['doc', 'xls', 'ppt', 'docm', 'xlsm', 'pptm']
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        
        if ext not in office_extensions:
            return False
            
        # Simple check for OLE Compound Document format
        if content.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            # Look for VBA project streams (simplified)
            return b'VBA' in content or b'vbaProject.bin' in content
            
        return False
    
    # ==================== 1.6 Threat Intelligence ====================
    
    def check_threat_intel(self, indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Check indicators against threat intelligence sources"""
        results = {
            'ip_reputation': {},
            'domain_reputation': {},
            'file_reputation': {},
            'url_reputation': {},
            'verdict': 'clean'
        }
        
        # Check IPs with AbuseIPDB if API key is available
        if APIConfig.ABUSEIPDB_API_KEY:
            for ip in indicators.get('ips', []):
                results['ip_reputation'][ip] = self._check_ip_reputation(ip)
        
        # Check domains with VirusTotal if API key is available
        if APIConfig.VIRUSTOTAL_API_KEY:
            for domain in indicators.get('domains', []):
                results['domain_reputation'][domain] = self._check_domain_reputation(domain)
            
            # Check file hashes
            for file_hash in indicators.get('hashes', []):
                results['file_reputation'][file_hash] = self._check_hash_reputation(file_hash)
        
        # Check URLs with URLhaus (no API key needed)
        for url in indicators.get('urls', []):
            results['url_reputation'][url] = self._check_url_reputation(url)
        
        # Determine overall verdict
        if any(r.get('malicious', False) for r in results['ip_reputation'].values()):
            results['verdict'] = 'malicious'
        elif any(r.get('suspicious', False) for r in results['ip_reputation'].values()):
            results['verdict'] = 'suspicious'
        
        return results
    
    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB"""
        result = {
            'ip': ip,
            'malicious': False,
            'suspicious': False,
            'sources': {}
        }
        
        try:
            headers = {
                'Key': APIConfig.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                result['sources']['abuseipdb'] = {
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt')
                }
                
                if data.get('abuseConfidenceScore', 0) > 50:
                    result['malicious'] = True
                elif data.get('abuseConfidenceScore', 0) > 20:
                    result['suspicious'] = True
                    
        except Exception as e:
            result['sources']['abuseipdb'] = {'error': str(e)}
        
        return result
    
    def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using VirusTotal"""
        result = {
            'domain': domain,
            'malicious': False,
            'suspicious': False,
            'sources': {}
        }
        
        try:
            headers = {'x-apikey': APIConfig.VIRUSTOTAL_API_KEY}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result['sources']['virustotal'] = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
                
                if stats.get('malicious', 0) > 0:
                    result['malicious'] = True
                elif stats.get('suspicious', 0) > 0:
                    result['suspicious'] = True
                    
        except Exception as e:
            result['sources']['virustotal'] = {'error': str(e)}
        
        return result
    
    def _check_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against VirusTotal"""
        result = {
            'hash': file_hash,
            'malicious': False,
            'suspicious': False,
            'sources': {}
        }
        
        if len(file_hash) not in [32, 40, 64]:  # MD5, SHA1, SHA256
            return result
            
        try:
            headers = {'x-apikey': APIConfig.VIRUSTOTAL_API_KEY}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result['sources']['virustotal'] = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'type': data.get('data', {}).get('attributes', {}).get('type_description', 'unknown')
                }
                
                if stats.get('malicious', 0) > 0:
                    result['malicious'] = True
                elif stats.get('suspicious', 0) > 0:
                    result['suspicious'] = True
                    
        except Exception as e:
            result['sources']['virustotal'] = {'error': str(e)}
        
        return result
    
    def _check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using URLhaus"""
        result = {
            'url': url,
            'malicious': False,
            'sources': {}
        }
        
        try:
            response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('url_status') == 'online':
                    result['sources']['urlhaus'] = {
                        'threat': data.get('threat'),
                        'tags': data.get('tags', []),
                        'first_seen': data.get('date_added')
                    }
                    result['malicious'] = True
                else:
                    result['sources']['urlhaus'] = {'status': 'clean'}
                    
        except Exception as e:
            result['sources']['urlhaus'] = {'error': str(e)}
        
        return result
    
    # ==================== 1.8 Sender Analysis ====================
    
    def analyze_sender(self, email_headers: Dict[str, str], from_email: str) -> Dict[str, Any]:
        """Analyze sender information and reputation"""
        analysis = {
            'email': from_email,
            'domain': self._extract_domain(from_email),
            'spf': False,
            'dkim': False,
            'dmarc': False,
            'reputation': 'neutral',
            'anomalies': [],
            'verdict': 'clean'
        }
        
        # Extract domain from email
        if '@' in from_email:
            analysis['domain'] = from_email.split('@')[1].lower()
        
        # Check authentication headers
        auth_results = email_headers.get('Authentication-Results', '').lower()
        analysis['spf'] = 'spf=pass' in auth_results
        analysis['dkim'] = 'dkim=pass' in auth_results
        analysis['dmarc'] = 'dmarc=pass' in auth_results
        
        # Check for common spoofed domains
        if analysis['domain'] in self.common_spoofed_domains:
            analysis['anomalies'].append('common_spoofed_domain')
        
        # Check domain age (simplified)
        domain_age = self._get_domain_age(analysis['domain'])
        if domain_age:
            analysis['domain_age_days'] = domain_age
            if domain_age < 30:  # Very new domain
                analysis['anomalies'].append('new_domain')
        
        # Check for suspicious patterns in email
        if self._is_suspicious_email(from_email):
            analysis['anomalies'].append('suspicious_email_pattern')
        
        # Set reputation and verdict
        if not all([analysis['spf'], analysis['dkim'], analysis['dmarc']]):
            analysis['reputation'] = 'low'
            analysis['verdict'] = 'suspicious'
        
        if analysis['anomalies']:
            analysis['verdict'] = 'suspicious'
        
        return analysis
    
    def _get_domain_age(self, domain: str) -> Optional[int]:
        """Get domain age in days (simplified)"""
        try:
            import whois
            from datetime import datetime
            
            domain_info = whois.whois(domain)
            
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            if creation_date:
                age = (datetime.now() - creation_date).days
                return max(0, age)
                
        except Exception:
            pass
            
        return None
    
    def _is_suspicious_email(self, email: str) -> bool:
        """Check for suspicious email patterns"""
        suspicious_patterns = [
            r'\d{10}@',  # Numbers at the start
            r'[a-f0-9]{32}@',  # MD5 hash as username
            r'[0-9]{4,}@',  # Many numbers in username
            r'[a-z]\.[a-z]@',  # Single letters separated by dots
            r'[^@]+\+[^@]+@',  # Plus addressing (can be used for tracking)
            r'[^@]+\.(jpg|png|gif|pdf)@'  # Username looks like a filename
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return True
                
        return False
    
    # ==================== Email Reputation (Existing Method) ====================
    
    def check_email_reputation(self, email: str) -> Dict[str, Any]:
        """
        Check email reputation using free services and pattern analysis
        
        Args:
            email: Email address to check
            
        Returns:
            Dict containing reputation analysis results
        """
        if not email or '@' not in email:
            return {"available": False, "error": "Invalid email address"}
            
        result = {
            "available": True,
            "email": email,
            "domain": email.split('@')[-1],
            "suspicious": False,
            "verdict": "clean",
            "details": {
                "disposable": False,
                "free_provider": False,
                "suspicious_patterns": [],
                "domain_reputation": "neutral"
            },
            "anomalies": []
        }
        
        try:
            # Check for disposable email domains
            disposable_domains = [
                'mailinator.com', 'tempmail.com', 'guerrillamail.com',
                '10minutemail.com', 'yopmail.com', 'temp-mail.org'
            ]
            
            # Check for free email providers
            free_email_providers = [
                'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                'aol.com', 'protonmail.com', 'zoho.com', 'mail.com'
            ]
            
            domain = email.split('@')[-1].lower()
            result['details']['disposable'] = any(d in domain for d in disposable_domains)
            result['details']['free_provider'] = any(p in domain for p in free_email_providers)
            
            # Check for suspicious patterns in email
            suspicious_patterns = []
            
            # Check for email patterns like user+tag@domain.com
            if '+' in email.split('@')[0]:
                suspicious_patterns.append("contains_plus_tag")
                
            # Check for sequence of numbers in local part
            if any(c.isdigit() for c in email.split('@')[0]):
                suspicious_patterns.append("contains_numbers_in_username")
                
            # Check for suspicious domain patterns
            if any(c.isdigit() for c in domain.split('.')[0]):
                suspicious_patterns.append("domain_contains_numbers")
                
            # Check for suspicious TLDs
            suspicious_tlds = ['.xyz', '.top', '.gq', '.ml', '.cf', '.ga', '.tk']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_patterns.append("suspicious_tld")
                
            # Update result with suspicious patterns
            result['details']['suspicious_patterns'] = suspicious_patterns
            
            # Check domain age if possible
            try:
                domain_age = self._get_domain_age(domain)
                if domain_age:
                    result['details']['domain_age_days'] = domain_age
                    if domain_age < 30:  # Less than 30 days old
                        suspicious_patterns.append("new_domain")
                        result['details']['domain_reputation'] = "new"
            except Exception:
                pass
                
            # Check if domain is in common spoofed domains list
            if domain in self.common_spoofed_domains:
                suspicious_patterns.append("commonly_spoofed_domain")
                result['details']['domain_reputation'] = "risky"
                
            # Check for domain similarity to popular domains (typosquatting)
            popular_domains = ['paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'bankofamerica', 'wellsfargo']
            domain_without_tld = domain.split('.')[0]
            for popular in popular_domains:
                if popular in domain_without_tld and domain_without_tld != popular:
                    suspicious_patterns.append(f"possible_typosquatting_{popular}")
                    result['details']['domain_reputation'] = "risky"
                    break
                    
            # If we found any suspicious patterns, mark as suspicious
            if suspicious_patterns:
                result['suspicious'] = True
                result['verdict'] = "suspicious"
                result['anomalies'] = suspicious_patterns
            
            return result
            
        except Exception as e:
            return {
                "available": False,
                "error": str(e),
                "email": email,
                "verdict": "error"
            }
    
    # ==================== Helper Methods ====================
    
    def analyze_email_components(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive email analysis combining all components
        
        Args:
            email_data: Dictionary containing email components:
                - headers: Dict of email headers
                - from_email: Sender email address
                - subject: Email subject
                - body: Email body content
                - body_type: Content type ('text/plain' or 'text/html')
                - urls: List of URLs found in the email
                - attachments: List of attachments (filename, content)
                - ips: List of IP addresses found
                - domains: List of domains found
                
        Returns:
            Dict with comprehensive analysis results
        """
        analysis = {
            'header_analysis': None,
            'content_analysis': None,
            'link_analysis': None,
            'attachment_analysis': [],
            'threat_intel': None,
            'sender_analysis': None,
            'overall_verdict': 'clean',
            'risk_score': 0,
            'anomalies': []
        }
        
        # 1.1 Header Analysis
        if 'headers' in email_data:
            analysis['header_analysis'] = self.analyze_headers(email_data['headers'])
            if analysis['header_analysis'].get('verdict') == 'suspicious':
                analysis['risk_score'] += 30
                analysis['anomalies'].extend(analysis['header_analysis'].get('anomalies', []))
        
        # 1.2 Content Analysis
        if 'body' in email_data:
            content_type = email_data.get('body_type', 'text/plain')
            analysis['content_analysis'] = self.analyze_content(
                email_data['body'], 
                content_type
            )
            analysis['risk_score'] += analysis['content_analysis'].get('score', 0)
        
        # 1.3 Link Analysis
        if 'urls' in email_data or 'body' in email_data:
            content = email_data.get('urls', []) or [email_data.get('body', '')]
            content_type = email_data.get('body_type', 'text/plain')
            if isinstance(content, list):
                # If URLs are provided directly
                analysis['link_analysis'] = {
                    'links': [self._analyze_single_link(url) for url in content],
                    'verdict': 'clean'
                }
            else:
                # If we need to extract URLs from content
                analysis['link_analysis'] = self.analyze_links(content, content_type)
            
            # Check for suspicious links
            if analysis['link_analysis'].get('verdict') == 'suspicious':
                analysis['risk_score'] += 40
                analysis['anomalies'].append('suspicious_links_found')
        
        # 1.4 Attachment Analysis
        if 'attachments' in email_data and email_data['attachments']:
            for attachment in email_data['attachments']:
                filename = attachment.get('filename', 'unknown')
                content = attachment.get('content', b'')
                if content:
                    attachment_analysis = self.analyze_attachment(content, filename)
                    analysis['attachment_analysis'].append(attachment_analysis)
                    
                    # Update risk score based on attachment analysis
                    if attachment_analysis['verdict'] == 'high_risk':
                        analysis['risk_score'] += 50
                        analysis['anomalies'].append('high_risk_attachment')
                    elif attachment_analysis['verdict'] == 'medium_risk':
                        analysis['risk_score'] += 30
                        analysis['anomalies'].append('medium_risk_attachment')
        
        # 1.6 Threat Intelligence
        indicators = {
            'ips': email_data.get('ips', []),
            'domains': email_data.get('domains', []),
            'urls': email_data.get('urls', []),
            'hashes': []  # Add file hashes if available
        }
        
        # Add attachment hashes if available
        for attachment in analysis.get('attachment_analysis', []):
            if 'hashes' in attachment:
                indicators['hashes'].append(attachment['hashes']['sha256'])
        
        if any(indicators.values()):  # Only check if we have indicators
            analysis['threat_intel'] = self.check_threat_intel(indicators)
            if analysis['threat_intel'].get('verdict') == 'malicious':
                analysis['risk_score'] += 70
                analysis['anomalies'].append('malicious_indicators_found')
            elif analysis['threat_intel'].get('verdict') == 'suspicious':
                analysis['risk_score'] += 40
                analysis['anomalies'].append('suspicious_indicators_found')
        
        # 1.8 Sender Analysis
        if 'from_email' in email_data and 'headers' in email_data:
            analysis['sender_analysis'] = self.analyze_sender(
                email_data['headers'],
                email_data['from_email']
            )
            if analysis['sender_analysis'].get('verdict') == 'suspicious':
                analysis['risk_score'] += 30
                analysis['anomalies'].extend(analysis['sender_analysis'].get('anomalies', []))
        
        # Determine overall verdict based on risk score
        analysis['risk_score'] = min(100, analysis['risk_score'])  # Cap at 100
        
        if analysis['risk_score'] >= 70:
            analysis['overall_verdict'] = 'high_risk'
        elif analysis['risk_score'] >= 40:
            analysis['overall_verdict'] = 'medium_risk'
        elif analysis['risk_score'] > 0:
            analysis['overall_verdict'] = 'low_risk'
        
        return analysis

    # Add any other missing helper methods here
    def _get_domain_from_email(self, email: str) -> str:
        """Extract domain from email address"""
        if '@' in email:
            return email.split('@')[1].lower()
        return ''
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        if not domain:
            return False
        
        # Check for suspicious TLDs
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            return True
            
        # Check for common spoofed domains
        if domain in self.common_spoofed_domains:
            return True
            
        return False
    
    def check_breach_data(self, email: str) -> Dict[str, Any]:
        """Check if email appears in data breaches using Have I Been Pwned"""
        if not self.haveibeenpwned_api_key:
            return {"available": False, "error": "Have I Been Pwned API key not configured"}
            
        try:
            headers = {
                "hibp-api-key": self.haveibeenpwned_api_key,
                "User-Agent": "PhishGuard-AI"
            }
            response = requests.get(
                f"{self.haveibeenpwned_api}breachedaccount/{email}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "available": True,
                    "breach_count": len(breaches),
                    "breaches": [{
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "compromised_data": b.get("DataClasses", [])
                    } for b in breaches],
                    "verdict": "compromised" if breaches else "clean"
                }
            elif response.status_code == 404:
                return {"available": True, "breach_count": 0, "verdict": "clean"}
            return {"available": False, "error": f"API returned status {response.status_code}"}
            
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def analyze_attachment(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Analyze file attachments using Hybrid Analysis"""
        if not self.hybrid_analysis_api_key:
            return {"available": False, "error": "Hybrid Analysis API key not configured"}
            
        try:
            headers = {
                "api-key": self.hybrid_analysis_api_key,
                "User-Agent": "PhishGuard-AI"
            }
            
            # Submit file for analysis
            files = {"file": (filename, file_content)}
            response = requests.post(
                "https://www.hybrid-analysis.com/api/v2/submit/file",
                headers=headers,
                files=files,
                data={"environment_id": 100},  # Windows 10 64-bit
                timeout=30
            )
            
            if response.status_code == 201:
                result = response.json()
                job_id = result.get("job_id")
                
                # In production, you would use a webhook or polling mechanism here
                # For this example, we'll return the submission details
                return {
                    "available": True,
                    "submission_id": job_id,
                    "status": "submitted",
                    "verdict": "pending",
                    "message": "Analysis in progress. Use the submission ID to check results later."
                }
                
            return {"available": False, "error": f"API returned status {response.status_code}"}
            
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using GreyNoise"""
        if not self.greynoise_api_key:
            return {"available": False, "error": "GreyNoise API key not configured"}
            
        try:
            headers = {"key": self.greynoise_api_key, "User-Agent": "PhishGuard-AI"}
            response = requests.get(
                f"https://api.greynoise.io/v2/noise/context/{ip}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "available": True,
                    "ip": data.get("ip"),
                    "classification": data.get("classification"),
                    "last_seen": data.get("last_seen"),
                    "actor": data.get("actor"),
                    "tags": data.get("tags", []),
                    "verdict": "malicious" if data.get("classification") == "malicious" 
                              else "suspicious" if data.get("classification") == "suspicious" 
                              else "clean"
                }
            return {"available": False, "error": f"API returned status {response.status_code}"}
            
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using URLhaus"""
        try:
            # Get domain from URL
            domain = urlparse(url).netloc
            if not domain:
                return {"available": False, "error": "Invalid URL format"}
                
            # Check URL
            data = {"url": url}
            response = requests.post(
                f"{self.urlhaus_api}url/",
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    threats = result.get("threats", [])
                    return {
                        "available": True,
                        "malicious": len(threats) > 0,
                        "threats": threats,
                        "verdict": "malicious" if threats else "clean"
                    }
            return {"available": False, "error": f"API returned status {response.status_code}"}
            
        except Exception as e:
            return {"available": False, "error": str(e)}


def analyze_email_components(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze all URLs, IPs, domains, and files from an email with deep analysis
    
    Args:
        email_data: dict with 'urls', 'ips', 'domains', 'attachments', 'from_email', 'headers', etc.
    
    Returns:
        dict with comprehensive analysis results including deep analysis
    """
    # Initialize results with basic information
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_analysis": {},
        "urls": [],
        "ips": [],
        "domains": [],
        "attachments": [],
        "risk_score": 0,
        "verdict": "clean",
        "warnings": [],
        "recommendations": [],
        "errors": []
    }
    
    # Initialize the deep analyzer
    deep_analyzer = DeepEmailAnalyzer()
    
    # Analyze sender email
    if email_data.get('from_email'):
        email_rep = deep_analyzer.check_email_reputation(email_data['from_email'])
        breach_data = deep_analyzer.check_breach_data(email_data['from_email'])
        
        results['email_analysis'] = {
            "email": email_data['from_email'],
            "reputation": email_rep,
            "breach_data": breach_data
        }
        
        # Update risk score based on email analysis
        if email_rep.get('suspicious', False):
            results['risk_score'] += 30
            results['warnings'].append("Suspicious email reputation")
            
        if breach_data.get('breach_count', 0) > 0:
            results['risk_score'] += 20
            results['warnings'].append(f"Email found in {breach_data['breach_count']} data breaches")
    
    # Analyze URLs
    print("\n=== Starting URL Analysis ===")
    for url in email_data.get('urls', []):
        try:
            print(f"\nAnalyzing URL: {url}")
            url_analysis = URLAnalyzer.analyze_url_comprehensive(url)
            if not isinstance(url_analysis, dict):
                raise ValueError("Unexpected response format from URL analysis")
            print(f"URL Analysis Result: {url_analysis.get('verdict', 'no verdict')}, is_malicious: {url_analysis.get('is_malicious', False)}")
            results['urls'].append(url_analysis)
        except Exception as e:
            error_msg = f"Error analyzing URL {url}: {str(e)}"
            results['errors'].append(error_msg)
            results['urls'].append({
                "url": url,
                "error": str(e),
                "verdict": "error",
                "available": False
            })
    
    # Analyze IPs with deep analysis
    for ip in email_data.get('ips', []):
        try:
            # First run basic IP analysis
            ip_analysis = IPAnalyzer.analyze_ip_comprehensive(ip)
            if not isinstance(ip_analysis, dict):
                raise ValueError("Unexpected response format from IP analysis")
                
            # Then run deep analysis
            deep_ip_analysis = deep_analyzer.check_ip_reputation(ip)
            
            # Combine results
            combined_analysis = {
                **ip_analysis,
                "deep_analysis": deep_ip_analysis
            }
            
            # Update risk score based on deep analysis
            if deep_ip_analysis.get('verdict') in ['malicious', 'suspicious']:
                results['risk_score'] += 30
                results['warnings'].append(f"Suspicious IP detected: {ip}")
            
            results['ips'].append(combined_analysis)
            
        except Exception as e:
            error_msg = f"Error analyzing IP {ip}: {str(e)}"
            results['errors'].append(error_msg)
            results['ips'].append({
                "ip": ip,
                "error": str(e),
                "verdict": "error",
                "available": False
            })
    
    # Analyze Domains
    for domain in email_data.get('domains', []):
        try:
            domain_analysis = DomainAnalyzer.analyze_domain_comprehensive(domain)
            if not isinstance(domain_analysis, dict):
                raise ValueError("Unexpected response format from domain analysis")
            results['domains'].append(domain_analysis)
        except Exception as e:
            error_msg = f"Error analyzing domain {domain}: {str(e)}"
            results['errors'].append(error_msg)
            results['domains'].append({
                "domain": domain,
                "error": str(e),
                "verdict": "error",
                "available": False
            })
    
    # Analyze Attachments with deep analysis
    for file_info in email_data.get('attachments', []):
        try:
            if 'content' not in file_info:
                continue
                
            # Calculate file hashes
            hashes = FileAnalyzer.calculate_file_hash(file_info['content'])
            
            # Run basic file analysis
            file_analysis = FileAnalyzer.check_virustotal_hash(hashes['sha256'])
            if not isinstance(file_analysis, dict):
                raise ValueError("Unexpected response format from file analysis")
            
            # Run deep analysis
            deep_file_analysis = deep_analyzer.analyze_attachment(
                file_info['content'],
                file_info.get('filename', 'unknown')
            )
            
            # Combine results
            combined_analysis = {
                **file_analysis,
                "hashes": hashes,
                "filename": file_info.get('filename'),
                "deep_analysis": deep_file_analysis
            }
            
            # Update risk score if malicious
            if deep_file_analysis.get('verdict') == 'malicious':
                combined_analysis['verdict'] = 'malicious'
                combined_analysis['is_malicious'] = True
                results['risk_score'] += 50
                results['warnings'].append(f"Malicious attachment detected: {file_info.get('filename')}")
            
            results['attachments'].append(combined_analysis)
            
        except Exception as e:
            error_msg = f"Error analyzing file {file_info.get('filename', 'unknown')}: {str(e)}"
            results['errors'].append(error_msg)
            results['attachments'].append({
                "filename": file_info.get('filename', 'unknown'),
                "error": str(e),
                "verdict": "error",
                "available": False
            })
                # Calculate overall verdict based on risk score and analysis results
    if results['risk_score'] >= 70:
        results['overall_verdict'] = 'malicious'
    elif results['risk_score'] >= 30:
        results['overall_verdict'] = 'suspicious'
    else:
        results['overall_verdict'] = 'clean'
    
    # Add recommendations based on findings
    if results['overall_verdict'] == 'malicious':
        results['recommendations'].append(
            "This email appears to be malicious. Do not interact with any links or attachments."
        )
    elif results['overall_verdict'] == 'suspicious':
        results['recommendations'].append(
            "This email appears suspicious. Proceed with caution and verify the sender's identity."
        )
    
    # Add summary of findings
    malicious_count = sum(1 for url in results['urls'] if url.get('verdict') == 'malicious')
    malicious_count += sum(1 for ip in results['ips'] if ip.get('verdict') == 'malicious')
    malicious_count += sum(1 for att in results['attachments'] if att.get('verdict') == 'malicious')
    
    suspicious_count = sum(1 for url in results['urls'] if url.get('verdict') == 'suspicious')
    suspicious_count += sum(1 for ip in results['ips'] if ip.get('verdict') == 'suspicious')
    suspicious_count += sum(1 for att in results['attachments'] if att.get('verdict') == 'suspicious')
    
    clean_count = sum(1 for url in results['urls'] if url.get('verdict') == 'clean')
    clean_count += sum(1 for ip in results['ips'] if ip.get('verdict') == 'clean')
    clean_count += sum(1 for att in results['attachments'] if att.get('verdict') == 'clean')
    
    total_checks = malicious_count + suspicious_count + clean_count
    
    results['summary'] = {
        'malicious': malicious_count,
        'suspicious': suspicious_count,
        'clean': clean_count,
        'total_checks': total_checks,
        'risk_score': results['risk_score']
    }
    
    # Ensure consistent structure for all results
    for result_list in [results['urls'], results['ips'], results['domains'], results['files']]:
        for item in result_list:
            if 'verdict' not in item:
                item['verdict'] = 'unknown'
            if 'is_malicious' not in item:
                item['is_malicious'] = item.get('verdict') == 'malicious' or item.get('verdict') == 'suspicious'
            if 'confidence' not in item:
                item['confidence'] = 100 if item.get('verdict') == 'clean' else 0
    
    return results


# ==================== CONFIGURATION HELPER ====================

def get_api_status():
    """Check which APIs are configured"""
    return {
        "virustotal": bool(APIConfig.VIRUSTOTAL_API_KEY),
        "urlscan": bool(APIConfig.URLSCAN_API_KEY),
        "abuseipdb": bool(APIConfig.ABUSEIPDB_API_KEY),
        "google_safe_browsing": bool(APIConfig.GOOGLE_SAFE_BROWSING_API_KEY),
        "phishtank": True,  # No key required
        "whois": bool(APIConfig.WHOIS_API_KEY),
        "ipqualityscore": bool(APIConfig.IPQUALITYSCORE_API_KEY),
        "emailrep": bool(APIConfig.EMAILREP_API_KEY),
        "hibp": bool(APIConfig.HIBP_API_KEY),
        "hybrid_analysis": bool(APIConfig.HYBRID_ANALYSIS_API_KEY),
        "greynoise": bool(APIConfig.GREYNOISE_API_KEY)
    }


def set_api_key(service, api_key):
    """Set API key for a service"""
    service_map = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "urlscan": "URLSCAN_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "google_safe_browsing": "GOOGLE_SAFE_BROWSING_API_KEY",
        "phishtank": "PHISHTANK_API_KEY",
        "whois": "WHOIS_API_KEY",
        "ipqualityscore": "IPQUALITYSCORE_API_KEY",
        "emailrep": "EMAILREP_API_KEY",
        "hibp": "HIBP_API_KEY",
        "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
        "greynoise": "GREYNOISE_API_KEY"
    }
    
    if service in service_map:
        setattr(APIConfig, service_map[service], api_key)
        return True
    return False

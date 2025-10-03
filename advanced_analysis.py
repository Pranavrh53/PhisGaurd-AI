"""
Advanced Analysis Module with External API Integration
Provides deep analysis of URLs, IPs, domains, and files using security APIs

Supported APIs:
- VirusTotal: URL/File/IP/Domain reputation
- URLScan.io: URL screenshot and analysis
- AbuseIPDB: IP reputation
- Google Safe Browsing: URL safety check
- WHOIS: Domain age and registration info
- PhishTank: Known phishing URL database
"""

import requests
import hashlib
import time
import json
from urllib.parse import urlparse
import base64
from datetime import datetime

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
    WHOIS_API_KEY = ""  # Get from: https://whoisxmlapi.com/
    WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


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
    def analyze_url_comprehensive(url):
        """
        Run all URL checks and aggregate results with enhanced analysis
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Comprehensive analysis including results from all available sources
        """
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "sources": [],
            "threats": [],
            "scores": {
                "malicious": 0,
                "suspicious": 0,
                "clean": 0
            },
            "verdict": "clean",
            "confidence": 0,
            "details": {}
        }
        
        # Dictionary to store API results
        api_results = {}
        
        # VirusTotal Analysis
        if APIConfig.VIRUSTOTAL_API_KEY:
            try:
                vt_result = URLAnalyzer.analyze_with_virustotal(url)
                api_results['virustotal'] = vt_result
                
                if vt_result.get('available', False):
                    if vt_result.get('verdict') == 'malicious':
                        results['scores']['malicious'] += 1
                        results['threats'].append('VirusTotal: Malicious URL detected')
                    elif vt_result.get('verdict') == 'suspicious':
                        results['scores']['suspicious'] += 1
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
                        results['scores']['malicious'] += 1
                        results['threats'].append('URLScan: Suspicious activity detected')
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
                        results['scores']['malicious'] += 1
                        results['threats'].extend(gsb_result.get('threats', ['Google Safe Browsing: Unsafe URL']))
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
        
        # Calculate overall verdict and confidence
        total_checks = sum(results['scores'].values())
        if total_checks > 0:
            malicious_score = results['scores']['malicious']
            suspicious_score = results['scores']['suspicious'] * 0.5  # Suspicious counts half
            
            # Calculate confidence based on number of checks and agreement
            confidence = ((malicious_score + suspicious_score) / total_checks) * 100
            results['confidence'] = min(100, max(0, int(confidence)))
            
            # Set verdict based on scores
            if results['scores']['malicious'] > 0:
                results['verdict'] = 'malicious'
            elif results['scores']['suspicious'] > 0:
                results['verdict'] = 'suspicious'
            else:
                results['verdict'] = 'clean'
        
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
        """Run all domain checks"""
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "whois": DomainAnalyzer.get_whois_info(domain),
            "virustotal": DomainAnalyzer.analyze_with_virustotal(domain)
        }
        
        # Calculate overall verdict
        malicious_count = 0
        total_checks = 0
        risk_factors = []
        
        for service, data in results.items():
            if service in ['domain', 'timestamp']:
                continue
            if data.get('available'):
                total_checks += 1
                if data.get('verdict') == 'malicious':
                    malicious_count += 1
                    risk_factors.append(f"{service}: malicious")
                if data.get('is_recently_registered'):
                    risk_factors.append("Recently registered domain")
        
        results['overall_verdict'] = {
            "is_malicious": malicious_count > 0,
            "malicious_sources": malicious_count,
            "total_sources": total_checks,
            "risk_factors": risk_factors,
            "confidence": (malicious_count / total_checks * 100) if total_checks > 0 else 0
        }
        
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


# ==================== MAIN ANALYSIS FUNCTION ====================

def analyze_email_components(email_data):
    """
    Analyze all URLs, IPs, domains, and files from an email
    
    Args:
        email_data: dict with 'urls', 'ips', 'domains', 'attachments'
    
    Returns:
        dict with comprehensive analysis results
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "urls": [],
        "ips": [],
        "domains": [],
        "files": []
    }
    
    # Analyze URLs
    for url in email_data.get('urls', []):
        url_analysis = URLAnalyzer.analyze_url_comprehensive(url)
        results['urls'].append(url_analysis)
    
    # Analyze IPs
    for ip in email_data.get('ips', []):
        ip_analysis = IPAnalyzer.analyze_ip_comprehensive(ip)
        results['ips'].append(ip_analysis)
    
    # Analyze Domains
    for domain in email_data.get('domains', []):
        domain_analysis = DomainAnalyzer.analyze_domain_comprehensive(domain)
        results['domains'].append(domain_analysis)
    
    # Analyze Files
    for file_info in email_data.get('attachments', []):
        if 'content' in file_info:
            hashes = FileAnalyzer.calculate_file_hash(file_info['content'])
            file_analysis = FileAnalyzer.check_virustotal_hash(hashes['sha256'])
            file_analysis['hashes'] = hashes
            file_analysis['filename'] = file_info.get('filename')
            results['files'].append(file_analysis)
    
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
        "ipqualityscore": bool(APIConfig.IPQUALITYSCORE_API_KEY)
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
        "ipqualityscore": "IPQUALITYSCORE_API_KEY"
    }
    
    if service in service_map:
        setattr(APIConfig, service_map[service], api_key)
        return True
    return False

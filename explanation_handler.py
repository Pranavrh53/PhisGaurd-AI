"""
Explanation Handler Module
Provides human-readable explanations for analysis results
"""
from typing import Dict, Any, List
import json

class ExplanationHandler:
    def __init__(self):
        # Predefined templates for different types of explanations
        self.templates = {
            'url': {
                'suspicious_keyword': "The URL contains '{keyword}' which is commonly used in phishing attempts.",
                'ip_address': "The URL uses an IP address instead of a domain name, which is unusual for legitimate services.",
                'url_shortener': "This URL uses a URL shortening service, which can hide the actual destination.",
                'non_standard_port': "The URL uses a non-standard port, which is uncommon for legitimate services.",
                'https_with_ip': "The URL uses HTTPS with an IP address, which is unusual for legitimate services.",
                'excessive_subdomains': "The URL has an unusually high number of subdomains, which can be a sign of phishing.",
                'suspicious_tld': "The URL uses a suspicious top-level domain (TLD) that's often associated with malicious sites.",
                'suspicious_parameter': "The URL contains suspicious parameters that might be used for phishing.",
            },
            'email': {
                'spf_fail': "SPF check failed. The sending server is not authorized to send emails for this domain.",
                'dkim_fail': "DKIM signature verification failed. The email may have been tampered with.",
                'dmarc_fail': "DMARC check failed. The email doesn't comply with the domain's email authentication policy.",
                'domain_mismatch': "The 'From' domain doesn't match the 'Return-Path' domain, which is suspicious.",
                'suspicious_sender': "The sender's email address looks suspicious or is from a high-risk domain.",
                'urgent_language': "The email uses urgent language to pressure you into taking immediate action.",
                'suspicious_links': "The email contains links that appear to be suspicious or lead to untrusted websites.",
                'suspicious_attachments': "The email contains attachments that may be dangerous.",
            }
        }
    
    def explain_url_analysis(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate explanations for URL analysis results"""
        explanations = []
        
        # Add overall verdict
        if analysis.get('verdict') == 'malicious':
            explanations.append({
                'type': 'warning',
                'message': 'This URL has been identified as potentially malicious.'
            })
        
        # Add specific findings
        if 'threats' in analysis:
            for threat in analysis['threats']:
                if 'suspicious_keyword' in threat.lower():
                    keyword = threat.split('"')[-2] if '"' in threat else 'a suspicious keyword'
                    explanations.append({
                        'type': 'warning',
                        'message': self.templates['url']['suspicious_keyword'].format(keyword=keyword)
                    })
                elif 'IP address' in threat:
                    explanations.append({
                        'type': 'warning',
                        'message': self.templates['url']['ip_address']
                    })
                # Add more threat types as needed
        
        # Add security checks
        if not analysis.get('https', True):
            explanations.append({
                'type': 'warning',
                'message': 'This URL does not use HTTPS, which means your connection is not encrypted.'
            })
        
        return explanations
    
    def explain_email_analysis(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate explanations for email analysis results"""
        explanations = []
        
        # Check authentication results
        if 'header_analysis' in analysis:
            headers = analysis['header_analysis']
            if not headers.get('spf', False):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['spf_fail']
                })
            if not headers.get('dkim', False):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['dkim_fail']
                })
            if 'anomalies' in headers and headers['anomalies']:
                for anomaly in headers['anomalies']:
                    if 'mismatch' in anomaly:
                        explanations.append({
                            'type': 'warning',
                            'message': self.templates['email']['domain_mismatch']
                        })
        
        # Add content analysis results
        if 'content_analysis' in analysis:
            content = analysis['content_analysis']
            if content.get('urgency_score', 0) > 0.7:
                explanations.append({
                    'type': 'info',
                    'message': self.templates['email']['urgent_language']
                })
        
        # Add link analysis results
        if 'link_analysis' in analysis and analysis['link_analysis'].get('suspicious_links', 0) > 0:
            explanations.append({
                'type': 'warning',
                'message': self.templates['email']['suspicious_links']
            })
        
        return explanations
    
    def format_explanations(self, explanations: List[Dict[str, str]]) -> str:
        """Format explanations as a chat-like response"""
        if not explanations:
            return "No specific issues were found in the analysis."
        
        formatted = ["Here's what I found in the analysis:", ""]
        for i, exp in enumerate(explanations, 1):
            formatted.append(f"{i}. {exp['message']}")
        
        return "\n".join(formatted)

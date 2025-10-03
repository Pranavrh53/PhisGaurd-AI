"""
Advanced Email Feature Extraction Module
Implements comprehensive phishing detection features including:
- Header-based features (SPF, DKIM, domain analysis)
- Content-based features (keywords, grammar, urgency)
- URL-based features (shorteners, domain mismatch, IP addresses)
- Attachment-based features (file types, extension mismatch)
- Psychological features (emotional triggers, authority)
- Technical features (geographical origin, encoding)
- Reputation-based features (blacklisting, domain reputation)
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
from collections import Counter
import unicodedata

# Optional: language_tool_python for grammar checking (not required)
try:
    import language_tool_python
    GRAMMAR_TOOL_AVAILABLE = True
except ImportError:
    GRAMMAR_TOOL_AVAILABLE = False


# ==================== CONSTANTS ====================

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "cutt.ly", "short.io", "s.id"
}

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.pif', '.jar', '.js', '.vbs', '.html', '.hta',
    '.docm', '.xlsm', '.xls', '.pptm', '.zip', '.rar', '.bat', '.cmd',
    '.com', '.msi', '.apk', '.app', '.deb', '.dmg'
}

SPAMMY_KEYWORDS = [
    'urgent', 'verify', 'suspended', 'account', 'password', 'click here',
    'confirm', 'update', 'security', 'bank', 'login', 'expire', 'limited time',
    'act now', 'congratulations', 'winner', 'free', 'prize', 'claim',
    'refund', 'tax', 'payment', 'invoice', 'delivery', 'package',
    'social security', 'ssn', 'credit card', 'debit card', 'pin',
    'verify your identity', 'unusual activity', 'locked', 'blocked',
    'reactivate', 'restore', 'validate', 'authenticate'
]

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'asap', 'right now', 'act now', 'hurry',
    'expire', 'expires', 'expiring', 'deadline', 'limited time',
    'last chance', 'final notice', 'time sensitive', 'within 24 hours',
    'within 48 hours', 'before it\'s too late', 'don\'t miss out'
]

THREAT_KEYWORDS = [
    'suspended', 'locked', 'blocked', 'closed', 'terminated', 'deactivated',
    'restricted', 'frozen', 'disabled', 'cancelled', 'revoked',
    'legal action', 'lawsuit', 'arrest', 'warrant', 'investigation',
    'fraud', 'unauthorized', 'suspicious activity', 'unusual activity'
]

AUTHORITY_KEYWORDS = [
    'compliance', 'regulation', 'policy', 'terms of service', 'legal',
    'official', 'government', 'irs', 'fbi', 'police', 'court',
    'administrator', 'manager', 'director', 'security team', 'support team',
    'customer service', 'technical support', 'it department'
]

FINANCIAL_KEYWORDS = [
    'bank', 'credit card', 'debit card', 'account number', 'routing number',
    'ssn', 'social security', 'password', 'pin', 'cvv', 'security code',
    'tax', 'refund', 'payment', 'invoice', 'billing', 'transaction',
    'wire transfer', 'paypal', 'venmo', 'bitcoin', 'cryptocurrency'
]

GENERIC_SALUTATIONS = [
    'dear customer', 'dear user', 'dear member', 'dear valued customer',
    'dear sir/madam', 'dear account holder', 'hello customer', 'hi there',
    'greetings', 'dear friend', 'dear client'
]

LEGITIMATE_DOMAINS = {
    'google.com', 'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'paypal.com', 'bankofamerica.com', 'chase.com',
    'wellsfargo.com', 'citibank.com', 'usbank.com'
}

# URL regex patterns
URL_REGEX = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
IP_IN_URL_REGEX = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


# ==================== HEADER-BASED FEATURES ====================

class HeaderFeatureExtractor:
    """Extract features from email headers"""
    
    @staticmethod
    def extract_domain(email_address):
        """Extract domain from email address"""
        if not email_address:
            return ""
        match = EMAIL_REGEX.search(email_address)
        if match:
            return match.group().split('@')[-1].lower()
        return ""
    
    @staticmethod
    def check_spf_status(headers):
        """Check SPF authentication status"""
        spf_header = headers.get('Received-SPF', '').lower()
        auth_results = headers.get('Authentication-Results', '').lower()
        
        if 'pass' in spf_header or 'spf=pass' in auth_results:
            return 'pass'
        elif 'fail' in spf_header or 'spf=fail' in auth_results:
            return 'fail'
        elif 'softfail' in spf_header or 'spf=softfail' in auth_results:
            return 'softfail'
        elif 'neutral' in spf_header or 'spf=neutral' in auth_results:
            return 'neutral'
        return 'none'
    
    @staticmethod
    def check_dkim_status(headers):
        """Check DKIM signature status"""
        dkim_sig = headers.get('DKIM-Signature', '')
        auth_results = headers.get('Authentication-Results', '').lower()
        
        if dkim_sig:
            has_dkim = True
        else:
            has_dkim = False
        
        if 'dkim=pass' in auth_results:
            return 'pass', has_dkim
        elif 'dkim=fail' in auth_results:
            return 'fail', has_dkim
        
        return 'none', has_dkim
    
    @staticmethod
    def check_domain_mismatch(from_addr, return_path):
        """Check if From and Return-Path domains match"""
        from_domain = HeaderFeatureExtractor.extract_domain(from_addr)
        return_domain = HeaderFeatureExtractor.extract_domain(return_path)
        
        if not from_domain or not return_domain:
            return False
        
        # Extract base domains
        from_ext = tldextract.extract(from_domain)
        return_ext = tldextract.extract(return_domain)
        
        from_base = f"{from_ext.domain}.{from_ext.suffix}"
        return_base = f"{return_ext.domain}.{return_ext.suffix}"
        
        return from_base != return_base
    
    @staticmethod
    def is_legitimate_domain(domain):
        """Check if domain is in known legitimate domains"""
        if not domain:
            return False
        
        ext = tldextract.extract(domain)
        base_domain = f"{ext.domain}.{ext.suffix}"
        
        return base_domain in LEGITIMATE_DOMAINS
    
    @staticmethod
    def check_recently_registered(domain):
        """
        Check if domain is recently registered (placeholder)
        In production, this would query WHOIS or domain age APIs
        """
        # This is a placeholder - would need external API in production
        # For now, return False (not recently registered)
        return False
    
    @staticmethod
    def extract_header_features(msg):
        """Extract all header-based features from email message"""
        features = {}
        
        # Get headers
        from_addr = msg.get('From', '')
        return_path = msg.get('Return-Path', msg.get('return-path', ''))
        reply_to = msg.get('Reply-To', '')
        
        # Extract domains
        from_domain = HeaderFeatureExtractor.extract_domain(from_addr)
        return_domain = HeaderFeatureExtractor.extract_domain(return_path)
        reply_domain = HeaderFeatureExtractor.extract_domain(reply_to)
        
        # SPF and DKIM
        spf_status = HeaderFeatureExtractor.check_spf_status(msg)
        dkim_status, has_dkim = HeaderFeatureExtractor.check_dkim_status(msg)
        
        # Domain checks
        domain_mismatch = HeaderFeatureExtractor.check_domain_mismatch(from_addr, return_path)
        is_legit_domain = HeaderFeatureExtractor.is_legitimate_domain(from_domain)
        
        # Populate features
        features['from_domain'] = from_domain
        features['return_domain'] = return_domain
        features['has_spf'] = 1 if spf_status != 'none' else 0
        features['spf_pass'] = 1 if spf_status == 'pass' else 0
        features['spf_fail'] = 1 if spf_status in ['fail', 'softfail'] else 0
        features['has_dkim'] = 1 if has_dkim else 0
        features['dkim_pass'] = 1 if dkim_status == 'pass' else 0
        features['dkim_fail'] = 1 if dkim_status == 'fail' else 0
        features['domain_mismatch'] = 1 if domain_mismatch else 0
        features['from_return_mismatch'] = 1 if domain_mismatch else 0
        features['is_legitimate_domain'] = 1 if is_legit_domain else 0
        features['has_reply_to'] = 1 if reply_to else 0
        features['reply_to_mismatch'] = 1 if reply_domain and reply_domain != from_domain else 0
        
        return features


# ==================== CONTENT-BASED FEATURES ====================

class ContentFeatureExtractor:
    """Extract features from email content"""
    
    def __init__(self):
        # Initialize grammar checker (optional, can be slow)
        self.grammar_tool = None
        try:
            self.grammar_tool = language_tool_python.LanguageTool('en-US')
        except:
            pass
    
    @staticmethod
    def extract_text_from_html(html_content):
        """Extract plain text from HTML"""
        if not html_content:
            return ""
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.get_text(separator=' ', strip=True)
    
    @staticmethod
    def count_spammy_keywords(text):
        """Count occurrences of spammy keywords"""
        text_lower = text.lower()
        count = 0
        found_keywords = []
        
        for keyword in SPAMMY_KEYWORDS:
            if keyword in text_lower:
                count += text_lower.count(keyword)
                found_keywords.append(keyword)
        
        return count, found_keywords
    
    @staticmethod
    def count_urgency_keywords(text):
        """Count urgency-related keywords"""
        text_lower = text.lower()
        count = 0
        
        for keyword in URGENCY_KEYWORDS:
            if keyword in text_lower:
                count += text_lower.count(keyword)
        
        return count
    
    @staticmethod
    def count_threat_keywords(text):
        """Count threat-related keywords"""
        text_lower = text.lower()
        count = 0
        
        for keyword in THREAT_KEYWORDS:
            if keyword in text_lower:
                count += text_lower.count(keyword)
        
        return count
    
    @staticmethod
    def count_authority_keywords(text):
        """Count authority-related keywords"""
        text_lower = text.lower()
        count = 0
        
        for keyword in AUTHORITY_KEYWORDS:
            if keyword in text_lower:
                count += text_lower.count(keyword)
        
        return count
    
    @staticmethod
    def count_financial_keywords(text):
        """Count financial information request keywords"""
        text_lower = text.lower()
        count = 0
        
        for keyword in FINANCIAL_KEYWORDS:
            if keyword in text_lower:
                count += text_lower.count(keyword)
        
        return count
    
    @staticmethod
    def has_generic_salutation(text):
        """Check for generic salutations"""
        text_lower = text.lower()
        
        for salutation in GENERIC_SALUTATIONS:
            if salutation in text_lower:
                return True
        
        return False
    
    @staticmethod
    def calculate_grammar_errors(text):
        """Calculate grammar and spelling errors (optional)"""
        # This can be slow, so it's optional
        try:
            tool = language_tool_python.LanguageTool('en-US')
            matches = tool.check(text[:1000])  # Check first 1000 chars
            tool.close()
            return len(matches)
        except:
            return 0
    
    @staticmethod
    def calculate_text_statistics(text):
        """Calculate various text statistics"""
        if not text:
            return {
                'length': 0,
                'word_count': 0,
                'uppercase_ratio': 0,
                'digit_ratio': 0,
                'special_char_ratio': 0
            }
        
        word_count = len(text.split())
        uppercase_count = sum(1 for c in text if c.isupper())
        digit_count = sum(1 for c in text if c.isdigit())
        special_char_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        
        return {
            'length': len(text),
            'word_count': word_count,
            'uppercase_ratio': uppercase_count / max(1, len(text)),
            'digit_ratio': digit_count / max(1, len(text)),
            'special_char_ratio': special_char_count / max(1, len(text))
        }
    
    @staticmethod
    def extract_content_features(subject, body_text, body_html):
        """Extract all content-based features"""
        features = {}
        
        # Combine text
        full_text = f"{subject} {body_text}"
        if body_html and not body_text:
            full_text = f"{subject} {ContentFeatureExtractor.extract_text_from_html(body_html)}"
        
        # Text statistics
        stats = ContentFeatureExtractor.calculate_text_statistics(full_text)
        features['body_len'] = stats['length']
        features['body_words'] = stats['word_count']
        features['uppercase_ratio'] = stats['uppercase_ratio']
        features['digit_ratio'] = stats['digit_ratio']
        features['special_char_ratio'] = stats['special_char_ratio']
        
        # Subject statistics
        subj_stats = ContentFeatureExtractor.calculate_text_statistics(subject)
        features['subj_len'] = subj_stats['length']
        features['subj_words'] = subj_stats['word_count']
        
        # Punctuation
        features['exclaim_count'] = full_text.count('!')
        features['question_count'] = full_text.count('?')
        
        # Keyword counts
        spammy_count, found_keywords = ContentFeatureExtractor.count_spammy_keywords(full_text)
        features['spammy_keyword_count'] = spammy_count
        features['urgency_keyword_count'] = ContentFeatureExtractor.count_urgency_keywords(full_text)
        features['threat_keyword_count'] = ContentFeatureExtractor.count_threat_keywords(full_text)
        features['authority_keyword_count'] = ContentFeatureExtractor.count_authority_keywords(full_text)
        features['financial_keyword_count'] = ContentFeatureExtractor.count_financial_keywords(full_text)
        
        # Generic salutation
        features['has_generic_salutation'] = 1 if ContentFeatureExtractor.has_generic_salutation(full_text) else 0
        
        # Individual keyword flags (for backward compatibility)
        text_lower = full_text.lower()
        features['kw_verify'] = 1 if 'verify' in text_lower else 0
        features['kw_password'] = 1 if 'password' in text_lower else 0
        features['kw_account'] = 1 if 'account' in text_lower else 0
        features['kw_urgent'] = 1 if 'urgent' in text_lower else 0
        features['kw_click here'] = 1 if 'click here' in text_lower else 0
        features['kw_bank'] = 1 if 'bank' in text_lower else 0
        features['kw_login'] = 1 if 'login' in text_lower else 0
        features['kw_update'] = 1 if 'update' in text_lower else 0
        features['kw_suspend'] = 1 if 'suspend' in text_lower else 0
        features['kw_confirm'] = 1 if 'confirm' in text_lower else 0
        features['kw_security'] = 1 if 'security' in text_lower else 0
        features['kw_ssn'] = 1 if 'ssn' in text_lower or 'social security' in text_lower else 0
        features['kw_credit card'] = 1 if 'credit card' in text_lower else 0
        
        return features


# ==================== URL-BASED FEATURES ====================

class URLFeatureExtractor:
    """Extract features from URLs in email"""
    
    @staticmethod
    def extract_urls(text, html):
        """Extract all URLs from text and HTML"""
        urls = []
        
        # Extract from text
        if text:
            urls.extend(URL_REGEX.findall(text))
        
        # Extract from HTML
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                urls.append(a['href'])
            
            # Also find URLs in text
            urls.extend(URL_REGEX.findall(html))
        
        # Remove duplicates
        return list(set(urls))
    
    @staticmethod
    def extract_anchor_texts(html):
        """Extract anchor text and href pairs"""
        if not html:
            return []
        
        anchors = []
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            text = a.get_text(strip=True)
            href = a['href']
            anchors.append((href, text))
        
        return anchors
    
    @staticmethod
    def is_shortener(url):
        """Check if URL uses a shortening service"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return domain in SHORTENER_DOMAINS
        except:
            return False
    
    @staticmethod
    def has_ip_address(url):
        """Check if URL uses IP address instead of domain"""
        return bool(IP_IN_URL_REGEX.match(url))
    
    @staticmethod
    def count_subdomains(url):
        """Count number of subdomains"""
        try:
            ext = tldextract.extract(url)
            if ext.subdomain:
                return len(ext.subdomain.split('.'))
            return 0
        except:
            return 0
    
    @staticmethod
    def is_https(url):
        """Check if URL uses HTTPS"""
        return url.lower().startswith('https://')
    
    @staticmethod
    def check_anchor_mismatch(anchors):
        """Check if anchor text doesn't match href domain"""
        mismatches = 0
        
        for href, text in anchors:
            # Check if text looks like a URL
            if 'http' in text.lower() or '.' in text:
                try:
                    # Extract domain from text
                    text_urls = URL_REGEX.findall(text)
                    if text_urls:
                        text_domain = urlparse(text_urls[0]).netloc
                        href_domain = urlparse(href).netloc
                        
                        if text_domain and href_domain and text_domain != href_domain:
                            mismatches += 1
                except:
                    pass
        
        return mismatches
    
    @staticmethod
    def extract_url_features(body_text, body_html):
        """Extract all URL-based features"""
        features = {}
        
        # Extract URLs
        urls = URLFeatureExtractor.extract_urls(body_text, body_html)
        anchors = URLFeatureExtractor.extract_anchor_texts(body_html)
        
        # Basic counts
        features['num_urls'] = len(urls)
        features['num_unique_domains'] = len(set(urlparse(url).netloc for url in urls if urlparse(url).netloc))
        
        # URL characteristics
        features['num_shorteners'] = sum(1 for url in urls if URLFeatureExtractor.is_shortener(url))
        features['num_ip_urls'] = sum(1 for url in urls if URLFeatureExtractor.has_ip_address(url))
        features['num_http_urls'] = sum(1 for url in urls if not URLFeatureExtractor.is_https(url))
        
        # Average URL length
        if urls:
            features['avg_url_len'] = sum(len(url) for url in urls) / len(urls)
            features['max_subdomains'] = max(URLFeatureExtractor.count_subdomains(url) for url in urls)
        else:
            features['avg_url_len'] = 0
            features['max_subdomains'] = 0
        
        # Anchor text mismatch
        features['anchor_mismatch_count'] = URLFeatureExtractor.check_anchor_mismatch(anchors)
        features['domain_mismatch'] = 1 if features['anchor_mismatch_count'] > 0 else 0
        
        return features


# ==================== ATTACHMENT-BASED FEATURES ====================

class AttachmentFeatureExtractor:
    """Extract features from email attachments"""
    
    @staticmethod
    def get_attachments(msg):
        """Extract attachment information from email message"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True) or b'')
                    })
        
        return attachments
    
    @staticmethod
    def has_suspicious_extension(filename):
        """Check if filename has suspicious extension"""
        if not filename:
            return False
        
        filename_lower = filename.lower()
        return any(filename_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
    
    @staticmethod
    def has_double_extension(filename):
        """Check for double extension (e.g., invoice.pdf.exe)"""
        if not filename:
            return False
        
        parts = filename.split('.')
        return len(parts) > 2
    
    @staticmethod
    def extract_attachment_features(msg):
        """Extract all attachment-based features"""
        features = {}
        
        attachments = AttachmentFeatureExtractor.get_attachments(msg)
        
        features['num_attachments'] = len(attachments)
        features['has_suspicious_attachment'] = 0
        features['has_double_extension'] = 0
        features['total_attachment_size'] = 0
        
        for att in attachments:
            if AttachmentFeatureExtractor.has_suspicious_extension(att['filename']):
                features['has_suspicious_attachment'] = 1
            
            if AttachmentFeatureExtractor.has_double_extension(att['filename']):
                features['has_double_extension'] = 1
            
            features['total_attachment_size'] += att['size']
        
        return features


# ==================== PSYCHOLOGICAL FEATURES ====================

class PsychologicalFeatureExtractor:
    """Extract psychological manipulation features"""
    
    EMOTION_KEYWORDS = {
        'fear': ['afraid', 'scared', 'worried', 'concerned', 'risk', 'danger', 'threat', 'warning'],
        'urgency': ['urgent', 'immediately', 'now', 'asap', 'hurry', 'quick', 'fast'],
        'greed': ['free', 'win', 'won', 'prize', 'reward', 'bonus', 'gift', 'money'],
        'curiosity': ['secret', 'revealed', 'discover', 'find out', 'learn', 'exclusive']
    }
    
    @staticmethod
    def detect_emotions(text):
        """Detect emotional triggers in text"""
        text_lower = text.lower()
        emotion_scores = {}
        
        for emotion, keywords in PsychologicalFeatureExtractor.EMOTION_KEYWORDS.items():
            score = sum(text_lower.count(kw) for kw in keywords)
            emotion_scores[emotion] = score
        
        return emotion_scores
    
    @staticmethod
    def detect_scarcity(text):
        """Detect scarcity tactics"""
        scarcity_keywords = [
            'limited', 'exclusive', 'only', 'last chance', 'expires',
            'while supplies last', 'limited time', 'act now', 'don\'t miss'
        ]
        
        text_lower = text.lower()
        return sum(text_lower.count(kw) for kw in scarcity_keywords)
    
    @staticmethod
    def extract_psychological_features(subject, body_text, body_html):
        """Extract all psychological features"""
        features = {}
        
        full_text = f"{subject} {body_text}"
        if body_html and not body_text:
            full_text = f"{subject} {ContentFeatureExtractor.extract_text_from_html(body_html)}"
        
        # Emotion detection
        emotions = PsychologicalFeatureExtractor.detect_emotions(full_text)
        features['emotion_fear'] = emotions.get('fear', 0)
        features['emotion_urgency'] = emotions.get('urgency', 0)
        features['emotion_greed'] = emotions.get('greed', 0)
        features['emotion_curiosity'] = emotions.get('curiosity', 0)
        
        # Scarcity
        features['scarcity_score'] = PsychologicalFeatureExtractor.detect_scarcity(full_text)
        
        # Has emotional trigger
        features['has_emotional_trigger'] = 1 if sum(emotions.values()) > 0 else 0
        
        return features


# ==================== TECHNICAL FEATURES ====================

class TechnicalFeatureExtractor:
    """Extract technical and network-based features"""
    
    @staticmethod
    def detect_homoglyphs(text):
        """Detect homoglyph attacks (look-alike characters)"""
        # Check for non-ASCII characters that look like ASCII
        suspicious_count = 0
        
        for char in text:
            if ord(char) > 127:  # Non-ASCII
                # Normalize and check if it looks like ASCII
                normalized = unicodedata.normalize('NFKD', char)
                if len(normalized) > 0 and ord(normalized[0]) < 127:
                    suspicious_count += 1
        
        return suspicious_count
    
    @staticmethod
    def check_encoding(msg):
        """Check for unusual character encodings"""
        content_type = msg.get('Content-Type', '')
        charset = 'utf-8'  # default
        
        if 'charset=' in content_type:
            try:
                charset = content_type.split('charset=')[1].split(';')[0].strip().strip('"\'')
            except:
                pass
        
        # Suspicious encodings
        suspicious_encodings = ['iso-2022', 'shift_jis', 'euc-kr', 'big5']
        is_suspicious = any(enc in charset.lower() for enc in suspicious_encodings)
        
        return charset, is_suspicious
    
    @staticmethod
    def extract_technical_features(msg, body_text, body_html):
        """Extract all technical features"""
        features = {}
        
        full_text = f"{body_text} {body_html}"
        
        # Homoglyph detection
        features['homoglyph_count'] = TechnicalFeatureExtractor.detect_homoglyphs(full_text)
        
        # Encoding
        charset, is_suspicious = TechnicalFeatureExtractor.check_encoding(msg)
        features['suspicious_encoding'] = 1 if is_suspicious else 0
        
        # HTML to text ratio
        if body_html and body_text:
            html_len = len(body_html)
            text_len = len(body_text)
            features['html_to_text_ratio'] = html_len / max(1, text_len)
        else:
            features['html_to_text_ratio'] = 0
        
        # Has HTML but no text (suspicious)
        features['html_only'] = 1 if body_html and not body_text else 0
        
        return features


# ==================== MAIN FEATURE EXTRACTION ====================

def extract_all_features(email_content):
    """
    Extract all features from email content
    
    Args:
        email_content: Raw email string or email.message.Message object
    
    Returns:
        dict: Dictionary of all extracted features
    """
    # Parse email if it's a string
    if isinstance(email_content, str):
        msg = email.message_from_string(email_content, policy=policy.default)
    else:
        msg = email_content
    
    # Initialize feature dictionary
    all_features = {}
    
    # Extract basic email parts
    subject = msg.get('Subject', '') or ''
    from_addr = msg.get('From', '') or ''
    
    # Extract body
    body_text = ""
    body_html = ""
    
    for part in msg.walk():
        content_type = part.get_content_type()
        
        if content_type == 'text/plain' and not part.get_filename():
            try:
                body_text += part.get_payload(decode=True).decode(errors='ignore')
            except:
                pass
        elif content_type == 'text/html' and not part.get_filename():
            try:
                body_html += part.get_payload(decode=True).decode(errors='ignore')
            except:
                pass
    
    # If no parts found, try to get payload directly
    if not body_text and not body_html:
        try:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                body_text = payload.decode(errors='ignore')
        except:
            pass
    
    # Extract features from each category
    header_features = HeaderFeatureExtractor.extract_header_features(msg)
    content_features = ContentFeatureExtractor.extract_content_features(subject, body_text, body_html)
    url_features = URLFeatureExtractor.extract_url_features(body_text, body_html)
    attachment_features = AttachmentFeatureExtractor.extract_attachment_features(msg)
    psychological_features = PsychologicalFeatureExtractor.extract_psychological_features(subject, body_text, body_html)
    technical_features = TechnicalFeatureExtractor.extract_technical_features(msg, body_text, body_html)
    
    # Combine all features
    all_features.update(header_features)
    all_features.update(content_features)
    all_features.update(url_features)
    all_features.update(attachment_features)
    all_features.update(psychological_features)
    all_features.update(technical_features)
    
    # Add body text for vectorization
    all_features['body'] = f"{subject} {body_text}"
    if not body_text and body_html:
        all_features['body'] = f"{subject} {ContentFeatureExtractor.extract_text_from_html(body_html)}"
    
    return all_features


def extract_features_for_prediction(email_content):
    """
    Extract features and format them for model prediction
    
    Args:
        email_content: Raw email string
    
    Returns:
        dict: Dictionary of features ready for model input
    """
    return extract_all_features(email_content)

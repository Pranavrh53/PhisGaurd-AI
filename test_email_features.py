"""
Test script for email feature extraction
Demonstrates how different phishing indicators are detected

NOTE: This is a DEVELOPER TESTING TOOL, not for end users.
End users should use the web interface at http://localhost:5000

Purpose:
- Test the feature extraction module during development
- Validate that all feature categories work correctly
- Demonstrate phishing detection on sample emails
- Help developers understand feature behavior

For end users: Run 'python app.py' and use the web interface instead.
"""

from email_features import extract_all_features
import json

# Test Case 1: Typical Phishing Email
phishing_email_1 = """From: security@paypa1-verify.com
To: victim@example.com
Subject: URGENT: Your PayPal Account Will Be Suspended!
Return-Path: bounce@suspicious-domain.xyz

Dear Customer,

Your PayPal account has been temporarily suspended due to unusual activity. 
You must verify your identity IMMEDIATELY to avoid permanent account closure.

Click here to verify now: http://bit.ly/paypal-verify

This is your FINAL WARNING. Act now before it's too late!

If you don't respond within 24 hours, your account will be permanently closed 
and you will lose access to all funds.

Verify your account: http://192.168.1.100/paypal/login.php

Best regards,
PayPal Security Team
"""

# Test Case 2: Legitimate Email
legitimate_email = """From: notifications@github.com
To: developer@example.com
Subject: [GitHub] New pull request in your repository
Return-Path: bounces@github.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
Authentication-Results: spf=pass

Hi John Smith,

A new pull request has been opened in your repository "awesome-project".

Pull Request #42: Fix bug in authentication module
Opened by: contributor123

You can review the changes here:
https://github.com/yourname/awesome-project/pull/42

Thanks,
The GitHub Team
"""

# Test Case 3: Phishing with Emotional Manipulation
phishing_email_2 = """From: irs-department@irs-gov-refund.com
To: taxpayer@example.com
Subject: You've Won a $5,000 Tax Refund - Claim Now!

Dear Valued Taxpayer,

Congratulations! You are eligible for a $5,000 tax refund.

This is a LIMITED TIME offer - only available to the first 100 people!
You must act IMMEDIATELY or you will LOSE this opportunity forever.

To claim your refund, click here: http://tinyurl.com/irs-refund-2024

We need you to verify the following information:
- Social Security Number
- Bank Account Number
- Credit Card Information
- Mother's Maiden Name

WARNING: If you don't respond within 48 hours, your refund will be forfeited!

This is your LAST CHANCE to claim this exclusive offer!

Sincerely,
IRS Refund Department
"""

# Test Case 4: Phishing with Attachment
phishing_email_3 = """From: hr@company-payroll.biz
To: employee@company.com
Subject: Important: Update Your Payroll Information
Return-Path: admin@sketchy-server.ru

Dear Employee,

Please update your payroll information by opening the attached file.

The file is named: Payroll_Update_Form.pdf.exe

You must complete this within 24 hours or your next paycheck will be delayed.

Click here if you have trouble opening the attachment: http://192.168.50.10/payroll

Regards,
HR Department
"""

def test_email(email_content, description):
    """Test feature extraction on an email"""
    print(f"\n{'='*80}")
    print(f"TEST: {description}")
    print(f"{'='*80}\n")
    
    # Extract features
    features = extract_all_features(email_content)
    
    # Display key indicators
    print("🔍 KEY PHISHING INDICATORS:")
    print("-" * 80)
    
    # Header features
    print("\n📧 HEADER ANALYSIS:")
    print(f"  • SPF Present: {bool(features.get('has_spf', 0))}")
    print(f"  • DKIM Present: {bool(features.get('has_dkim', 0))}")
    print(f"  • Domain Mismatch: {bool(features.get('from_return_mismatch', 0))}")
    print(f"  • From Domain: {features.get('from_domain', 'N/A')}")
    print(f"  • Return Domain: {features.get('return_domain', 'N/A')}")
    
    # URL features
    print("\n🔗 URL ANALYSIS:")
    print(f"  • Total URLs: {features.get('num_urls', 0)}")
    print(f"  • URL Shorteners: {features.get('num_shorteners', 0)}")
    print(f"  • IP-based URLs: {features.get('num_ip_urls', 0)}")
    print(f"  • Anchor Mismatches: {features.get('anchor_mismatch_count', 0)}")
    
    # Content features
    print("\n📝 CONTENT ANALYSIS:")
    print(f"  • Spammy Keywords: {features.get('spammy_keyword_count', 0)}")
    print(f"  • Urgency Keywords: {features.get('urgency_keyword_count', 0)}")
    print(f"  • Threat Keywords: {features.get('threat_keyword_count', 0)}")
    print(f"  • Financial Keywords: {features.get('financial_keyword_count', 0)}")
    print(f"  • Generic Salutation: {bool(features.get('has_generic_salutation', 0))}")
    print(f"  • Exclamation Marks: {features.get('exclaim_count', 0)}")
    
    # Psychological features
    print("\n🧠 PSYCHOLOGICAL TRIGGERS:")
    print(f"  • Fear Triggers: {features.get('emotion_fear', 0)}")
    print(f"  • Urgency Triggers: {features.get('emotion_urgency', 0)}")
    print(f"  • Greed Triggers: {features.get('emotion_greed', 0)}")
    print(f"  • Scarcity Score: {features.get('scarcity_score', 0)}")
    
    # Attachment features
    print("\n📎 ATTACHMENT ANALYSIS:")
    print(f"  • Attachments: {features.get('num_attachments', 0)}")
    print(f"  • Suspicious Attachments: {bool(features.get('has_suspicious_attachment', 0))}")
    
    # Technical features
    print("\n⚙️ TECHNICAL ANALYSIS:")
    print(f"  • Homoglyph Characters: {features.get('homoglyph_count', 0)}")
    print(f"  • Suspicious Encoding: {bool(features.get('suspicious_encoding', 0))}")
    
    # Calculate risk score (simple heuristic)
    risk_score = 0
    risk_score += features.get('from_return_mismatch', 0) * 20
    risk_score += (1 - features.get('has_spf', 0)) * 10
    risk_score += (1 - features.get('has_dkim', 0)) * 10
    risk_score += features.get('num_shorteners', 0) * 15
    risk_score += features.get('num_ip_urls', 0) * 20
    risk_score += min(features.get('spammy_keyword_count', 0) * 3, 30)
    risk_score += min(features.get('urgency_keyword_count', 0) * 5, 20)
    risk_score += min(features.get('threat_keyword_count', 0) * 5, 20)
    risk_score += features.get('has_generic_salutation', 0) * 15
    risk_score += features.get('has_suspicious_attachment', 0) * 25
    risk_score += min(features.get('emotion_fear', 0) * 3, 15)
    risk_score += min(features.get('scarcity_score', 0) * 3, 15)
    
    risk_score = min(risk_score, 100)
    
    print(f"\n{'='*80}")
    print(f"⚠️  RISK SCORE: {risk_score}/100")
    
    if risk_score >= 70:
        print(f"🚨 VERDICT: HIGH RISK - Likely Phishing")
    elif risk_score >= 40:
        print(f"⚠️  VERDICT: MEDIUM RISK - Suspicious")
    else:
        print(f"✅ VERDICT: LOW RISK - Likely Legitimate")
    
    print(f"{'='*80}\n")
    
    return features, risk_score


def main():
    """Run all test cases"""
    print("\n" + "="*80)
    print("PhishGuard-AI: Email Feature Extraction Test Suite")
    print("="*80)
    
    # Run tests
    test_email(phishing_email_1, "Typical Phishing Email (PayPal Scam)")
    test_email(legitimate_email, "Legitimate Email (GitHub Notification)")
    test_email(phishing_email_2, "Phishing with Emotional Manipulation (IRS Scam)")
    test_email(phishing_email_3, "Phishing with Malicious Attachment")
    
    print("\n" + "="*80)
    print("✅ All tests completed!")
    print("="*80 + "\n")
    
    # Additional test: Feature extraction performance
    print("\n📊 FEATURE EXTRACTION SUMMARY:")
    print("-" * 80)
    features = extract_all_features(phishing_email_1)
    print(f"Total features extracted: {len(features)}")
    print(f"\nFeature categories:")
    print(f"  • Header features: SPF, DKIM, domain analysis")
    print(f"  • Content features: keywords, statistics, punctuation")
    print(f"  • URL features: shorteners, IP addresses, mismatches")
    print(f"  • Attachment features: file types, extensions")
    print(f"  • Psychological features: emotions, triggers")
    print(f"  • Technical features: encoding, homoglyphs")
    print("-" * 80 + "\n")


if __name__ == "__main__":
    main()

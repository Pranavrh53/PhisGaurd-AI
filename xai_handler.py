"""
XAI (eXplainable AI) Handler Module
Provides model-agnostic explanations for predictions using SHAP, LIME, and rule-based methods
"""
from typing import Dict, Any, List, Union, Tuple, Optional
import json
import numpy as np
import pandas as pd
import shap
import lime
import lime.lime_tabular
import joblib
from pathlib import Path
import re
from datetime import datetime

class XAIHandler:
    def __init__(self):
        """Initialize the XAI handler with models and explainers"""
        self.models = self._load_models()
        self.vectorizers = self._load_vectorizers()
        self.explainers = {}
        self._init_explainers()
        
        # Explanation templates
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
                'shap_explanation': "The most important features contributing to this prediction are: {features}",
                'lime_explanation': "Local explanation for this prediction:",
                'anchor_explanation': "The model is confident about this prediction because the URL contains these key patterns:"
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
                'shap_explanation': "Key features influencing this email classification:",
                'lime_explanation': "Local explanation for this email classification:",
                'anchor_explanation': "The model classifies this email as suspicious because it contains these key patterns:"
            }
        }
    
    def _load_models(self) -> Dict[str, Any]:
        """Load pre-trained models"""
        models_dir = Path("pkl")
        models = {}
        
        # Load URL model
        url_model_path = models_dir / "URL_detection_model.pkl"
        if url_model_path.exists():
            models['url'] = joblib.load(url_model_path)
            
        # Load email model
        email_assets_path = models_dir / "phish_detector_joblib.pkl"
        if email_assets_path.exists():
            email_assets = joblib.load(email_assets_path)
            models['email'] = email_assets.get('model')
            
        return models
    
    def _load_vectorizers(self) -> Dict[str, Any]:
        """Load vectorizers and feature preprocessors"""
        vectorizers = {}
        email_assets_path = Path("pkl/phish_detector_joblib.pkl")
        
        if email_assets_path.exists():
            email_assets = joblib.load(email_assets_path)
            vectorizers['email'] = {
                'vectorizer': email_assets.get('vectorizer'),
                'scaler': email_assets.get('scaler'),
                'numeric_cols': email_assets.get('numeric_cols', [])
            }
            
        return vectorizers
    
    def _init_explainers(self):
        """Initialize explainers for each model"""
        # Initialize SHAP explainers
        if 'url' in self.models:
            self.explainers['url'] = {
                'shap': shap.Explainer(self.models['url']),
                'lime': lime.lime_tabular.LimeTabularExplainer(
                    np.zeros((1, len(self.models['url'].feature_importances_))),
                    feature_names=self.models['url'].feature_names_in_,
                    class_names=['Legitimate', 'Phishing'],
                    mode='classification'
                )
            }
            
        if 'email' in self.models and 'email' in self.vectorizers:
            # Get sample data for LIME
            sample_data = np.zeros((1, len(self.vectorizers['email']['numeric_cols'])))
            self.explainers['email'] = {
                'shap': shap.Explainer(self.models['email']),
                'lime': lime.lime_tabular.LimeTabularExplainer(
                    sample_data,
                    feature_names=self.vectorizers['email']['numeric_cols'],
                    class_names=['Legitimate', 'Phishing'],
                    mode='classification'
                )
            }
    
    def explain_with_shap(self, model_type: str, X: np.ndarray) -> Dict[str, Any]:
        """Generate SHAP explanations for a prediction"""
        if model_type not in self.explainers or 'shap' not in self.explainers[model_type]:
            return {}
            
        explainer = self.explainers[model_type]['shap']
        shap_values = explainer.shap_values(X)
        
        # For binary classification, we take the SHAP values for class 1 (phishing)
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # For binary classification
            
        # Get feature importance
        feature_importance = np.abs(shap_values).mean(axis=0)
        feature_names = self._get_feature_names(model_type, X.shape[1])
        
        # Create explanation
        explanation = {
            'feature_importance': dict(zip(feature_names, feature_importance)),
            'shap_values': shap_values.tolist() if hasattr(shap_values, 'tolist') else shap_values,
            'expected_value': explainer.expected_value[1] if hasattr(explainer.expected_value, '__iter__') else explainer.expected_value
        }
        
        return explanation
    
    def explain_with_lime(self, model_type: str, X: np.ndarray, num_features: int = 5) -> Dict[str, Any]:
        """Generate LIME explanations for a prediction"""
        if model_type not in self.explainers or 'lime' not in self.explainers[model_type]:
            return {}
            
        explainer = self.explainers[model_type]['lime']
        
        # Predict function for LIME
        def predict_proba(X):
            return self.models[model_type].predict_proba(X)
            
        # Generate explanation
        exp = explainer.explain_instance(
            X[0],  # For a single instance
            predict_proba,
            num_features=num_features,
            top_labels=1
        )
        
        # Format explanation
        explanation = {
            'as_list': exp.as_list(),
            'as_map': exp.as_map(),
            'prediction': exp.predict_proba.tolist(),
            'local_pred': exp.local_pred.tolist() if hasattr(exp, 'local_pred') else None
        }
        
        return explanation
    
    def _get_feature_names(self, model_type: str, num_features: int) -> List[str]:
        """Get feature names for the given model type"""
        if model_type == 'url' and 'url' in self.models:
            try:
                return list(self.models['url'].feature_names_in_)
            except:
                pass
        elif model_type == 'email' and 'email' in self.vectorizers:
            try:
                return self.vectorizers['email']['numeric_cols']
            except:
                pass
        return [f'feature_{i}' for i in range(num_features)]
    
    def generate_explanation_report(self, model_type: str, input_data: Union[str, Dict], prediction: Dict) -> Dict[str, Any]:
        """Generate a comprehensive explanation report"""
        # Prepare input data for explainers
        X = self._prepare_input_data(model_type, input_data)
        
        # Generate explanations
        shap_exp = self.explain_with_shap(model_type, X) if X.size > 0 else {}
        lime_exp = self.explain_with_lime(model_type, X) if X.size > 0 else {}
        
        # Generate rule-based explanations
        rule_based = self._generate_rule_based_explanations(model_type, input_data, prediction)
        
        # Create report
        report = {
            'model_type': model_type,
            'prediction': prediction,
            'explanations': {
                'rule_based': rule_based,
                'shap': shap_exp,
                'lime': lime_exp
            },
            'visualizations': {}
        }
        
        return report
    
    def _prepare_input_data(self, model_type: str, input_data: Union[str, Dict]) -> np.ndarray:
        """Prepare input data for explainability methods"""
        if model_type == 'url' and isinstance(input_data, str):
            # For URL model, we need to extract features first
            features = {
                'url_length': len(input_data),
                'num_dots': input_data.count('.'),
                'num_hyphens': input_data.count('-'),
                'num_underscore': input_data.count('_'),
                'num_forward_slash': input_data.count('/'),
                'num_question_mark': input_data.count('?'),
                'num_equals': input_data.count('='),
                'num_ampersand': input_data.count('&'),
                'num_digits': sum(c.isdigit() for c in input_data),
                'has_https': 1 if input_data.startswith('https://') else 0,
                'has_http': 1 if input_data.startswith('http://') else 0,
                'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', input_data) else 0,
            }
            
            # Convert to DataFrame with expected columns
            try:
                expected_columns = joblib.load("pkl/expected_columns.pkl")
                df = pd.DataFrame([features])
                df = df.reindex(columns=expected_columns, fill_value=0)
                return df.values
            except:
                pass
                
        elif model_type == 'email' and isinstance(input_data, dict):
            # For email model, we need to vectorize the text and scale the features
            if 'email_text' in input_data and 'vectorizer' in self.vectorizers.get('email', {}):
                # Vectorize text
                text_vec = self.vectorizers['email']['vectorizer'].transform([input_data['email_text']])
                
                # Get numeric features
                numeric_features = []
                if 'numeric_cols' in self.vectorizers.get('email', {}):
                    numeric_features = [
                        input_data.get(feature, 0) 
                        for feature in self.vectorizers['email']['numeric_cols']
                    ]
                
                # Combine features
                if hasattr(text_vec, 'toarray'):
                    text_features = text_vec.toarray()
                else:
                    text_features = text_vec
                    
                X = np.hstack([text_features, numeric_features])
                
                # Scale features if scaler is available
                if 'scaler' in self.vectorizers.get('email', {}):
                    X = self.vectorizers['email']['scaler'].transform(X)
                    
                return X
                
        return np.array([])
    
    def _generate_rule_based_explanations(self, model_type: str, input_data: Union[str, Dict], 
                                        prediction: Dict) -> List[Dict[str, Any]]:
        """Generate rule-based explanations based on input data and prediction"""
        explanations = []
        
        if model_type == 'url' and isinstance(input_data, str):
            url = input_data.lower()
            
            # Add overall verdict
            if prediction.get('is_phishing', False):
                explanations.append({
                    'type': 'warning',
                    'message': 'This URL has been identified as potentially malicious.',
                    'confidence': prediction.get('confidence', 0),
                    'source': 'rule_based',
                    'feature': 'overall_verdict'
                })
            
            # Check for suspicious keywords
            suspicious_keywords = ['login', 'signin', 'account', 'verify', 'secure', 'banking', 'paypal']
            for keyword in suspicious_keywords:
                if keyword in url:
                    explanations.append({
                        'type': 'warning',
                        'message': self.templates['url']['suspicious_keyword'].format(keyword=keyword),
                        'source': 'rule_based',
                        'feature': f'contains_{keyword}'
                    })
            
            # Check for IP address in URL
            if re.match(r'\d+\.\d+\.\d+\.\d+', url):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['url']['ip_address'],
                    'source': 'rule_based',
                    'feature': 'uses_ip_address'
                })
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly']
            if any(shortener in url for shortener in shorteners):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['url']['url_shortener'],
                    'source': 'rule_based',
                    'feature': 'uses_url_shortener'
                })
        
        elif model_type == 'email' and isinstance(input_data, dict):
            # Add email-specific rule-based explanations
            if input_data.get('spf_fail', False):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['spf_fail'],
                    'source': 'rule_based',
                    'feature': 'spf_fail'
                })
                
            if input_data.get('dkim_fail', False):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['dkim_fail'],
                    'source': 'rule_based',
                    'feature': 'dkim_fail'
                })
                
            if input_data.get('dmarc_fail', False):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['dmarc_fail'],
                    'source': 'rule_based',
                    'feature': 'dmarc_fail'
                })
            
            # Check for urgent language
            urgent_words = ['urgent', 'immediately', 'action required', 'account suspended', 'verify now']
            email_text = input_data.get('email_text', '').lower()
            if any(word in email_text for word in urgent_words):
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['urgent_language'],
                    'source': 'rule_based',
                    'feature': 'urgent_language'
                })
            
            # Check for suspicious links
            if 'suspicious_links' in input_data and input_data['suspicious_links']:
                explanations.append({
                    'type': 'warning',
                    'message': self.templates['email']['suspicious_links'],
                    'source': 'rule_based',
                    'feature': 'suspicious_links'
                })
        
        return explanations
    
    def format_explanations_for_ui(self, explanation_report: Dict[str, Any]) -> Dict[str, Any]:
        """Format the explanation report for the UI"""
        formatted = {
            'model_type': explanation_report.get('model_type', 'unknown'),
            'prediction': explanation_report.get('prediction', {}),
            'explanations': [],
            'feature_importance': {}
        }
        
        # Add rule-based explanations
        for exp in explanation_report.get('explanations', {}).get('rule_based', []):
            formatted['explanations'].append({
                'type': exp.get('type', 'info'),
                'message': exp.get('message', ''),
                'source': 'rule_based',
                'feature': exp.get('feature', '')
            })
        
        # Add SHAP explanations
        shap_exp = explanation_report.get('explanations', {}).get('shap', {})
        if shap_exp and 'feature_importance' in shap_exp:
            formatted['feature_importance']['shap'] = {
                'features': [
                    {'name': k, 'importance': v} 
                    for k, v in sorted(
                        shap_exp['feature_importance'].items(), 
                        key=lambda x: abs(x[1]), 
                        reverse=True
                    )[:10]  # Top 10 features
                ],
                'source': 'shap'
            }
            
            # Add SHAP explanation message
            top_features = [
                f"{feat['name']} ({feat['importance']:.2f})" 
                for feat in formatted['feature_importance']['shap']['features'][:3]
            ]
            
            formatted['explanations'].append({
                'type': 'info',
                'message': f"{self.templates[formatted['model_type']]['shap_explanation']} {', '.join(top_features)}",
                'source': 'shap'
            })
        
        # Add LIME explanations
        lime_exp = explanation_report.get('explanations', {}).get('lime', {})
        if lime_exp and 'as_list' in lime_exp:
            formatted['explanations'].append({
                'type': 'info',
                'message': self.templates[formatted['model_type']]['lime_explanation'],
                'source': 'lime',
                'details': [
                    {'feature': feat[0], 'weight': float(feat[1])}
                    for feat in lime_exp['as_list']
                ]
            })
        
        return formatted
    
    def generate_xai_report(self, analysis_type: str, analysis_data: Dict[str, Any], raw_input: str) -> str:
        """
        Generates a comprehensive, formatted text report for the XAI analysis.
        """
        report_lines = []
        
        # 1. Header
        report_lines.append(f"=" * 50)
        report_lines.append("PHISGUARD AI - EXPLAINABLE AI ANALYSIS REPORT")
        report_lines.append(f"=" * 50)
        report_lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Analysis Type: {analysis_type.upper()}")
        report_lines.append(f"Input: {raw_input[:100]}{'...' if len(raw_input) > 100 else ''}")
        report_lines.append("-" * 50)
        
        # 2. Overall Verdict
        verdict = analysis_data.get('prediction', {}).get('verdict', 'UNKNOWN').upper()
        confidence = analysis_data.get('prediction', {}).get('confidence', 0)
        
        report_lines.append(f"OVERALL VERDICT: {verdict}")
        report_lines.append(f"CONFIDENCE: {confidence:.2f}%")
        report_lines.append("-" * 50)
        
        # 3. Explanation Summary
        formatted = self.format_explanations_for_ui(analysis_data)
        
        report_lines.append("KEY FINDINGS (XAI EXPLANATION)")
        if formatted.get('explanations'):
            for i, exp in enumerate(formatted['explanations'], 1):
                report_lines.append(f"  {i}. [{exp.get('type', 'info').upper()}] {exp['message']}")
        else:
            report_lines.append("  No specific suspicious characteristics were highlighted.")
        report_lines.append("-" * 50)
        
        # 4. Feature Importance
        if formatted.get('feature_importance', {}).get('shap', {}).get('features'):
            report_lines.append("TOP INFLUENTIAL FEATURES")
            for i, feat in enumerate(formatted['feature_importance']['shap']['features'][:5], 1):
                report_lines.append(f"  {i}. {feat['name']}: {feat['importance']:.4f}")
            report_lines.append("-" * 50)
        
        # 5. Detailed Explanation
        report_lines.append("DETAILED EXPLANATION")
        report_lines.append("This section provides a detailed breakdown of the analysis:")
        
        # Add rule-based findings
        rule_based = [e for e in formatted.get('explanations', []) if e.get('source') == 'rule_based']
        if rule_based:
            report_lines.append("\nRule-based Analysis:")
            for i, exp in enumerate(rule_based, 1):
                report_lines.append(f"  {i}. {exp['message']}")
        
        # Add SHAP feature importance
        if formatted.get('feature_importance', {}).get('shap', {}).get('features'):
            report_lines.append("\nFeature Importance (SHAP):")
            for i, feat in enumerate(formatted['feature_importance']['shap']['features'][:10], 1):
                influence = "increases" if feat['importance'] > 0 else "decreases"
                report_lines.append(f"  {i}. {feat['name']}: {abs(feat['importance']):.4f} ({influence} phishing probability)")
        
        # Add LIME explanation if available
        lime_exp = next((e for e in formatted.get('explanations', []) if e.get('source') == 'lime'), None)
        if lime_exp and lime_exp.get('details'):
            report_lines.append("\nLocal Explanation (LIME):")
            for i, detail in enumerate(lime_exp['details'][:5], 1):
                influence = "supports" if detail['weight'] > 0 else "contradicts"
                report_lines.append(f"  {i}. {detail['feature']}: {influence} the prediction (weight: {detail['weight']:.4f})")
        
        report_lines.append("\n" + "=" * 50)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 50)
        
        return "\n".join(report_lines)
    
    def download_explanation_report(self, analysis_type: str, analysis_data: Dict[str, Any], 
                                 raw_input: str, filename: str = "phishguard_analysis_report.txt") -> str:
        """
        Generates and saves the XAI report to a file.
        Returns the path to the saved file.
        """
        report_content = self.generate_xai_report(analysis_type, analysis_data, raw_input)
        
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Save report to file
        report_path = reports_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        return str(report_path.absolute())

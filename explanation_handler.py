"""
XAI (eXplainable AI) Handler Module for PhishGuard AI
Provides model-agnostic explanations for predictions using SHAP, LIME, and rule-based methods.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

# Import SHAP and LIME for model explanations
import shap
import lime
import lime.lime_tabular

class XAIHandler:
    """
    XAI Handler for generating model explanations using SHAP and LIME.
    """
    
    def __init__(self):
        """Initialize the XAI handler with models and explainers."""
        self.models = self._load_models()
        self.vectorizers = self._load_vectorizers()
        self.explainers = {}
        self._init_explainers()
    
    def _load_models(self) -> Dict[str, Any]:
        """Load pre-trained models."""
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
        """Load vectorizers and feature preprocessors."""
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
        """Initialize explainers for each model."""
        # Initialize SHAP explainers
        if 'url' in self.models:
            url_model = self.models['url']
            try:
                # For tree-based models
                if hasattr(url_model, 'feature_importances_'):
                    self.explainers['url'] = {
                        'shap': shap.TreeExplainer(url_model),
                        'lime': lime.lime_tabular.LimeTabularExplainer(
                            np.zeros((1, len(url_model.feature_importances_))),
                            feature_names=url_model.feature_names_in_,
                            class_names=['Legitimate', 'Phishing'],
                            mode='classification'
                        )
                    }
                # For other models, use KernelExplainer
                else:
                    # Use a dummy predict function for the explainer
                    def predict_proba(X):
                        return url_model.predict_proba(X)
                    
                    # Create a small sample of data for the explainer
                    background = shap.sample(self._get_training_data('url'), 100)
                    self.explainers['url'] = {
                        'shap': shap.KernelExplainer(predict_proba, background),
                        'lime': lime.lime_tabular.LimeTabularExplainer(
                            background,
                            feature_names=url_model.feature_names_in_,
                            class_names=['Legitimate', 'Phishing'],
                            mode='classification'
                        )
                    }
            except Exception as e:
                print(f"Warning: Could not initialize URL explainer: {str(e)}")
                self.explainers['url'] = {}
        
        if 'email' in self.models and 'email' in self.vectorizers:
            email_model = self.models['email']
            try:
                # For VotingClassifier, use the predict_proba function directly
                if hasattr(email_model, 'voting') and email_model.voting == 'soft':
                    # Create a wrapper function for the predict_proba method
                    def voting_predict_proba(X):
                        return email_model.predict_proba(X)
                    
                    # Create a small sample of data for the explainer
                    background = self._get_training_data('email')
                    self.explainers['email'] = {
                        'shap': shap.KernelExplainer(voting_predict_proba, background),
                        'lime': lime.lime_tabular.LimeTabularExplainer(
                            background,
                            feature_names=self.vectorizers['email']['numeric_cols'],
                            class_names=['Legitimate', 'Phishing'],
                            mode='classification'
                        )
                    }
                # For other models
                else:
                    self.explainers['email'] = {
                        'shap': shap.Explainer(email_model),
                        'lime': lime.lime_tabular.LimeTabularExplainer(
                            np.zeros((1, len(self.vectorizers['email']['numeric_cols']))),
                            feature_names=self.vectorizers['email']['numeric_cols'],
                            class_names=['Legitimate', 'Phishing'],
                            mode='classification'
                        )
                    }
            except Exception as e:
                print(f"Warning: Could not initialize email explainer: {str(e)}")
                self.explainers['email'] = {}

    def _get_training_data(self, model_type: str, n_samples: int = 100) -> np.ndarray:
        """Get a sample of training data for the specified model type."""
        # This is a placeholder - in a real application, you would load your training data
        # For now, we'll return random data with the right shape
        if model_type == 'url':
            # Assuming URL model has 20 features as an example
            return np.random.rand(n_samples, 20)
        elif model_type == 'email':
            # Assuming email model has 50 numeric features as an example
            return np.random.rand(n_samples, len(self.vectorizers['email']['numeric_cols']))
        return np.random.rand(n_samples, 10)  # Default fallback
    
    def explain_with_shap(self, model_type: str, X: np.ndarray) -> Dict[str, Any]:
        """Generate SHAP explanations for a prediction."""
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
        """Generate LIME explanations for a prediction."""
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
        """Get feature names for the given model type and number of features."""
        if model_type == 'url' and 'url' in self.models:
            if hasattr(self.models['url'], 'feature_names_in_'):
                return list(self.models['url'].feature_names_in_)
            return [f'feature_{i}' for i in range(num_features)]
        
        elif model_type == 'email' and 'email' in self.vectorizers:
            return self.vectorizers['email'].get('numeric_cols', [f'feature_{i}' for i in range(num_features)])
        
        return [f'feature_{i}' for i in range(num_features)]
    
    def generate_rule_based_explanation(self, model_type: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """Generate rule-based explanations based on feature values."""
        explanations = []
        
        if model_type == 'url':
            # Example rule-based explanations for URL
            if features.get('uses_ip', 0) == 1:
                explanations.append({
                    'type': 'warning',
                    'message': 'The URL uses an IP address instead of a domain name, which is unusual for legitimate services.'
                })
            
            if features.get('excessive_subdomains', 0) == 1:
                explanations.append({
                    'type': 'warning',
                    'message': 'The URL has an unusually high number of subdomains, which can be a sign of phishing.'
                })
            
            if features.get('suspicious_tld', 0) == 1:
                explanations.append({
                    'type': 'warning',
                    'message': 'The URL uses a suspicious top-level domain (TLD) that\'s often associated with malicious sites.'
                })
            
            if features.get('has_url_shortener', 0) == 1:
                explanations.append({
                    'type': 'info',
                    'message': 'This URL uses a URL shortening service, which can hide the actual destination.'
                })
        
        elif model_type == 'email':
            # Example rule-based explanations for email
            if features.get('urgent_language', 0) > 0.7:
                explanations.append({
                    'type': 'warning',
                    'message': 'The email uses urgent language to pressure you into taking immediate action.'
                })
            
            if features.get('suspicious_keywords', 0) > 0.5:
                explanations.append({
                    'type': 'warning',
                    'message': 'The email contains suspicious keywords commonly used in phishing attempts.'
                })
            
            if features.get('suspicious_links', 0) > 0:
                explanations.append({
                    'type': 'warning',
                    'message': 'The email contains links that appear to be suspicious or lead to untrusted websites.'
                })
            
            if features.get('suspicious_attachments', 0) > 0:
                explanations.append({
                    'type': 'danger',
                    'message': 'The email contains attachments that may be dangerous.'
                })
        
        return {'explanations': explanations}
    
    def format_explanations_for_ui(self, explanations: Dict[str, Any], model_type: str) -> Dict[str, Any]:
        """Format explanations for display in the UI."""
        formatted = {
            'feature_importance': [],
            'local_explanations': [],
            'rule_based': []
        }
        
        # Format SHAP feature importance
        if 'shap' in explanations and 'feature_importance' in explanations['shap']:
            for feature, importance in explanations['shap']['feature_importance'].items():
                formatted['feature_importance'].append({
                    'feature': feature,
                    'importance': float(importance),
                    'impact': 'positive' if importance > 0 else 'negative'
                })
            
            # Sort by absolute importance
            formatted['feature_importance'].sort(key=lambda x: abs(x['importance']), reverse=True)
        
        # Format LIME local explanations
        if 'lime' in explanations and 'as_list' in explanations['lime']:
            for feature, weight in explanations['lime']['as_list']:
                formatted['local_explanations'].append({
                    'feature': feature,
                    'weight': float(weight),
                    'impact': 'positive' if weight > 0 else 'negative'
                })
        
        # Add rule-based explanations
        if 'rule_based' in explanations and 'explanations' in explanations['rule_based']:
            formatted['rule_based'] = explanations['rule_based']['explanations']
        
        return formatted
    
    def generate_xai_report(self, model_type: str, input_data: Any, prediction: float, explanations: Dict[str, Any]) -> str:
        """
        Generate a comprehensive XAI report.
        
        Args:
            model_type: Type of model ('url' or 'email')
            input_data: The input data that was used for prediction
            prediction: The model's prediction (0-1 probability)
            explanations: Dictionary containing SHAP and LIME explanations
            
        Returns:
            str: A formatted XAI report
        """
        report = []
        report.append("=" * 80)
        report.append("PHISHGUARD AI - EXPLAINABLE AI REPORT")
        report.append("=" * 80)
        report.append(f"Analysis Type: {model_type.upper()} Analysis")
        report.append(f"Prediction: {'Phishing' if prediction > 0.5 else 'Legitimate'} (Confidence: {prediction*100:.2f}%)")
        report.append("\n" + "=" * 40 + " EXPLANATION " + "=" * 40)
        
        # Add SHAP summary
        if 'shap' in explanations and 'feature_importance' in explanations['shap']:
            report.append("\nFEATURE IMPORTANCE (SHAP):")
            report.append("-" * 80)
            for i, (feature, importance) in enumerate(explanations['shap']['feature_importance'].items(), 1):
                impact = "+" if importance > 0 else "-"
                report.append(f"{i:2d}. {impact} {feature}: {abs(importance):.4f}")
        
        # Add LIME explanation
        if 'lime' in explanations and 'as_list' in explanations['lime']:
            report.append("\nLOCAL EXPLANATION (LIME):")
            report.append("-" * 80)
            for i, (feature, weight) in enumerate(explanations['lime']['as_list'], 1):
                impact = "+" if weight > 0 else "-"
                report.append(f"{i:2d}. {impact} {feature}: {abs(weight):.4f}")
        
        # Add rule-based explanations
        if 'rule_based' in explanations and 'explanations' in explanations['rule_based']:
            report.append("\nRULE-BASED FINDINGS:")
            report.append("-" * 80)
            for i, exp in enumerate(explanations['rule_based']['explanations'], 1):
                report.append(f"{i:2d}. [{exp['type'].upper()}] {exp['message']}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_report_to_file(self, report: str, filename: str = None) -> str:
        """
        Save the XAI report to a file.
        
        Args:
            report: The report content to save
            filename: Optional custom filename (without extension)
            
        Returns:
            str: Path to the saved report file
        """
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename if not provided
        if not filename:
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xai_report_{timestamp}.txt"
        elif not filename.endswith('.txt'):
            filename += '.txt'
        
        # Save the report
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        return str(filepath)

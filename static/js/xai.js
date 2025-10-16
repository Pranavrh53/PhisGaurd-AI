/**
 * XAI (Explainable AI) Module for PhishGuard
 * Handles displaying model explanations and feature importance
 */

class XAIDisplayer {
    constructor() {
        this.explanationContainer = document.getElementById('xai-explanations');
        this.reportLink = document.getElementById('download-report');
        this.currentReportId = null;
    }

    /**
     * Show loading state for XAI explanations
     */
    showLoading() {
        this.explanationContainer.innerHTML = `
            <div class="xai-loading">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading explanations...</span>
                </div>
                <p>Generating explanations...</p>
            </div>
        `;
    }

    /**
     * Display error message
     * @param {string} message - Error message to display
     */
    showError(message) {
        this.explanationContainer.innerHTML = `
            <div class="alert alert-danger" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                ${message}
            </div>
        `;
    }

    /**
     * Display XAI explanations
     * @param {Object} data - XAI explanation data
     */
    displayExplanations(data) {
        this.currentReportId = data.report_id;
        
        // Update report download link
        if (this.reportLink) {
            this.reportLink.href = `/api/xai/report/${data.report_id}`;
            this.reportLink.classList.remove('d-none');
        }

        // Create HTML for explanations
        let html = `
            <div class="xai-prediction mb-4">
                <h4>Prediction: 
                    <span class="badge ${data.prediction > 0.5 ? 'bg-danger' : 'bg-success'}">
                        ${(data.prediction * 100).toFixed(2)}% ${data.prediction > 0.5 ? 'Phishing' : 'Legitimate'}
                    </span>
                </h4>
            </div>
        `;

        // Feature Importance (SHAP)
        if (data.explanations.feature_importance?.length > 0) {
            html += `
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Feature Importance</h5>
                        <small class="text-muted">Which features contributed most to this prediction?</small>
                    </div>
                    <div class="card-body">
                        <div class="feature-importance">
                            ${data.explanations.feature_importance.slice(0, 10).map(feat => `
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between mb-1">
                                        <span>${this.formatFeatureName(feat.feature)}</span>
                                        <span class="fw-bold ${feat.impact === 'positive' ? 'text-danger' : 'text-success'}">
                                            ${feat.impact === 'positive' ? '↑' : '↓'} ${Math.abs(feat.importance).toFixed(4)}
                                        </span>
                                    </div>
                                    <div class="progress" style="height: 8px;">
                                        <div class="progress-bar ${feat.impact === 'positive' ? 'bg-danger' : 'bg-success'}" 
                                             role="progressbar" 
                                             style="width: ${Math.min(100, Math.abs(feat.importance) * 100)}%"
                                             aria-valuenow="${Math.abs(feat.importance) * 100}" 
                                             aria-valuemin="0" 
                                             aria-valuemax="100">
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        }

        // Local Explanations (LIME)
        if (data.explanations.local_explanations?.length > 0) {
            html += `
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Local Explanation</h5>
                        <small class="text-muted">How this specific prediction was made</small>
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            ${data.explanations.local_explanations.slice(0, 5).map(exp => `
                                <li class="list-group-item d-flex justify-content-between align-items-center">
                                    ${this.formatFeatureName(exp.feature)}
                                    <span class="badge ${exp.impact === 'positive' ? 'bg-danger' : 'bg-success'}">
                                        ${exp.impact === 'positive' ? '+' : ''}${exp.weight.toFixed(4)}
                                    </span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        // Rule-based Explanations
        if (data.explanations.rule_based?.length > 0) {
            const iconMap = {
                'warning': 'exclamation-triangle',
                'danger': 'exclamation-octagon',
                'info': 'info-circle'
            };

            html += `
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Key Findings</h5>
                        <small class="text-muted">Important patterns detected</small>
                    </div>
                    <div class="card-body">
                        <div class="list-group">
                            ${data.explanations.rule_based.map(rule => `
                                <div class="list-group-item list-group-item-${rule.type}">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-${iconMap[rule.type] || 'info-circle'} me-2"></i>
                                        <span>${rule.message}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        }

        this.explanationContainer.innerHTML = html;
    }

    /**
     * Format feature names for display
     * @param {string} feature - Raw feature name
     * @returns {string} Formatted feature name
     */
    formatFeatureName(feature) {
        // Convert snake_case to Title Case
        return feature
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    /**
     * Clear all explanations
     */
    clear() {
        this.explanationContainer.innerHTML = '';
        if (this.reportLink) {
            this.reportLink.classList.add('d-none');
        }
        this.currentReportId = null;
    }
}

// Initialize XAI displayer when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.xaiDisplayer = new XAIDisplayer();
});

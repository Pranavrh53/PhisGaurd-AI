function formatURLResult(data) {
  let html = '<div class="result">';
  html += '<div class="result-section">';
  html += '<h3><i class="fas fa-link"></i> URL Analysis: ' + (data.url || 'Unknown URL') + '</h3>';
  
  // Handle different response structures
  const virustotal = data.virustotal || {};
  const urlscan = data.urlscan || {};
  
  // Determine overall verdict from available sources
  let isMalicious = false;
  let confidence = 0;
  let maliciousSources = 0;
  let totalSources = 0;
  
  if (data.overall_verdict) {
    // Use the provided overall_verdict if available
    const verdict = data.overall_verdict;
    isMalicious = verdict.is_malicious || false;
    confidence = verdict.confidence || 0;
    maliciousSources = verdict.malicious_sources || 0;
    totalSources = verdict.total_sources || 0;
  } else {
    // Determine verdict from available sources
    if (virustotal.available) {
      totalSources++;
      if (virustotal.malicious > 0) maliciousSources++;
      confidence = Math.max(confidence, virustotal.confidence || 0);
    }
    if (urlscan.available) {
      totalSources++;
      if (urlscan.malicious) maliciousSources++;
    }
    isMalicious = maliciousSources > 0;
  }
  
  // Display the verdict
  html += `<span class="verdict-badge verdict-${isMalicious ? 'malicious' : 'clean'}">`;
  html += `<i class="fas ${isMalicious ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>`;
  html += isMalicious ? 'MALICIOUS' : 'CLEAN';
  html += `</span>`;
  
  // Display confidence if we have any sources
  if (totalSources > 0) {
    html += `<p style="color: var(--dark-text-secondary); margin-top: var(--space-2);">`;
    html += `Confidence: <strong>${confidence.toFixed(1)}%</strong> `;
    html += `(${maliciousSources}/${totalSources} sources flagged)`;
    html += `</p>`;
  }
  html += '</div>';
  
  // Individual service results
  if (virustotal.available) {
    html += '<div class="result-section">';
    html += '<h3><i class="fas fa-shield-virus"></i> VirusTotal</h3>';
    
    if (virustotal.error) {
      html += `<p class="error-message">Error: ${virustotal.error}</p>`;
    } else {
      html += `<p style="color: var(--dark-text-secondary);">`;
      html += `Status: <strong>${virustotal.malicious > 0 ? 'Malicious' : 'Clean'}</strong> | `;
      html += `Confidence: <strong>${virustotal.confidence || 0}%</strong>`;
      
      if (virustotal.malicious || virustotal.suspicious || virustotal.harmless) {
        html += `<br>Scans: `;
        if (virustotal.malicious) html += `<strong>${virustotal.malicious} malicious</strong> | `;
        if (virustotal.suspicious) html += `${virustotal.suspicious} suspicious | `;
        if (virustotal.harmless) html += `${virustotal.harmless} clean`;
      }
      
      html += `</p>`;
      
      if (virustotal.permalink) {
        html += `<p><a href="${virustotal.permalink}" target="_blank" style="color: var(--primary-500); text-decoration: none;">`;
        html += `View Full Report <i class="fas fa-external-link-alt"></i></a></p>`;
      }
    }
    
    html += '</div>';
  }
  
  if (urlscan.available) {
    html += '<div class="result-section">';
    html += '<h3><i class="fas fa-search"></i> URLScan.io</h3>';
    
    if (urlscan.error) {
      html += `<p class="error-message">Error: ${urlscan.error}</p>`;
    } else {
      html += `<p style="color: var(--dark-text-secondary);">`;
      html += `Status: <strong>${urlscan.malicious ? 'Malicious' : 'Clean'}</strong>`;
      
      if (urlscan.verdict) {
        html += ` | Verdict: <strong>${urlscan.verdict}</strong>`;
      }
      
      if (urlscan.categories && urlscan.categories.length > 0) {
        html += `<br>Categories: <strong>${urlscan.categories.join(', ')}</strong>`;
      }
      
      if (urlscan.ip) {
        html += `<br>IP: <strong>${urlscan.ip}</strong>`;
        if (urlscan.country) {
          html += ` (${urlscan.country})`;
        }
      }
      
      html += `</p>`;
      
      if (urlscan.screenshot) {
        html += `<p><img src="${urlscan.screenshot}" style="max-width: 100%; border-radius: var(--radius-lg); border: 1px solid var(--dark-border);" alt="Screenshot"></p>`;
      }
      
      if (urlscan.report_url) {
        html += `<p><a href="${urlscan.report_url}" target="_blank" style="color: var(--primary-500); text-decoration: none;">`;
        html += `View Full Report <i class="fas fa-external-link-alt"></i></a></p>`;
      }
    }
    
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

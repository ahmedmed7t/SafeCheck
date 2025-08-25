package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Reason

/**
 * Calculates security scores for URLs based on comprehensive analysis results.
 */
object UrlScoreCalculator {
    
    /**
     * Calculates the overall security score based on all analysis results.
     */
    fun calculateScore(analysis: UrlAnalysisResults): Pair<Int, List<Reason>> {
        val reasons = mutableListOf<Reason>()
        var score = 100 // Start with perfect score
        
        // HTTPS Analysis (15% weight)
        score += analyzeHttpsSecurity(analysis.httpsAnalysis, reasons)
        
        // TLS Certificate Analysis (25% weight)
        score += analyzeTlsCertificate(analysis.tlsAnalysis, reasons)
        
        // Domain Age Analysis (15% weight)
        score += analyzeDomainAge(analysis.whoisAnalysis, reasons)
        
        // DNS Records Analysis (10% weight)
        score += analyzeDnsRecords(analysis.dnsAnalysis, reasons)
        
        // Security Threats Analysis (35% weight)
        score += analyzeSecurityThreats(analysis, reasons)
        
        // Ensure score stays within bounds
        score = score.coerceIn(0, 100)
        
        return Pair(score, reasons)
    }
    
    /**
     * Analyzes HTTPS security and returns score delta.
     */
    private fun analyzeHttpsSecurity(httpsAnalysis: HttpsAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (httpsAnalysis.supportsHttps) {
            reasons.add(Reason("HTTPS_SUPPORTED", "URL uses HTTPS encryption", 0))
        } else {
            reasons.add(Reason("NO_HTTPS", "URL does not use HTTPS encryption", -15))
            scoreDelta -= 15
        }
        
        if (httpsAnalysis.httpsAvailable && !httpsAnalysis.supportsHttps) {
            reasons.add(Reason("HTTPS_AVAILABLE", "HTTPS is available but not used", -5))
            scoreDelta -= 5
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes TLS certificate and returns score delta.
     */
    private fun analyzeTlsCertificate(tlsAnalysis: TlsCertificateAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (tlsAnalysis.hasValidCertificate) {
            reasons.add(Reason("VALID_TLS", "Valid TLS certificate", 5))
            scoreDelta += 5
        } else {
            reasons.add(Reason("INVALID_TLS", "Invalid or missing TLS certificate", -20))
            scoreDelta -= 20
        }
        
        when {
            tlsAnalysis.isExpired -> {
                reasons.add(Reason("EXPIRED_CERT", "TLS certificate has expired", -25))
                scoreDelta -= 25
            }
            tlsAnalysis.isExpiringSoon -> {
                reasons.add(Reason("EXPIRING_CERT", "TLS certificate expires soon (${tlsAnalysis.daysUntilExpiry} days)", -5))
                scoreDelta -= 5
            }
            tlsAnalysis.daysUntilExpiry > 90 -> {
                reasons.add(Reason("LONG_VALID_CERT", "TLS certificate valid for ${tlsAnalysis.daysUntilExpiry} days", 3))
                scoreDelta += 3
            }
        }
        
        // Analyze security issues
        tlsAnalysis.securityIssues.forEach { issue ->
            val severityDelta = when (issue.severity) {
                com.nexable.safecheck.core.platform.tls.Severity.CRITICAL -> -15
                com.nexable.safecheck.core.platform.tls.Severity.HIGH -> -10
                com.nexable.safecheck.core.platform.tls.Severity.MEDIUM -> -5
                com.nexable.safecheck.core.platform.tls.Severity.LOW -> -2
            }
            reasons.add(Reason("TLS_SECURITY_ISSUE", issue.description, severityDelta))
            scoreDelta += severityDelta
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes domain age and returns score delta.
     */
    private fun analyzeDomainAge(whoisAnalysis: WhoisDomainAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        when {
            whoisAnalysis.ageDays > 365 * 2 -> {
                reasons.add(Reason("VERY_ESTABLISHED_DOMAIN", "Domain is very well-established (${whoisAnalysis.ageDays} days)", 15))
                scoreDelta += 15
            }
            whoisAnalysis.ageDays > 365 -> {
                reasons.add(Reason("ESTABLISHED_DOMAIN", "Domain is well-established (${whoisAnalysis.ageDays} days)", 10))
                scoreDelta += 10
            }
            whoisAnalysis.ageDays > 90 -> {
                reasons.add(Reason("MODERATE_AGE", "Domain is moderately aged (${whoisAnalysis.ageDays} days)", 5))
                scoreDelta += 5
            }
            whoisAnalysis.ageDays > 30 -> {
                reasons.add(Reason("NEW_DOMAIN", "Domain is new (${whoisAnalysis.ageDays} days)", -5))
                scoreDelta -= 5
            }
            whoisAnalysis.ageDays > 0 -> {
                reasons.add(Reason("VERY_NEW_DOMAIN", "Domain is very new (${whoisAnalysis.ageDays} days)", -10))
                scoreDelta -= 10
            }
            else -> {
                reasons.add(Reason("UNKNOWN_AGE", "Unable to determine domain age", -5))
                scoreDelta -= 5
            }
        }
        
        if (whoisAnalysis.isExpired) {
            reasons.add(Reason("EXPIRED_DOMAIN", "Domain registration has expired", -30))
            scoreDelta -= 30
        } else if (whoisAnalysis.daysTillExpiry != null && whoisAnalysis.daysTillExpiry!! < 30) {
            reasons.add(Reason("EXPIRING_DOMAIN", "Domain expires soon (${whoisAnalysis.daysTillExpiry} days)", -10))
            scoreDelta -= 10
        }
        
        if (whoisAnalysis.isPrivacyProtected) {
            reasons.add(Reason("PRIVACY_PROTECTED", "Domain registration is privacy protected", -3))
            scoreDelta -= 3
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes DNS records and returns score delta.
     */
    private fun analyzeDnsRecords(dnsAnalysis: DnsRecordAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (dnsAnalysis.hasARecords) {
            reasons.add(Reason("HAS_DNS_A", "Domain has valid A records", 5))
            scoreDelta += 5
        } else {
            reasons.add(Reason("NO_DNS_A", "Domain lacks A records", -15))
            scoreDelta -= 15
        }
        
        if (dnsAnalysis.hasAAAARecords) {
            reasons.add(Reason("HAS_IPV6", "Domain supports IPv6", 2))
            scoreDelta += 2
        }
        
        if (dnsAnalysis.hasMxRecords) {
            reasons.add(Reason("HAS_EMAIL", "Domain has email capabilities", 1))
            scoreDelta += 1
        }
        
        if (dnsAnalysis.hasSpfRecord) {
            reasons.add(Reason("HAS_SPF", "Domain has SPF email security record", 3))
            scoreDelta += 3
        }
        
        if (dnsAnalysis.hasDmarcRecord) {
            reasons.add(Reason("HAS_DMARC", "Domain has DMARC email security record", 3))
            scoreDelta += 3
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes security threats and returns score delta.
     */
    private fun analyzeSecurityThreats(analysis: UrlAnalysisResults, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // Homograph Analysis
        if (analysis.homographAnalysis.isSuspicious) {
            val severity = when {
                analysis.homographAnalysis.hasMixedScripts -> -30
                analysis.homographAnalysis.hasSuspiciousCharacters -> -20
                else -> -10
            }
            reasons.add(Reason("HOMOGRAPH_ATTACK", "Domain contains suspicious Unicode characters", severity))
            scoreDelta += severity
        }
        
        // Typosquatting Analysis
        if (analysis.typosquattingAnalysis.isSuspicious) {
            val similarity = analysis.typosquattingAnalysis.similarities.firstOrNull()
            if (similarity != null) {
                val severity = when {
                    similarity.similarity > 0.9 -> -30
                    similarity.similarity > 0.8 -> -25
                    else -> -15
                }
                reasons.add(Reason("TYPOSQUATTING", "Domain similar to ${similarity.targetDomain} (${(similarity.similarity * 100).toInt()}% similar)", severity))
                scoreDelta += severity
            }
        }
        
        // IDN Analysis
        if (analysis.idnAnalysis.isIdn) {
            if (analysis.idnAnalysis.containsSuspiciousCharacters) {
                reasons.add(Reason("SUSPICIOUS_IDN", "Domain uses suspicious international characters", -20))
                scoreDelta -= 20
            } else {
                reasons.add(Reason("IDN_DOMAIN", "Domain uses international characters", -5))
                scoreDelta -= 5
            }
        }
        
        // URL Shortener Analysis
        if (analysis.shortenerAnalysis.isShortener) {
            reasons.add(Reason("URL_SHORTENER", "URL uses shortening service (${analysis.shortenerAnalysis.shortenerService})", -10))
            scoreDelta -= 10
        }
        
        // Reputation Analysis
        if (analysis.reputationAnalysis.isKnownMalicious) {
            reasons.add(Reason("KNOWN_MALICIOUS", "URL is known to be malicious", -50))
            scoreDelta -= 50
        } else if (analysis.reputationAnalysis.isSuspicious) {
            reasons.add(Reason("SUSPICIOUS_REPUTATION", "URL has suspicious reputation", -20))
            scoreDelta -= 20
        } else if (analysis.reputationAnalysis.reputationScore > 70) {
            reasons.add(Reason("GOOD_REPUTATION", "URL has good reputation", 5))
            scoreDelta += 5
        }
        
        return scoreDelta
    }
}

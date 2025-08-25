package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Reason

/**
 * Calculates security scores for emails based on comprehensive analysis results.
 */
object EmailScoreCalculator {
    
    /**
     * Calculates the overall security score based on all email analysis results.
     */
    fun calculateScore(analysis: EmailAnalysisResults): Pair<Int, List<Reason>> {
        val reasons = mutableListOf<Reason>()
        var score = 100 // Start with perfect score
        
        // Email Syntax Analysis (10% weight)
        score += analyzeEmailSyntax(analysis.syntaxAnalysis, reasons)
        
        // Disposable Email Analysis (20% weight)
        score += analyzeDisposableEmail(analysis.disposableAnalysis, reasons)
        
        // Email Infrastructure Analysis (25% weight)
        score += analyzeEmailInfrastructure(analysis, reasons)
        
        // Email Security Policies Analysis (25% weight)
        score += analyzeEmailSecurity(analysis, reasons)
        
        // Provider and Domain Reputation Analysis (20% weight)
        score += analyzeReputation(analysis, reasons)
        
        // Ensure score stays within bounds
        score = score.coerceIn(0, 100)
        
        return Pair(score, reasons)
    }
    
    /**
     * Analyzes email syntax and returns score delta.
     */
    private fun analyzeEmailSyntax(syntaxAnalysis: EmailSyntaxAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (!syntaxAnalysis.isValid) {
            reasons.add(Reason("INVALID_EMAIL_SYNTAX", "Email has invalid syntax", -30))
            scoreDelta -= 30
        } else if (syntaxAnalysis.rfc5322Compliant) {
            reasons.add(Reason("RFC5322_COMPLIANT", "Email follows RFC 5322 standards", 5))
            scoreDelta += 5
        }
        
        // Analyze specific syntax issues
        for (issue in syntaxAnalysis.syntaxIssues) {
            val severity = when (issue.severity) {
                EmailSeverity.CRITICAL -> -15
                EmailSeverity.HIGH -> -10
                EmailSeverity.MEDIUM -> -5
                EmailSeverity.LOW -> -2
            }
            reasons.add(Reason("SYNTAX_ISSUE", issue.description, severity))
            scoreDelta += severity
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes disposable email usage and returns score delta.
     */
    private fun analyzeDisposableEmail(disposableAnalysis: DisposableEmailAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (disposableAnalysis.isDisposable) {
            val severity = when (disposableAnalysis.providerType) {
                DisposableProviderType.TEMPORARY -> -25
                DisposableProviderType.GUERRILLA -> -30
                DisposableProviderType.FORWARDING -> -15
                DisposableProviderType.ALIAS -> -10
                DisposableProviderType.UNKNOWN -> -20
            }
            
            val service = disposableAnalysis.disposableService ?: "unknown service"
            reasons.add(Reason("DISPOSABLE_EMAIL", "Email uses disposable service ($service)", severity))
            scoreDelta += severity
            
        } else {
            reasons.add(Reason("PERMANENT_EMAIL", "Email appears to be permanent", 5))
            scoreDelta += 5
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes email infrastructure and returns score delta.
     */
    private fun analyzeEmailInfrastructure(analysis: EmailAnalysisResults, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // MX Record Analysis
        if (analysis.mxAnalysis.hasMxRecords) {
            reasons.add(Reason("HAS_MX_RECORDS", "Domain has valid MX records", 10))
            scoreDelta += 10
            
            if (analysis.mxAnalysis.hasBackupMx) {
                reasons.add(Reason("HAS_BACKUP_MX", "Domain has backup MX records", 5))
                scoreDelta += 5
            }
            
            // Factor in MX reputation
            when {
                analysis.mxAnalysis.mxReputationScore >= 80 -> {
                    reasons.add(Reason("GOOD_MX_REPUTATION", "MX servers have good reputation", 5))
                    scoreDelta += 5
                }
                analysis.mxAnalysis.mxReputationScore <= 30 -> {
                    reasons.add(Reason("POOR_MX_REPUTATION", "MX servers have poor reputation", -10))
                    scoreDelta -= 10
                }
            }
        } else {
            reasons.add(Reason("NO_MX_RECORDS", "Domain lacks MX records", -20))
            scoreDelta -= 20
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes email security policies and returns score delta.
     */
    private fun analyzeEmailSecurity(analysis: EmailAnalysisResults, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // SPF Analysis
        if (analysis.spfAnalysis.hasSpfRecord) {
            if (analysis.spfAnalysis.isValid) {
                reasons.add(Reason("VALID_SPF", "Domain has valid SPF record", 8))
                scoreDelta += 8
                
                if (analysis.spfAnalysis.hasHardFail) {
                    reasons.add(Reason("SPF_HARD_FAIL", "SPF policy includes hard fail", 5))
                    scoreDelta += 5
                } else if (analysis.spfAnalysis.allowsAll) {
                    reasons.add(Reason("SPF_ALLOWS_ALL", "SPF policy allows all senders", -5))
                    scoreDelta -= 5
                }
            } else {
                reasons.add(Reason("INVALID_SPF", "Domain has invalid SPF record", -3))
                scoreDelta -= 3
            }
        } else {
            reasons.add(Reason("NO_SPF_RECORD", "Domain lacks SPF record", -8))
            scoreDelta -= 8
        }
        
        // DMARC Analysis
        if (analysis.dmarcAnalysis.hasDmarcRecord) {
            if (analysis.dmarcAnalysis.isValid) {
                reasons.add(Reason("VALID_DMARC", "Domain has valid DMARC policy", 10))
                scoreDelta += 10
                
                when (analysis.dmarcAnalysis.policy) {
                    DmarcPolicy.REJECT -> {
                        reasons.add(Reason("DMARC_REJECT", "DMARC policy is set to reject", 8))
                        scoreDelta += 8
                    }
                    DmarcPolicy.QUARANTINE -> {
                        reasons.add(Reason("DMARC_QUARANTINE", "DMARC policy is set to quarantine", 5))
                        scoreDelta += 5
                    }
                    DmarcPolicy.NONE -> {
                        reasons.add(Reason("DMARC_NONE", "DMARC policy is set to none", 0))
                    }
                }
            } else {
                reasons.add(Reason("INVALID_DMARC", "Domain has invalid DMARC record", -3))
                scoreDelta -= 3
            }
        } else {
            reasons.add(Reason("NO_DMARC_RECORD", "Domain lacks DMARC policy", -10))
            scoreDelta -= 10
        }
        
        // DKIM Analysis
        if (analysis.dkimAnalysis.hasDkimSupport) {
            if (analysis.dkimAnalysis.isConfiguredCorrectly) {
                reasons.add(Reason("VALID_DKIM", "Domain has properly configured DKIM", 7))
                scoreDelta += 7
                
                if (analysis.dkimAnalysis.keyLength >= 2048) {
                    reasons.add(Reason("STRONG_DKIM_KEY", "DKIM uses strong key length", 3))
                    scoreDelta += 3
                } else if (analysis.dkimAnalysis.keyLength < 1024) {
                    reasons.add(Reason("WEAK_DKIM_KEY", "DKIM uses weak key length", -5))
                    scoreDelta -= 5
                }
            } else {
                reasons.add(Reason("MISCONFIGURED_DKIM", "DKIM is misconfigured", -3))
                scoreDelta -= 3
            }
        } else {
            reasons.add(Reason("NO_DKIM", "Domain lacks DKIM authentication", -7))
            scoreDelta -= 7
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes reputation and returns score delta.
     */
    private fun analyzeReputation(analysis: EmailAnalysisResults, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // Domain Reputation Analysis
        val domainRep = analysis.domainReputationAnalysis
        if (domainRep.isKnownSpammer) {
            reasons.add(Reason("KNOWN_SPAMMER", "Domain is known for sending spam", -40))
            scoreDelta -= 40
        } else if (domainRep.isKnownPhisher) {
            reasons.add(Reason("KNOWN_PHISHER", "Domain is known for phishing", -50))
            scoreDelta -= 50
        } else if (domainRep.hasGoodReputation) {
            reasons.add(Reason("GOOD_DOMAIN_REPUTATION", "Domain has good reputation", 10))
            scoreDelta += 10
        }
        
        when (domainRep.blacklistStatus) {
            BlacklistStatus.LISTED -> {
                reasons.add(Reason("BLACKLISTED", "Domain is blacklisted", -30))
                scoreDelta -= 30
            }
            BlacklistStatus.SUSPICIOUS -> {
                reasons.add(Reason("SUSPICIOUS_DOMAIN", "Domain has suspicious reputation", -15))
                scoreDelta -= 15
            }
            BlacklistStatus.CLEAN -> {
                reasons.add(Reason("CLEAN_REPUTATION", "Domain has clean reputation", 5))
                scoreDelta += 5
            }
            BlacklistStatus.UNKNOWN -> {
                // Neutral, no score change
            }
        }
        
        // Provider Reputation Analysis
        val providerRep = analysis.providerReputationAnalysis
        when (providerRep.providerType) {
            EmailProviderType.MAJOR_PROVIDER -> {
                reasons.add(Reason("MAJOR_PROVIDER", "Email from major provider (${providerRep.providerName})", 15))
                scoreDelta += 15
            }
            EmailProviderType.BUSINESS_PROVIDER -> {
                reasons.add(Reason("BUSINESS_PROVIDER", "Email from business provider", 10))
                scoreDelta += 10
            }
            EmailProviderType.HOSTING_PROVIDER -> {
                reasons.add(Reason("HOSTING_PROVIDER", "Email from hosting provider", 5))
                scoreDelta += 5
            }
            EmailProviderType.CUSTOM_DOMAIN -> {
                reasons.add(Reason("CUSTOM_DOMAIN", "Email from custom domain", 0))
            }
            EmailProviderType.DISPOSABLE -> {
                reasons.add(Reason("DISPOSABLE_PROVIDER", "Email from disposable provider", -25))
                scoreDelta -= 25
            }
            EmailProviderType.SUSPICIOUS -> {
                reasons.add(Reason("SUSPICIOUS_PROVIDER", "Email from suspicious provider", -20))
                scoreDelta -= 20
            }
            EmailProviderType.UNKNOWN -> {
                reasons.add(Reason("UNKNOWN_PROVIDER", "Email from unknown provider", -5))
                scoreDelta -= 5
            }
        }
        
        if (providerRep.hasGoodDeliverability) {
            reasons.add(Reason("GOOD_DELIVERABILITY", "Provider has good deliverability", 5))
            scoreDelta += 5
        }
        
        when (providerRep.trustLevel) {
            ProviderTrustLevel.HIGH -> {
                reasons.add(Reason("HIGH_TRUST_PROVIDER", "High trust provider", 8))
                scoreDelta += 8
            }
            ProviderTrustLevel.MEDIUM -> {
                reasons.add(Reason("MEDIUM_TRUST_PROVIDER", "Medium trust provider", 3))
                scoreDelta += 3
            }
            ProviderTrustLevel.LOW -> {
                reasons.add(Reason("LOW_TRUST_PROVIDER", "Low trust provider", -10))
                scoreDelta -= 10
            }
            ProviderTrustLevel.UNKNOWN -> {
                // Neutral, no score change
            }
        }
        
        return scoreDelta
    }
}

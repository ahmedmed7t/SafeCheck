package com.nexable.safecheck.core.domain.scanner

import kotlinx.datetime.Clock

/**
 * Email domain reputation analyzer.
 */
object EmailDomainReputationAnalyzer {
    
    // Known malicious email domains
    private val knownSpamDomains = setOf(
        "spam.example.com", "phishing.example.com", "malware.example.com",
        // In a real implementation, this would be a comprehensive database
        // of known malicious domains updated regularly
    )
    
    // Known phishing domains
    private val knownPhishingDomains = setOf(
        "paypal-security.com", "amazon-update.com", "apple-verification.com",
        "microsoft-security.net", "google-account.org", "facebook-security.com",
        // These are examples - real implementation would have comprehensive lists
    )
    
    /**
     * Analyzes email domain reputation.
     */
    suspend fun analyze(domain: String): EmailDomainReputationAnalysis {
        val isKnownSpammer = knownSpamDomains.contains(domain.lowercase())
        val isKnownPhisher = knownPhishingDomains.contains(domain.lowercase())
        
        var reputationScore = 50 // Start with neutral score
        val reputationSources = mutableListOf<ReputationSource>()
        
        // Check against known malicious domains
        if (isKnownSpammer) {
            reputationScore = 0
            reputationSources.add(
                ReputationSource(
                    name = "SafeCheck Spam Database",
                    verdict = "SPAM",
                    confidence = 1.0,
                    details = mapOf("category" to "known_spammer")
                )
            )
        }
        
        if (isKnownPhisher) {
            reputationScore = 0
            reputationSources.add(
                ReputationSource(
                    name = "SafeCheck Phishing Database",
                    verdict = "PHISHING",
                    confidence = 1.0,
                    details = mapOf("category" to "known_phisher")
                )
            )
        }
        
        // Check domain characteristics
        val domainAnalysis = analyzeDomainCharacteristics(domain)
        reputationScore = (reputationScore + domainAnalysis.score) / 2
        
        if (domainAnalysis.isSuspicious) {
            reputationSources.add(
                ReputationSource(
                    name = "Domain Analysis",
                    verdict = "SUSPICIOUS",
                    confidence = domainAnalysis.confidence,
                    details = domainAnalysis.reasons
                )
            )
        }
        
        val hasGoodReputation = reputationScore >= 70 && !isKnownSpammer && !isKnownPhisher
        val blacklistStatus = when {
            isKnownSpammer || isKnownPhisher -> BlacklistStatus.LISTED
            reputationScore < 30 -> BlacklistStatus.SUSPICIOUS
            else -> BlacklistStatus.CLEAN
        }
        
        return EmailDomainReputationAnalysis(
            domain = domain,
            reputationScore = reputationScore.toInt().coerceIn(0, 100),
            isKnownSpammer = isKnownSpammer,
            isKnownPhisher = isKnownPhisher,
            hasGoodReputation = hasGoodReputation,
            reputationSources = reputationSources,
            blacklistStatus = blacklistStatus,
            lastChecked = Clock.System.now()
        )
    }
    
    private fun analyzeDomainCharacteristics(domain: String): DomainCharacteristics {
        var score = 50
        val reasons = mutableMapOf<String, String>()
        var isSuspicious = false
        var confidence = 0.0
        
        // Check for suspicious patterns
        val suspiciousPatterns = listOf(
            "phish", "scam", "fake", "security-", "account-", "verify-",
            "update-", "confirm-", "alert-", "warning-", "urgent-",
            "suspended-", "limited-", "restricted-"
        )
        
        for (pattern in suspiciousPatterns) {
            if (domain.contains(pattern, ignoreCase = true)) {
                score -= 20
                isSuspicious = true
                confidence += 0.3
                reasons["suspicious_keyword"] = "Domain contains suspicious keyword: $pattern"
            }
        }
        
        // Check for homograph attacks (simplified)
        if (domain.any { it.code > 127 }) {
            score -= 15
            isSuspicious = true
            confidence += 0.2
            reasons["homograph"] = "Domain contains non-ASCII characters"
        }
        
        // Check for excessive hyphens
        val hyphenCount = domain.count { it == '-' }
        if (hyphenCount > 3) {
            score -= 10
            confidence += 0.1
            reasons["excessive_hyphens"] = "Domain contains excessive hyphens"
        }
        
        // Check for numbers in suspicious positions
        if (domain.matches(Regex(".*\\d{4,}.*"))) {
            score -= 5
            confidence += 0.1
            reasons["suspicious_numbers"] = "Domain contains suspicious number patterns"
        }
        
        // Check for very long domains
        if (domain.length > 50) {
            score -= 10
            confidence += 0.1
            reasons["long_domain"] = "Domain is unusually long"
        }
        
        // Check for new TLDs that are commonly abused
        val suspiciousTlds = listOf(
            ".tk", ".ml", ".ga", ".cf", ".click", ".download", ".zip"
        )
        
        for (tld in suspiciousTlds) {
            if (domain.endsWith(tld, ignoreCase = true)) {
                score -= 15
                isSuspicious = true
                confidence += 0.2
                reasons["suspicious_tld"] = "Domain uses TLD commonly associated with abuse: $tld"
            }
        }
        
        return DomainCharacteristics(
            score = score.coerceIn(0, 100),
            isSuspicious = isSuspicious,
            confidence = confidence.coerceAtMost(1.0),
            reasons = reasons
        )
    }
    
    private data class DomainCharacteristics(
        val score: Int,
        val isSuspicious: Boolean,
        val confidence: Double,
        val reasons: Map<String, String>
    )
}

/**
 * Email provider reputation analyzer.
 */
object EmailProviderReputationAnalyzer {
    
    // Major email providers with high trust
    private val majorProviders = mapOf(
        "gmail.com" to ProviderInfo("Google Gmail", EmailProviderType.MAJOR_PROVIDER, 95),
        "googlemail.com" to ProviderInfo("Google Gmail", EmailProviderType.MAJOR_PROVIDER, 95),
        "outlook.com" to ProviderInfo("Microsoft Outlook", EmailProviderType.MAJOR_PROVIDER, 90),
        "hotmail.com" to ProviderInfo("Microsoft Hotmail", EmailProviderType.MAJOR_PROVIDER, 85),
        "live.com" to ProviderInfo("Microsoft Live", EmailProviderType.MAJOR_PROVIDER, 85),
        "yahoo.com" to ProviderInfo("Yahoo Mail", EmailProviderType.MAJOR_PROVIDER, 80),
        "ymail.com" to ProviderInfo("Yahoo Mail", EmailProviderType.MAJOR_PROVIDER, 80),
        "icloud.com" to ProviderInfo("Apple iCloud", EmailProviderType.MAJOR_PROVIDER, 90),
        "me.com" to ProviderInfo("Apple iCloud", EmailProviderType.MAJOR_PROVIDER, 90),
        "mac.com" to ProviderInfo("Apple iCloud", EmailProviderType.MAJOR_PROVIDER, 85),
        "aol.com" to ProviderInfo("AOL Mail", EmailProviderType.MAJOR_PROVIDER, 75),
        "protonmail.com" to ProviderInfo("ProtonMail", EmailProviderType.MAJOR_PROVIDER, 85),
        "protonmail.ch" to ProviderInfo("ProtonMail", EmailProviderType.MAJOR_PROVIDER, 85)
    )
    
    // Business email providers
    private val businessProviders = mapOf(
        "office365.com" to ProviderInfo("Microsoft Office 365", EmailProviderType.BUSINESS_PROVIDER, 90),
        "exchange.com" to ProviderInfo("Microsoft Exchange", EmailProviderType.BUSINESS_PROVIDER, 85),
        "zoho.com" to ProviderInfo("Zoho Mail", EmailProviderType.BUSINESS_PROVIDER, 80),
        "fastmail.com" to ProviderInfo("FastMail", EmailProviderType.BUSINESS_PROVIDER, 85),
        "mailbox.org" to ProviderInfo("Mailbox.org", EmailProviderType.BUSINESS_PROVIDER, 80),
        "tutanota.com" to ProviderInfo("Tutanota", EmailProviderType.BUSINESS_PROVIDER, 80)
    )
    
    // Common hosting providers
    private val hostingProviders = mapOf(
        "godaddy.com" to ProviderInfo("GoDaddy", EmailProviderType.HOSTING_PROVIDER, 70),
        "bluehost.com" to ProviderInfo("Bluehost", EmailProviderType.HOSTING_PROVIDER, 70),
        "hostgator.com" to ProviderInfo("HostGator", EmailProviderType.HOSTING_PROVIDER, 70),
        "namecheap.com" to ProviderInfo("Namecheap", EmailProviderType.HOSTING_PROVIDER, 70),
        "siteground.com" to ProviderInfo("SiteGround", EmailProviderType.HOSTING_PROVIDER, 75)
    )
    
    /**
     * Analyzes email provider reputation.
     */
    suspend fun analyze(domain: String): EmailProviderReputationAnalysis {
        val lowerDomain = domain.lowercase()
        
        // Check major providers
        majorProviders[lowerDomain]?.let { providerInfo ->
            return EmailProviderReputationAnalysis(
                domain = domain,
                providerName = providerInfo.name,
                providerType = providerInfo.type,
                reputationScore = providerInfo.score,
                isWellKnownProvider = true,
                hasGoodDeliverability = true,
                securityFeatures = getMajorProviderSecurityFeatures(lowerDomain),
                trustLevel = ProviderTrustLevel.HIGH
            )
        }
        
        // Check business providers
        businessProviders[lowerDomain]?.let { providerInfo ->
            return EmailProviderReputationAnalysis(
                domain = domain,
                providerName = providerInfo.name,
                providerType = providerInfo.type,
                reputationScore = providerInfo.score,
                isWellKnownProvider = true,
                hasGoodDeliverability = true,
                securityFeatures = getBusinessProviderSecurityFeatures(lowerDomain),
                trustLevel = ProviderTrustLevel.HIGH
            )
        }
        
        // Check hosting providers
        hostingProviders[lowerDomain]?.let { providerInfo ->
            return EmailProviderReputationAnalysis(
                domain = domain,
                providerName = providerInfo.name,
                providerType = providerInfo.type,
                reputationScore = providerInfo.score,
                isWellKnownProvider = true,
                hasGoodDeliverability = false,
                securityFeatures = getHostingProviderSecurityFeatures(lowerDomain),
                trustLevel = ProviderTrustLevel.MEDIUM
            )
        }
        
        // Check if it's a disposable provider
        if (DisposableEmailDetector.isDomainDisposable(lowerDomain)) {
            return EmailProviderReputationAnalysis(
                domain = domain,
                providerName = "Disposable Email Provider",
                providerType = EmailProviderType.DISPOSABLE,
                reputationScore = 10,
                isWellKnownProvider = false,
                hasGoodDeliverability = false,
                securityFeatures = emptyList(),
                trustLevel = ProviderTrustLevel.LOW
            )
        }
        
        // Check for custom domain characteristics
        val customDomainAnalysis = analyzeCustomDomain(domain)
        
        return EmailProviderReputationAnalysis(
            domain = domain,
            providerName = null,
            providerType = customDomainAnalysis.type,
            reputationScore = customDomainAnalysis.score,
            isWellKnownProvider = false,
            hasGoodDeliverability = customDomainAnalysis.likelyGoodDeliverability,
            securityFeatures = emptyList(),
            trustLevel = customDomainAnalysis.trustLevel
        )
    }
    
    private fun getMajorProviderSecurityFeatures(domain: String): List<SecurityFeature> {
        return when (domain) {
            "gmail.com", "googlemail.com" -> listOf(
                SecurityFeature("Two-Factor Authentication", true, "Supports 2FA"),
                SecurityFeature("Advanced Phishing Protection", true, "Built-in phishing detection"),
                SecurityFeature("Encryption in Transit", true, "TLS encryption"),
                SecurityFeature("Encryption at Rest", true, "Data encrypted at rest"),
                SecurityFeature("DMARC Support", true, "Full DMARC implementation")
            )
            "outlook.com", "hotmail.com", "live.com" -> listOf(
                SecurityFeature("Two-Factor Authentication", true, "Supports 2FA"),
                SecurityFeature("Advanced Threat Protection", true, "Built-in threat protection"),
                SecurityFeature("Encryption in Transit", true, "TLS encryption"),
                SecurityFeature("DMARC Support", true, "Full DMARC implementation")
            )
            "protonmail.com", "protonmail.ch" -> listOf(
                SecurityFeature("End-to-End Encryption", true, "Zero-access encryption"),
                SecurityFeature("Two-Factor Authentication", true, "Supports 2FA"),
                SecurityFeature("Open Source", true, "Auditable code"),
                SecurityFeature("Anonymous Account Creation", true, "Privacy focused")
            )
            else -> emptyList()
        }
    }
    
    private fun getBusinessProviderSecurityFeatures(domain: String): List<SecurityFeature> {
        return listOf(
            SecurityFeature("Business-Grade Security", true, "Enterprise security features"),
            SecurityFeature("Encryption in Transit", true, "TLS encryption"),
            SecurityFeature("Spam Protection", true, "Advanced spam filtering")
        )
    }
    
    private fun getHostingProviderSecurityFeatures(domain: String): List<SecurityFeature> {
        return listOf(
            SecurityFeature("Basic Encryption", true, "Standard TLS encryption"),
            SecurityFeature("Spam Protection", false, "Limited spam filtering")
        )
    }
    
    private fun analyzeCustomDomain(domain: String): CustomDomainAnalysis {
        // Analyze characteristics of custom domains
        var score = 50
        var trustLevel = ProviderTrustLevel.UNKNOWN
        var type = EmailProviderType.CUSTOM_DOMAIN
        var likelyGoodDeliverability = false
        
        // Check for corporate indicators
        val corporateIndicators = listOf(
            "corp", "company", "inc", "ltd", "llc", "group", "enterprise",
            "business", "org", "edu", "gov"
        )
        
        val hasCorporateIndicators = corporateIndicators.any { indicator ->
            domain.contains(indicator, ignoreCase = true)
        }
        
        if (hasCorporateIndicators) {
            score += 15
            trustLevel = ProviderTrustLevel.MEDIUM
            type = EmailProviderType.BUSINESS_PROVIDER
            likelyGoodDeliverability = true
        }
        
        // Check for suspicious characteristics
        val suspiciousPatterns = listOf(
            "temp", "fake", "test", "spam", "noreply", "donotreply"
        )
        
        val hasSuspiciousPatterns = suspiciousPatterns.any { pattern ->
            domain.contains(pattern, ignoreCase = true)
        }
        
        if (hasSuspiciousPatterns) {
            score -= 20
            trustLevel = ProviderTrustLevel.LOW
            type = EmailProviderType.SUSPICIOUS
        }
        
        // Check domain age indicators (simplified heuristic)
        if (domain.length > 15) {
            score += 5 // Longer domains might be more established
        }
        
        return CustomDomainAnalysis(
            score = score.coerceIn(0, 100),
            trustLevel = trustLevel,
            type = type,
            likelyGoodDeliverability = likelyGoodDeliverability
        )
    }
    
    private data class ProviderInfo(
        val name: String,
        val type: EmailProviderType,
        val score: Int
    )
    
    private data class CustomDomainAnalysis(
        val score: Int,
        val trustLevel: ProviderTrustLevel,
        val type: EmailProviderType,
        val likelyGoodDeliverability: Boolean
    )
}

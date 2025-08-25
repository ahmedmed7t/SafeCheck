package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.platform.dns.DnsResolver

/**
 * MX record analyzer using platform DNS implementation.
 */
object MxRecordAnalyzer {
    
    /**
     * Analyzes MX records for an email domain.
     */
    suspend fun analyze(domain: String, dnsResolver: DnsResolver): MxRecordAnalysis {
        return when (val result = dnsResolver.resolveMX(domain)) {
            is Result.Success -> {
                val mxRecords = result.data
                val mxRecordInfos = mxRecords.map { mx ->
                    MxRecordInfo(
                        host = mx.host,
                        priority = mx.priority,
                        isReachable = false, // Would need additional network check
                        responseTime = 0
                    )
                }
                
                val primaryMx = mxRecords.minByOrNull { it.priority }
                val hasBackupMx = mxRecords.size > 1
                
                MxRecordAnalysis(
                    domain = domain,
                    hasMxRecords = mxRecords.isNotEmpty(),
                    mxRecords = mxRecordInfos,
                    primaryMxHost = primaryMx?.host,
                    mxCount = mxRecords.size,
                    hasBackupMx = hasBackupMx,
                    mxReputationScore = calculateMxReputationScore(mxRecords)
                )
            }
            is Result.Error -> {
                MxRecordAnalysis(
                    domain = domain,
                    hasMxRecords = false,
                    mxReputationScore = 0
                )
            }
            is Result.Loading -> {
                MxRecordAnalysis(
                    domain = domain,
                    hasMxRecords = false,
                    mxReputationScore = 25
                )
            }
        }
    }
    
    private fun calculateMxReputationScore(mxRecords: List<com.nexable.safecheck.core.platform.dns.MxRecord>): Int {
        if (mxRecords.isEmpty()) return 0
        
        var score = 50 // Base score
        
        // Bonus for having multiple MX records (redundancy)
        if (mxRecords.size > 1) score += 10
        
        // Bonus for well-known mail providers
        val knownProviders = listOf(
            "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
            "icloud.com", "protonmail.com", "zoho.com", "fastmail.com"
        )
        
        val hasKnownProvider = mxRecords.any { mx ->
            knownProviders.any { provider ->
                mx.host.contains(provider, ignoreCase = true)
            }
        }
        
        if (hasKnownProvider) score += 20
        
        // Check for proper priority distribution
        val priorities = mxRecords.map { it.priority }.sorted()
        if (priorities.size > 1 && priorities[1] - priorities[0] >= 5) {
            score += 5 // Proper priority separation
        }
        
        return score.coerceIn(0, 100)
    }
}

/**
 * SPF record analyzer using platform DNS implementation.
 */
object SpfRecordAnalyzer {
    
    /**
     * Analyzes SPF records for an email domain.
     */
    suspend fun analyze(domain: String, dnsResolver: DnsResolver): SpfRecordAnalysis {
        return when (val result = dnsResolver.resolveTXT(domain)) {
            is Result.Success -> {
                val txtRecords = result.data
                val spfRecord = txtRecords.find { it.startsWith("v=spf1") }
                
                if (spfRecord != null) {
                    analyzeSpfRecord(domain, spfRecord)
                } else {
                    SpfRecordAnalysis(
                        domain = domain,
                        hasSpfRecord = false
                    )
                }
            }
            is Result.Error -> {
                SpfRecordAnalysis(
                    domain = domain,
                    hasSpfRecord = false
                )
            }
            is Result.Loading -> {
                SpfRecordAnalysis(
                    domain = domain,
                    hasSpfRecord = false
                )
            }
        }
    }
    
    private fun analyzeSpfRecord(domain: String, spfRecord: String): SpfRecordAnalysis {
        val mechanisms = mutableListOf<SpfMechanism>()
        val qualifiers = mutableListOf<SpfQualifier>()
        
        val tokens = spfRecord.split(" ")
        var isValid = true
        var hasHardFail = false
        var allowsAll = false
        
        for (token in tokens) {
            val trimmedToken = token.trim()
            if (trimmedToken.isEmpty()) continue
            
            when {
                trimmedToken.startsWith("v=spf1") -> {
                    // Version declaration, skip
                }
                trimmedToken.startsWith("include:") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.INCLUDE, trimmedToken.substring(8)))
                }
                trimmedToken.startsWith("a") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.A, trimmedToken))
                }
                trimmedToken.startsWith("mx") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.MX, trimmedToken))
                }
                trimmedToken.startsWith("ip4:") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.IP4, trimmedToken.substring(4)))
                }
                trimmedToken.startsWith("ip6:") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.IP6, trimmedToken.substring(4)))
                }
                trimmedToken.startsWith("exists:") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.EXISTS, trimmedToken.substring(7)))
                }
                trimmedToken.startsWith("redirect=") -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.REDIRECT, trimmedToken.substring(9)))
                }
                trimmedToken == "all" || trimmedToken == "+all" -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.ALL, "all", "+"))
                    allowsAll = true
                }
                trimmedToken == "-all" -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.ALL, "all", "-"))
                    hasHardFail = true
                }
                trimmedToken == "~all" -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.ALL, "all", "~"))
                }
                trimmedToken == "?all" -> {
                    mechanisms.add(SpfMechanism(SpfMechanismType.ALL, "all", "?"))
                }
            }
        }
        
        // Add qualifiers based on mechanisms
        if (hasHardFail) {
            qualifiers.add(SpfQualifier(SpfQualifierType.FAIL, "Hard fail policy"))
        }
        if (allowsAll) {
            qualifiers.add(SpfQualifier(SpfQualifierType.PASS, "Allows all senders"))
        }
        
        return SpfRecordAnalysis(
            domain = domain,
            hasSpfRecord = true,
            spfRecord = spfRecord,
            spfVersion = "spf1",
            mechanisms = mechanisms,
            qualifiers = qualifiers,
            isValid = isValid,
            hasHardFail = hasHardFail,
            allowsAll = allowsAll
        )
    }
}

/**
 * DMARC policy analyzer using platform DNS implementation.
 */
object DmarcPolicyAnalyzer {
    
    /**
     * Analyzes DMARC policy for an email domain.
     */
    suspend fun analyze(domain: String, dnsResolver: DnsResolver): DmarcPolicyAnalysis {
        val dmarcDomain = "_dmarc.$domain"
        
        return when (val result = dnsResolver.resolveTXT(dmarcDomain)) {
            is Result.Success -> {
                val txtRecords = result.data
                val dmarcRecord = txtRecords.find { it.startsWith("v=DMARC1") }
                
                if (dmarcRecord != null) {
                    analyzeDmarcRecord(domain, dmarcRecord)
                } else {
                    DmarcPolicyAnalysis(
                        domain = domain,
                        hasDmarcRecord = false
                    )
                }
            }
            is Result.Error -> {
                DmarcPolicyAnalysis(
                    domain = domain,
                    hasDmarcRecord = false
                )
            }
            is Result.Loading -> {
                DmarcPolicyAnalysis(
                    domain = domain,
                    hasDmarcRecord = false
                )
            }
        }
    }
    
    private fun analyzeDmarcRecord(domain: String, dmarcRecord: String): DmarcPolicyAnalysis {
        val parts = dmarcRecord.split(";").map { it.trim() }
        var policy = DmarcPolicy.NONE
        var subdomainPolicy = DmarcPolicy.NONE
        var alignment = DmarcAlignment.RELAXED
        var percentage = 100
        val reportingUris = mutableListOf<String>()
        var isValid = true
        
        for (part in parts) {
            val keyValue = part.split("=", limit = 2)
            if (keyValue.size != 2) continue
            
            val key = keyValue[0].trim()
            val value = keyValue[1].trim()
            
            when (key) {
                "v" -> {
                    if (value != "DMARC1") isValid = false
                }
                "p" -> {
                    policy = when (value.lowercase()) {
                        "none" -> DmarcPolicy.NONE
                        "quarantine" -> DmarcPolicy.QUARANTINE
                        "reject" -> DmarcPolicy.REJECT
                        else -> DmarcPolicy.NONE
                    }
                }
                "sp" -> {
                    subdomainPolicy = when (value.lowercase()) {
                        "none" -> DmarcPolicy.NONE
                        "quarantine" -> DmarcPolicy.QUARANTINE
                        "reject" -> DmarcPolicy.REJECT
                        else -> DmarcPolicy.NONE
                    }
                }
                "adkim" -> {
                    alignment = when (value.lowercase()) {
                        "s" -> DmarcAlignment.STRICT
                        "r" -> DmarcAlignment.RELAXED
                        else -> DmarcAlignment.RELAXED
                    }
                }
                "aspf" -> {
                    alignment = when (value.lowercase()) {
                        "s" -> DmarcAlignment.STRICT
                        "r" -> DmarcAlignment.RELAXED
                        else -> DmarcAlignment.RELAXED
                    }
                }
                "pct" -> {
                    percentage = value.toIntOrNull() ?: 100
                }
                "rua" -> {
                    reportingUris.addAll(value.split(",").map { it.trim() })
                }
                "ruf" -> {
                    reportingUris.addAll(value.split(",").map { it.trim() })
                }
            }
        }
        
        return DmarcPolicyAnalysis(
            domain = domain,
            hasDmarcRecord = true,
            dmarcRecord = dmarcRecord,
            policy = policy,
            subdomainPolicy = subdomainPolicy,
            alignment = alignment,
            percentage = percentage,
            reportingUris = reportingUris,
            isValid = isValid
        )
    }
}

/**
 * DKIM analyzer using platform DNS implementation.
 */
object DkimAnalyzer {
    
    private val commonSelectors = listOf(
        "default", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
        "dkim", "mail", "email", "mx", "smtp", "key1", "key2"
    )
    
    /**
     * Analyzes DKIM configuration for an email domain.
     */
    suspend fun analyze(domain: String, dnsResolver: DnsResolver): DkimAnalysis {
        val foundSelectors = mutableListOf<String>()
        var validSignatures = 0
        var keyLength = 0
        var algorithm: String? = null
        
        // Check common DKIM selectors
        for (selector in commonSelectors) {
            val dkimDomain = "$selector._domainkey.$domain"
            
            when (val result = dnsResolver.resolveTXT(dkimDomain)) {
                is Result.Success -> {
                    val txtRecords = result.data
                    val dkimRecord = txtRecords.find { it.contains("k=") || it.contains("p=") }
                    
                    if (dkimRecord != null) {
                        foundSelectors.add(selector)
                        validSignatures++
                        
                        // Parse DKIM record for details
                        val parsedInfo = parseDkimRecord(dkimRecord)
                        if (keyLength == 0) keyLength = parsedInfo.keyLength
                        if (algorithm == null) algorithm = parsedInfo.algorithm
                    }
                }
                is Result.Error -> {
                    // Selector not found, continue
                }
                is Result.Loading -> {
                    // Skip for now
                }
            }
        }
        
        val hasDkimSupport = foundSelectors.isNotEmpty()
        val isConfiguredCorrectly = hasDkimSupport && keyLength >= 1024
        
        return DkimAnalysis(
            domain = domain,
            hasDkimSupport = hasDkimSupport,
            dkimSelectors = foundSelectors,
            validSignatures = validSignatures,
            keyLength = keyLength,
            algorithm = algorithm,
            isConfiguredCorrectly = isConfiguredCorrectly
        )
    }
    
    private fun parseDkimRecord(dkimRecord: String): DkimRecordInfo {
        var keyLength = 0
        var algorithm: String? = null
        
        val parts = dkimRecord.split(";").map { it.trim() }
        
        for (part in parts) {
            val keyValue = part.split("=", limit = 2)
            if (keyValue.size != 2) continue
            
            val key = keyValue[0].trim()
            val value = keyValue[1].trim()
            
            when (key) {
                "k" -> {
                    algorithm = value
                }
                "p" -> {
                    // Estimate key length from public key
                    keyLength = estimateKeyLength(value)
                }
            }
        }
        
        return DkimRecordInfo(keyLength, algorithm)
    }
    
    private fun estimateKeyLength(publicKey: String): Int {
        // Rough estimation based on base64 encoded key length
        val cleanKey = publicKey.replace(Regex("[^A-Za-z0-9+/=]"), "")
        return when {
            cleanKey.length > 350 -> 2048
            cleanKey.length > 200 -> 1024
            cleanKey.length > 100 -> 512
            else -> 256
        }
    }
    
    private data class DkimRecordInfo(
        val keyLength: Int,
        val algorithm: String?
    )
}

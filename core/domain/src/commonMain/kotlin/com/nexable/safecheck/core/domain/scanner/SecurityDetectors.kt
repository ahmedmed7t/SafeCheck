package com.nexable.safecheck.core.domain.scanner

/**
 * Homograph attack detection using Unicode analysis.
 */
object HomographDetector {
    
    /**
     * Analyzes domain for potential homograph attacks.
     */
    suspend fun analyze(domain: String): HomographAnalysis {
        val suspiciousCharacters = domain.any { char ->
            char.code > 127 && // Non-ASCII
            (char.category == CharCategory.LOWERCASE_LETTER ||
             char.category == CharCategory.UPPERCASE_LETTER)
        }
        
        val mixedScripts = detectMixedScripts(domain)
        val isSuspicious = suspiciousCharacters || mixedScripts
        
        return HomographAnalysis(
            domain = domain,
            isSuspicious = isSuspicious,
            hasSuspiciousCharacters = suspiciousCharacters,
            hasMixedScripts = mixedScripts,
            suspiciousCharacters = if (suspiciousCharacters) {
                domain.filter { it.code > 127 }.toSet().toList()
            } else emptyList()
        )
    }
    
    private fun detectMixedScripts(domain: String): Boolean {
        val scripts = domain.mapNotNull { char ->
            when (char.code) {
                in 0x0000..0x007F -> "Latin"
                in 0x0400..0x04FF -> "Cyrillic"
                in 0x4E00..0x9FFF -> "CJK"
                in 0x0590..0x05FF -> "Hebrew"
                in 0x0600..0x06FF -> "Arabic"
                else -> null
            }
        }.toSet()
        
        return scripts.size > 1
    }
}

/**
 * Typosquatting detection using edit distance algorithms.
 */
object TyposquattingDetector {
    
    private val popularDomains = listOf(
        "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
        "twitter.com", "instagram.com", "linkedin.com", "youtube.com", "netflix.com",
        "paypal.com", "ebay.com", "github.com", "stackoverflow.com", "reddit.com",
        "wikipedia.org", "gmail.com", "yahoo.com", "outlook.com", "dropbox.com"
    )
    
    /**
     * Analyzes domain for potential typosquatting.
     */
    suspend fun analyze(domain: String): TyposquattingAnalysis {
        val similarities = mutableListOf<DomainSimilarity>()
        
        for (popularDomain in popularDomains) {
            val distance = calculateLevenshteinDistance(domain, popularDomain)
            val similarity = 1.0 - (distance.toDouble() / maxOf(domain.length, popularDomain.length))
            
            // Consider domains with high similarity as potential typosquatting
            if (similarity > 0.7 && domain != popularDomain) {
                similarities.add(
                    DomainSimilarity(
                        targetDomain = popularDomain,
                        similarity = similarity,
                        editDistance = distance
                    )
                )
            }
        }
        
        return TyposquattingAnalysis(
            domain = domain,
            isSuspicious = similarities.isNotEmpty(),
            similarities = similarities.sortedByDescending { it.similarity }
        )
    }
    
    private fun calculateLevenshteinDistance(s1: String, s2: String): Int {
        val len1 = s1.length
        val len2 = s2.length
        val matrix = Array(len1 + 1) { IntArray(len2 + 1) }
        
        for (i in 0..len1) matrix[i][0] = i
        for (j in 0..len2) matrix[0][j] = j
        
        for (i in 1..len1) {
            for (j in 1..len2) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                matrix[i][j] = minOf(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                )
            }
        }
        
        return matrix[len1][len2]
    }
}

/**
 * IDN (Internationalized Domain Name) analyzer.
 */
object IdnAnalyzer {
    
    /**
     * Analyzes Internationalized Domain Names.
     */
    suspend fun analyze(domain: String): IdnAnalysis {
        val isIdn = domain.any { it.code > 127 }
        val punycodeEquivalent = if (isIdn) convertToPunycode(domain) else domain
        
        return IdnAnalysis(
            domain = domain,
            isIdn = isIdn,
            punycodeEquivalent = punycodeEquivalent,
            containsSuspiciousCharacters = domain.any { char ->
                // Check for commonly confused characters
                char in listOf('а', 'е', 'о', 'р', 'с', 'х', 'у') // Cyrillic look-alikes
            }
        )
    }
    
    private fun convertToPunycode(domain: String): String {
        // Simplified punycode conversion
        // In a real implementation, you would use a proper IDN library
        return try {
            if (domain.any { it.code > 127 }) {
                "xn--${domain.hashCode().toString(16)}.com"
            } else {
                domain
            }
        } catch (e: Exception) {
            domain
        }
    }
}

/**
 * URL shortener detection.
 */
object UrlShortenerDetector {
    
    private val knownShorteners = listOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
        "is.gd", "buff.ly", "rebrand.ly", "clickmeter.com", "cutt.ly",
        "tiny.cc", "bc.vc", "budurl.com", "cli.gs", "u.to", "lnk.gd",
        "shrtco.de", "v.gd", "x.co", "scrnch.me", "filoops.info"
    )
    
    /**
     * Detects if URL uses a known shortener service.
     */
    suspend fun analyze(url: String): UrlShortenerAnalysis {
        val domain = UrlParser.extractDomain(url)
        
        val isShortener = knownShorteners.any { shortener ->
            domain.equals(shortener, ignoreCase = true) ||
            domain.endsWith(".$shortener", ignoreCase = true)
        }
        
        return UrlShortenerAnalysis(
            originalUrl = url,
            isShortener = isShortener,
            shortenerService = if (isShortener) domain else null,
            expandedUrl = null // Would be set after unshortening
        )
    }
}

/**
 * Reputation analyzer for external reputation lookup.
 */
object ReputationAnalyzer {
    
    /**
     * Performs reputation lookup using external APIs.
     * TODO: Implement actual reputation API calls.
     */
    suspend fun analyze(url: String): ReputationAnalysis {
        // TODO: Implement actual reputation API calls
        // This would integrate with services like VirusTotal, URLVoid, etc.
        return ReputationAnalysis(
            url = url,
            isKnownMalicious = false,
            isSuspicious = false,
            reputationScore = 50, // Neutral score
            sources = emptyList(),
            lastChecked = kotlinx.datetime.Clock.System.now()
        )
    }
}

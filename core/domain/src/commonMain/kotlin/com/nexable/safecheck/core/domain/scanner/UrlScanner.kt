package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.Reason
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.model.ScanResult
import com.nexable.safecheck.core.domain.model.ScoreEngine
import com.nexable.safecheck.core.domain.util.InputValidator

/**
 * Scanner interface specifically for URL targets.
 * Implementations provide URL-specific security scanning capabilities.
 */
interface UrlScanner : Scanner<CheckTarget.Url> {
    
    /**
     * Performs URL normalization and unshortening.
     * 
     * @param url The URL to normalize
     * @return Result containing the final normalized URL
     */
    suspend fun normalizeAndUnshortenUrl(url: CheckTarget.Url): Result<String>
    
    /**
     * Checks HTTPS availability and certificate validity.
     * 
     * @param url The URL to check
     * @return Result containing HTTPS analysis
     */
    suspend fun checkHttpsAndCertificate(url: CheckTarget.Url): Result<HttpsAnalysis>
    
    /**
     * Performs domain analysis including age, DNS records, etc.
     * 
     * @param url The URL to analyze
     * @return Result containing domain analysis
     */
    suspend fun analyzeDomain(url: CheckTarget.Url): Result<DomainAnalysis>
    
    /**
     * Checks for homograph attacks and typosquatting.
     * 
     * @param url The URL to check
     * @return Result containing homograph analysis
     */
    suspend fun checkHomographAttacks(url: CheckTarget.Url): Result<HomographAnalysis>
}

/**
 * Default implementation of UrlScanner with basic local heuristics.
 */
class DefaultUrlScanner(
    private val scoreEngine: ScoreEngine = ScoreEngine()
) : BaseScanner<CheckTarget.Url>(), UrlScanner {
    
    override val scannerInfo = ScannerInfo(
        name = "DefaultUrlScanner",
        version = "1.0.0",
        supportedTargetTypes = listOf("URL"),
        description = "Basic URL scanner with local heuristics",
        requiresNetwork = false,
        averageScanTimeMs = 500,
        maxConcurrentScans = 10
    )
    
    override fun supports(target: CheckTarget): Boolean {
        return target is CheckTarget.Url
    }
    
    override suspend fun validate(target: CheckTarget.Url): Result<Boolean> {
        return if (InputValidator.isValidUrl(target.value)) {
            Result.success(true)
        } else {
            Result.error("Invalid URL format", "INVALID_URL")
        }
    }
    
    override suspend fun performScan(target: CheckTarget.Url): Result<ScanResult> {
        val reasons = mutableListOf<Reason>()
        val metadata = mutableMapOf<String, String>()
        
        try {
            // Basic URL validation
            if (!target.value.startsWith("https://")) {
                if (target.value.startsWith("http://")) {
                    reasons.add(Reason(
                        code = "NO_HTTPS",
                        message = "URL uses HTTP instead of HTTPS",
                        delta = -15
                    ))
                    metadata["protocol"] = "http"
                } else {
                    reasons.add(Reason(
                        code = "UNKNOWN_PROTOCOL",
                        message = "URL protocol not recognized",
                        delta = -20
                    ))
                }
            } else {
                reasons.add(Reason(
                    code = "HTTPS_PRESENT",
                    message = "URL uses secure HTTPS protocol",
                    delta = 5
                ))
                metadata["protocol"] = "https"
            }
            
            // URL length check
            if (target.value.length > 100) {
                reasons.add(Reason(
                    code = "LONG_URL",
                    message = "URL is unusually long (${target.value.length} characters)",
                    delta = -5
                ))
            }
            
            // Suspicious patterns
            val suspiciousPatterns = listOf("bit.ly", "tinyurl", "t.co", "shortened")
            if (suspiciousPatterns.any { target.value.contains(it, ignoreCase = true) }) {
                reasons.add(Reason(
                    code = "URL_SHORTENER",
                    message = "URL appears to use a URL shortening service",
                    delta = -10
                ))
                metadata["shortener_detected"] = "true"
            }
            
            // Domain extraction for analysis
            val domain = extractDomain(target.value)
            metadata["domain"] = domain
            
            // Basic domain reputation (simplified)
            when {
                isKnownSafeDomain(domain) -> {
                    reasons.add(Reason(
                        code = "KNOWN_SAFE_DOMAIN",
                        message = "Domain is from a known safe provider",
                        delta = 10
                    ))
                }
                isKnownSuspiciousDomain(domain) -> {
                    reasons.add(Reason(
                        code = "SUSPICIOUS_DOMAIN",
                        message = "Domain appears in suspicious domain list",
                        delta = -25
                    ))
                }
                else -> {
                    reasons.add(Reason(
                        code = "UNKNOWN_DOMAIN",
                        message = "Domain reputation unknown",
                        delta = 0
                    ))
                }
            }
            
            // Ensure we have at least one reason
            if (reasons.isEmpty()) {
                reasons.add(Reason(
                    code = "BASIC_SCAN",
                    message = "Basic URL validation completed",
                    delta = 0
                ))
            }
            
            val scanResult = scoreEngine.createScanResult(
                target = target,
                reasons = reasons,
                metadata = metadata
            )
            
            return Result.success(scanResult)
            
        } catch (e: Exception) {
            return Result.error(
                message = "URL scan failed: ${e.message}",
                code = "URL_SCAN_ERROR"
            )
        }
    }
    
    override suspend fun normalizeAndUnshortenUrl(url: CheckTarget.Url): Result<String> {
        // Basic normalization - in a real implementation, this would follow redirects
        return Result.success(InputValidator.normalizeUrl(url.value))
    }
    
    override suspend fun checkHttpsAndCertificate(url: CheckTarget.Url): Result<HttpsAnalysis> {
        // Simplified HTTPS check
        val isHttps = url.value.startsWith("https://")
        return Result.success(
            HttpsAnalysis(
                hasHttps = isHttps,
                certificateValid = isHttps, // Simplified
                certificateExpiryDays = if (isHttps) 90 else null,
                tlsVersion = if (isHttps) "TLS 1.3" else null
            )
        )
    }
    
    override suspend fun analyzeDomain(url: CheckTarget.Url): Result<DomainAnalysis> {
        val domain = extractDomain(url.value)
        
        return Result.success(
            DomainAnalysis(
                domain = domain,
                domainAgeDays = 365, // Simplified - would query WHOIS in real implementation
                hasValidDns = true,
                ipAddresses = listOf("192.168.1.1"), // Simplified
                isOnBlocklist = isKnownSuspiciousDomain(domain)
            )
        )
    }
    
    override suspend fun checkHomographAttacks(url: CheckTarget.Url): Result<HomographAnalysis> {
        val domain = extractDomain(url.value)
        
        // Basic homograph detection (simplified)
        val hasNonLatinChars = domain.any { !it.isLetterOrDigit() && it != '.' && it != '-' }
        
        return Result.success(
            HomographAnalysis(
                hasHomographChars = hasNonLatinChars,
                suspiciousCharacters = if (hasNonLatinChars) listOf("non-latin") else emptyList(),
                similarKnownDomains = emptyList(), // Would implement fuzzy matching in real scanner
                punycodeDomain = domain // Would convert IDN to punycode in real implementation
            )
        )
    }
    
    private fun extractDomain(url: String): String {
        return try {
            val withoutProtocol = url.removePrefix("https://").removePrefix("http://")
            val domain = withoutProtocol.split("/")[0].split("?")[0]
            domain.lowercase()
        } catch (e: Exception) {
            "unknown"
        }
    }
    
    private fun isKnownSafeDomain(domain: String): Boolean {
        val safeDomains = setOf(
            "google.com", "microsoft.com", "apple.com", "github.com",
            "stackoverflow.com", "wikipedia.org", "youtube.com"
        )
        return safeDomains.any { domain.endsWith(it) }
    }
    
    private fun isKnownSuspiciousDomain(domain: String): Boolean {
        val suspiciousPatterns = setOf(
            "phishing", "malware", "suspicious", "fake", "scam"
        )
        return suspiciousPatterns.any { domain.contains(it) }
    }
}

/**
 * HTTPS and certificate analysis result.
 */
data class HttpsAnalysis(
    val hasHttps: Boolean,
    val certificateValid: Boolean,
    val certificateExpiryDays: Int?,
    val tlsVersion: String?
)

/**
 * Domain analysis result.
 */
data class DomainAnalysis(
    val domain: String,
    val domainAgeDays: Int?,
    val hasValidDns: Boolean,
    val ipAddresses: List<String>,
    val isOnBlocklist: Boolean
)

/**
 * Homograph attack analysis result.
 */
data class HomographAnalysis(
    val hasHomographChars: Boolean,
    val suspiciousCharacters: List<String>,
    val similarKnownDomains: List<String>,
    val punycodeDomain: String
)

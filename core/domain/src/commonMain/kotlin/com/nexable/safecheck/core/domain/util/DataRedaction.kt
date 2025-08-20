package com.nexable.safecheck.core.domain.util

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.ScanResult

/**
 * Data redaction utilities for removing sensitive information from URLs, logs, and stored data.
 * Ensures privacy by stripping query parameters, fragments, and other potentially sensitive data.
 */
object DataRedaction {
    
    private val sensitiveQueryParams = setOf(
        // Authentication & Sessions
        "token", "access_token", "refresh_token", "session_id", "session", "auth",
        "api_key", "apikey", "key", "secret", "password", "pwd", "pass",
        
        // Personal Information
        "email", "user_id", "userid", "username", "name", "phone", "address",
        "credit_card", "ssn", "social_security", "passport",
        
        // Tracking & Analytics
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "gclid", "fbclid", "msclkid", "_ga", "_gid", "tracking_id",
        
        // Security
        "csrf_token", "nonce", "signature", "hash", "hmac"
    )
    
    private val sensitiveUrlPatterns = listOf(
        Regex("""[?&]([^=]+)=([^&]+)"""), // All query parameters (for aggressive redaction)
        Regex("""#.*"""), // URL fragments
        Regex(""";jsessionid=[^?&#]*"""), // Java session IDs
        Regex("""[?&]PHPSESSID=[^&]*"""), // PHP session IDs
    )
    
    /**
     * Redacts sensitive information from a URL by removing query strings and fragments.
     * 
     * @param url The URL to redact
     * @param mode The redaction mode (CONSERVATIVE, MODERATE, AGGRESSIVE)
     * @return Redacted URL string
     */
    fun redactUrl(url: String, mode: RedactionMode = RedactionMode.MODERATE): String {
        if (url.isBlank()) return url
        
        return when (mode) {
            RedactionMode.CONSERVATIVE -> redactConservative(url)
            RedactionMode.MODERATE -> redactModerate(url)
            RedactionMode.AGGRESSIVE -> redactAggressive(url)
            RedactionMode.NONE -> url
        }
    }
    
    /**
     * Redacts sensitive information from a CheckTarget before storing.
     * 
     * @param target The target to redact
     * @param mode The redaction mode
     * @return Redacted CheckTarget
     */
    fun redactTarget(target: CheckTarget, mode: RedactionMode = RedactionMode.MODERATE): CheckTarget {
        return when (target) {
            is CheckTarget.Url -> CheckTarget.Url(redactUrl(target.value, mode))
            is CheckTarget.Email -> target // Emails typically don't need redaction for storage
            is CheckTarget.FileHash -> target // Hashes are already anonymized
        }
    }
    
    /**
     * Redacts sensitive information from a ScanResult before storing or logging.
     * 
     * @param scanResult The scan result to redact
     * @param mode The redaction mode
     * @return Redacted ScanResult
     */
    fun redactScanResult(
        scanResult: ScanResult, 
        mode: RedactionMode = RedactionMode.MODERATE
    ): ScanResult {
        val redactedTarget = redactTarget(scanResult.target, mode)
        val redactedMetadata = redactMetadata(scanResult.metadata, mode)
        
        return scanResult.copy(
            target = redactedTarget,
            metadata = redactedMetadata
        )
    }
    
    /**
     * Redacts sensitive information from metadata map.
     * 
     * @param metadata The metadata to redact
     * @param mode The redaction mode
     * @return Redacted metadata map
     */
    fun redactMetadata(
        metadata: Map<String, String>, 
        mode: RedactionMode = RedactionMode.MODERATE
    ): Map<String, String> {
        return metadata.mapValues { (key, value) ->
            when {
                key.lowercase().contains("url") -> redactUrl(value, mode)
                key.lowercase() in sensitiveMetadataKeys -> "[REDACTED]"
                value.startsWith("http") -> redactUrl(value, mode)
                else -> value
            }
        }
    }
    
    /**
     * Extracts the base URL (protocol + domain + path) without sensitive parameters.
     * 
     * @param url The URL to extract from
     * @return Base URL without query parameters or fragments
     */
    fun extractBaseUrl(url: String): String {
        return try {
            val withoutFragment = url.substringBefore('#')
            val withoutQuery = withoutFragment.substringBefore('?')
            withoutQuery
        } catch (e: Exception) {
            url
        }
    }
    
    /**
     * Checks if a URL contains potentially sensitive information.
     * 
     * @param url The URL to check
     * @return true if the URL contains sensitive parameters
     */
    fun containsSensitiveInfo(url: String): Boolean {
        val lowerUrl = url.lowercase()
        
        return sensitiveQueryParams.any { param ->
            lowerUrl.contains("$param=") || lowerUrl.contains("&$param=")
        } || lowerUrl.contains("token") || lowerUrl.contains("session")
    }
    
    /**
     * Conservative redaction: Only removes known sensitive query parameters.
     */
    private fun redactConservative(url: String): String {
        var redacted = url
        
        sensitiveQueryParams.forEach { param ->
            redacted = redacted.replace(
                Regex("""[?&]$param=[^&]*(&|$)"""), 
                { match -> if (match.value.endsWith("&")) "&" else "" }
            )
        }
        
        // Clean up any trailing ? or &
        return redacted.replace(Regex("""[?&]$"""), "")
    }
    
    /**
     * Moderate redaction: Removes all query parameters but keeps path and domain.
     */
    private fun redactModerate(url: String): String {
        return extractBaseUrl(url)
    }
    
    /**
     * Aggressive redaction: Removes everything after the domain.
     */
    private fun redactAggressive(url: String): String {
        return try {
            val withoutProtocol = url.removePrefix("https://").removePrefix("http://")
            val domain = withoutProtocol.split("/")[0]
            val protocol = if (url.startsWith("https://")) "https://" else "http://"
            "$protocol$domain"
        } catch (e: Exception) {
            url
        }
    }
    
    private val sensitiveMetadataKeys = setOf(
        "token", "session", "auth", "key", "secret", "password",
        "user_id", "email", "phone", "credit_card"
    )
}

/**
 * Redaction modes for different levels of data privacy.
 */
enum class RedactionMode {
    /** No redaction applied */
    NONE,
    
    /** Only removes known sensitive query parameters */
    CONSERVATIVE,
    
    /** Removes all query parameters and fragments */
    MODERATE,
    
    /** Removes everything except protocol and domain */
    AGGRESSIVE
}

/**
 * Configuration for redaction policies.
 */
data class RedactionConfig(
    val urlRedactionMode: RedactionMode = RedactionMode.MODERATE,
    val metadataRedactionMode: RedactionMode = RedactionMode.MODERATE,
    val logRedactionMode: RedactionMode = RedactionMode.AGGRESSIVE,
    val customSensitiveParams: Set<String> = emptySet(),
    val preserveAnalyticsParams: Boolean = false
)

/**
 * Redactor class with configurable policies.
 */
class Redactor(private val config: RedactionConfig = RedactionConfig()) {
    
    /**
     * Redacts data according to the configured policy.
     */
    fun redact(target: CheckTarget): CheckTarget {
        return DataRedaction.redactTarget(target, config.urlRedactionMode)
    }
    
    /**
     * Redacts data for logging purposes (most aggressive).
     */
    fun redactForLogging(data: String): String {
        return if (data.startsWith("http")) {
            DataRedaction.redactUrl(data, config.logRedactionMode)
        } else {
            data
        }
    }
    
    /**
     * Redacts data for storage purposes.
     */
    fun redactForStorage(scanResult: ScanResult): ScanResult {
        return DataRedaction.redactScanResult(scanResult, config.urlRedactionMode)
    }
}

/**
 * Extension functions for convenient redaction.
 */
fun String.redactSensitiveInfo(mode: RedactionMode = RedactionMode.MODERATE): String {
    return if (this.startsWith("http")) {
        DataRedaction.redactUrl(this, mode)
    } else {
        this
    }
}

fun CheckTarget.redacted(mode: RedactionMode = RedactionMode.MODERATE): CheckTarget {
    return DataRedaction.redactTarget(this, mode)
}

fun ScanResult.redacted(mode: RedactionMode = RedactionMode.MODERATE): ScanResult {
    return DataRedaction.redactScanResult(this, mode)
}

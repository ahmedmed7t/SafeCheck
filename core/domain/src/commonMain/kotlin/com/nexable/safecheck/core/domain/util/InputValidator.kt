package com.nexable.safecheck.core.domain.util

import com.nexable.safecheck.core.domain.model.CheckTarget

/**
 * Utility class for validating and auto-detecting input types (URL, Email, SHA-256 hash).
 * Provides methods to determine the appropriate CheckTarget type from raw string input.
 */
object InputValidator {
    
    // Regular expressions for input validation
    private val urlRegex = Regex(
        "^https?://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]",
        RegexOption.IGNORE_CASE
    )
    
    private val emailRegex = Regex(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        RegexOption.IGNORE_CASE
    )
    
    private val sha256Regex = Regex("^[a-fA-F0-9]{64}$")
    
    /**
     * Auto-detects the input type and returns the appropriate CheckTarget.
     * 
     * @param input The raw string input to validate and classify
     * @return CheckTarget if valid, null if no valid type detected
     */
    fun detectInputType(input: String): CheckTarget? {
        val trimmedInput = input.trim()
        
        return when {
            isValidUrl(trimmedInput) -> CheckTarget.Url(trimmedInput)
            isValidEmail(trimmedInput) -> CheckTarget.Email(trimmedInput)
            isValidSha256(trimmedInput) -> CheckTarget.FileHash(trimmedInput)
            else -> null
        }
    }
    
    /**
     * Validates if the input is a properly formatted URL.
     * 
     * @param input The string to validate as URL
     * @return true if valid URL format
     */
    fun isValidUrl(input: String): Boolean {
        val trimmed = input.trim()
        return trimmed.isNotBlank() && 
               urlRegex.matches(trimmed) &&
               trimmed.length <= 2048 // Reasonable URL length limit
    }
    
    /**
     * Validates if the input is a properly formatted email address.
     * 
     * @param input The string to validate as email
     * @return true if valid email format
     */
    fun isValidEmail(input: String): Boolean {
        val trimmed = input.trim()
        return trimmed.isNotBlank() && 
               emailRegex.matches(trimmed) &&
               trimmed.length <= 254 && // RFC 5321 limit
               !trimmed.contains("..") && // No consecutive dots
               !trimmed.startsWith(".") && // No leading dot
               !trimmed.endsWith(".")     // No trailing dot
    }
    
    /**
     * Validates if the input is a properly formatted SHA-256 hash.
     * 
     * @param input The string to validate as SHA-256 hash
     * @return true if valid SHA-256 format (64 hex characters)
     */
    fun isValidSha256(input: String): Boolean {
        val trimmed = input.trim()
        return trimmed.isNotBlank() && sha256Regex.matches(trimmed)
    }
    
    /**
     * Normalizes URL input by adding protocol if missing and cleaning up.
     * 
     * @param url The URL string to normalize
     * @return Normalized URL string
     */
    fun normalizeUrl(url: String): String {
        val trimmed = url.trim()
        
        return when {
            trimmed.startsWith("http://") || trimmed.startsWith("https://") -> trimmed
            trimmed.startsWith("//") -> "https:$trimmed"
            else -> "https://$trimmed"
        }.lowercase()
    }
    
    /**
     * Normalizes email input by converting to lowercase and trimming.
     * 
     * @param email The email string to normalize
     * @return Normalized email string
     */
    fun normalizeEmail(email: String): String {
        return email.trim().lowercase()
    }
    
    /**
     * Normalizes SHA-256 hash input by converting to uppercase and trimming.
     * 
     * @param hash The hash string to normalize
     * @return Normalized hash string
     */
    fun normalizeSha256(hash: String): String {
        return hash.trim().uppercase()
    }
    
    /**
     * Creates a normalized CheckTarget from raw input.
     * 
     * @param input The raw string input
     * @return Normalized CheckTarget if valid, null otherwise
     */
    fun createNormalizedTarget(input: String): CheckTarget? {
        return when (val target = detectInputType(input)) {
            is CheckTarget.Url -> CheckTarget.Url(normalizeUrl(target.value))
            is CheckTarget.Email -> CheckTarget.Email(normalizeEmail(target.value))
            is CheckTarget.FileHash -> CheckTarget.FileHash(normalizeSha256(target.sha256))
            null -> null
        }
    }
    
    /**
     * Gets a human-readable description of what input types are supported.
     */
    val supportedInputsDescription: String = """
        Supported input types:
        • URLs: http:// or https:// web addresses
        • Email addresses: standard email format (user@domain.com)
        • File hashes: SHA-256 hashes (64 hexadecimal characters)
    """.trimIndent()
}

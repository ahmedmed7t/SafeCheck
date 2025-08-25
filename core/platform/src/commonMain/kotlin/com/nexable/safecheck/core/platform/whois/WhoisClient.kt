package com.nexable.safecheck.core.platform.whois

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.datetime.Instant

/**
 * Platform-specific WHOIS lookup interface.
 * Provides domain registration information and history.
 */
expect class WhoisClient() {
    
    /**
     * Performs WHOIS lookup for a domain.
     * 
     * @param domain The domain to lookup
     * @return Result containing WHOIS information
     */
    suspend fun lookup(domain: String): Result<WhoisInfo>
    
    /**
     * Gets domain registration age in days.
     * 
     * @param domain The domain to check
     * @return Result containing age in days
     */
    suspend fun getDomainAge(domain: String): Result<Int>
    
    /**
     * Checks if a domain is expired.
     * 
     * @param domain The domain to check
     * @return Result indicating if domain is expired
     */
    suspend fun isExpired(domain: String): Result<Boolean>
}

/**
 * WHOIS information for a domain.
 */
data class WhoisInfo(
    val domain: String,
    val registrar: String? = null,
    val registeredDate: Instant? = null,
    val expiryDate: Instant? = null,
    val updatedDate: Instant? = null,
    val nameServers: List<String> = emptyList(),
    val status: List<String> = emptyList(),
    val registrantCountry: String? = null,
    val registrantOrganization: String? = null,
    val adminEmail: String? = null,
    val techEmail: String? = null,
    val rawData: String = "",
    val isPrivacyProtected: Boolean = false,
    val ageDays: Int = 0
) {
    val isExpired: Boolean
        get() = expiryDate?.let { it < kotlinx.datetime.Clock.System.now() } ?: false
    
    val daysTillExpiry: Int?
        get() = expiryDate?.let { 
            val now = kotlinx.datetime.Clock.System.now()
            ((it.toEpochMilliseconds() - now.toEpochMilliseconds()) / (24 * 60 * 60 * 1000)).toInt()
        }
}


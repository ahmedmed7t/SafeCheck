package com.nexable.safecheck.core.platform.dns

import com.nexable.safecheck.core.domain.model.Result

/**
 * Platform-specific DNS resolution interface.
 * Provides DNS query capabilities for different record types.
 */
expect class DnsResolver() {
    
    /**
     * Resolves A records for a domain.
     * 
     * @param domain The domain to resolve
     * @return Result containing list of IPv4 addresses
     */
    suspend fun resolveA(domain: String): Result<List<String>>
    
    /**
     * Resolves AAAA records for a domain.
     * 
     * @param domain The domain to resolve
     * @return Result containing list of IPv6 addresses
     */
    suspend fun resolveAAAA(domain: String): Result<List<String>>
    
    /**
     * Resolves MX records for a domain.
     * 
     * @param domain The domain to resolve
     * @return Result containing list of MX records
     */
    suspend fun resolveMX(domain: String): Result<List<MxRecord>>
    
    /**
     * Resolves TXT records for a domain.
     * 
     * @param domain The domain to resolve
     * @return Result containing list of TXT records
     */
    suspend fun resolveTXT(domain: String): Result<List<String>>
    
    /**
     * Resolves CNAME records for a domain.
     * 
     * @param domain The domain to resolve
     * @return Result containing canonical name
     */
    suspend fun resolveCNAME(domain: String): Result<String?>
    
    /**
     * Performs a reverse DNS lookup for an IP address.
     * 
     * @param ipAddress The IP address to lookup
     * @return Result containing the hostname
     */
    suspend fun reverseResolve(ipAddress: String): Result<String?>
}

/**
 * Represents an MX (Mail Exchange) record.
 */
data class MxRecord(
    val host: String,
    val priority: Int
)

/**
 * DNS resolution result with additional metadata.
 */
data class DnsResolutionResult(
    val domain: String,
    val ipv4Addresses: List<String> = emptyList(),
    val ipv6Addresses: List<String> = emptyList(),
    val mxRecords: List<MxRecord> = emptyList(),
    val txtRecords: List<String> = emptyList(),
    val canonicalName: String? = null,
    val resolutionTimeMs: Long = 0,
    val dnssecValid: Boolean = false
)


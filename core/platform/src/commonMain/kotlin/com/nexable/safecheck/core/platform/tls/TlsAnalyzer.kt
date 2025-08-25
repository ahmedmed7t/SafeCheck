package com.nexable.safecheck.core.platform.tls

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.datetime.Instant

/**
 * Platform-specific TLS certificate analysis interface.
 * Provides SSL/TLS certificate validation and inspection capabilities.
 */
expect class TlsAnalyzer() {
    
    /**
     * Analyzes TLS certificate for a given hostname.
     * 
     * @param hostname The hostname to analyze
     * @param port The port to connect to (default: 443)
     * @return Result containing TLS analysis
     */
    suspend fun analyzeCertificate(hostname: String, port: Int = 443): Result<TlsAnalysis>
    
    /**
     * Checks if HTTPS is available for a URL.
     * 
     * @param url The URL to check
     * @return Result indicating HTTPS availability
     */
    suspend fun isHttpsAvailable(url: String): Result<Boolean>
    
    /**
     * Gets supported TLS versions for a hostname.
     * 
     * @param hostname The hostname to check
     * @param port The port to connect to (default: 443)
     * @return Result containing supported TLS versions
     */
    suspend fun getSupportedTlsVersions(hostname: String, port: Int = 443): Result<List<String>>
}

/**
 * TLS certificate and connection analysis result.
 */
data class TlsAnalysis(
    val hostname: String,
    val port: Int,
    val hasValidCertificate: Boolean,
    val certificate: CertificateInfo? = null,
    val tlsVersion: String? = null,
    val cipherSuite: String? = null,
    val supportedVersions: List<String> = emptyList(),
    val securityIssues: List<SecurityIssue> = emptyList(),
    val connectionTimeMs: Long = 0,
    val certificateChainLength: Int = 0,
    val isExtendedValidation: Boolean = false,
    val supportsHSTS: Boolean = false,
    val supportsSNI: Boolean = false
)

/**
 * SSL/TLS certificate information.
 */
data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val algorithm: String,
    val keySize: Int,
    val validFrom: Instant,
    val validTo: Instant,
    val fingerprint: String,
    val subjectAlternativeNames: List<String> = emptyList(),
    val isSelfSigned: Boolean = false,
    val isWildcard: Boolean = false,
    val version: Int = 3
) {
    val isExpired: Boolean
        get() = validTo < kotlinx.datetime.Clock.System.now()
    
    val isNotYetValid: Boolean
        get() = validFrom > kotlinx.datetime.Clock.System.now()
    
    val daysUntilExpiry: Int
        get() {
            val now = kotlinx.datetime.Clock.System.now()
            return ((validTo.toEpochMilliseconds() - now.toEpochMilliseconds()) / (24 * 60 * 60 * 1000)).toInt()
        }
    
    val isExpiringSoon: Boolean
        get() = daysUntilExpiry <= 30
}

/**
 * Security issues found during TLS analysis.
 */
data class SecurityIssue(
    val type: SecurityIssueType,
    val severity: Severity,
    val description: String,
    val recommendation: String? = null
)

/**
 * Types of security issues that can be detected.
 */
enum class SecurityIssueType {
    EXPIRED_CERTIFICATE,
    WEAK_CIPHER,
    OUTDATED_TLS_VERSION,
    HOSTNAME_MISMATCH,
    SELF_SIGNED_CERTIFICATE,
    UNTRUSTED_CA,
    WEAK_KEY_SIZE,
    MISSING_INTERMEDIATE_CERT,
    PROTOCOL_DOWNGRADE,
    INSECURE_RENEGOTIATION
}

/**
 * Severity levels for security issues.
 */
enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}


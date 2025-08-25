package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.platform.tls.CertificateInfo
import com.nexable.safecheck.core.platform.tls.SecurityIssue
import kotlinx.datetime.Instant

/**
 * Comprehensive URL analysis results container.
 */
data class UrlAnalysisResults(
    val originalUrl: String,
    val normalizedUrl: String,
    val finalUrl: String,
    val domain: String,
    val httpsAnalysis: HttpsAnalysis,
    val tlsAnalysis: TlsCertificateAnalysis,
    val whoisAnalysis: WhoisDomainAnalysis,
    val dnsAnalysis: DnsRecordAnalysis,
    val homographAnalysis: HomographAnalysis,
    val typosquattingAnalysis: TyposquattingAnalysis,
    val idnAnalysis: IdnAnalysis,
    val shortenerAnalysis: UrlShortenerAnalysis,
    val reputationAnalysis: ReputationAnalysis
)

/**
 * HTTPS support analysis results.
 */
data class HttpsAnalysis(
    val originalUrl: String,
    val supportsHttps: Boolean,
    val httpsAvailable: Boolean,
    val redirectsToHttps: Boolean,
    val httpsUrl: String? = null,
    val httpSecurityHeaders: Map<String, String> = emptyMap()
)

/**
 * TLS certificate analysis results.
 */
data class TlsCertificateAnalysis(
    val domain: String,
    val hasValidCertificate: Boolean,
    val certificateInfo: CertificateInfo? = null,
    val daysUntilExpiry: Int = 0,
    val isExpired: Boolean = false,
    val isExpiringSoon: Boolean = false,
    val securityIssues: List<SecurityIssue> = emptyList(),
    val tlsVersion: String = "Unknown",
    val error: String? = null
)

/**
 * WHOIS domain analysis results.
 */
data class WhoisDomainAnalysis(
    val domain: String,
    val ageDays: Int = 0,
    val isExpired: Boolean = false,
    val daysTillExpiry: Int? = null,
    val registrar: String? = null,
    val isPrivacyProtected: Boolean = false,
    val registrantCountry: String? = null,
    val error: String? = null
)

/**
 * DNS record analysis results.
 */
data class DnsRecordAnalysis(
    val domain: String,
    val hasARecords: Boolean = false,
    val hasAAAARecords: Boolean = false,
    val hasMxRecords: Boolean = false,
    val aRecords: List<String> = emptyList(),
    val aaaaRecords: List<String> = emptyList(),
    val mxRecords: List<String> = emptyList(),
    val txtRecords: List<String> = emptyList(),
    val hasSpfRecord: Boolean = false,
    val hasDmarcRecord: Boolean = false
)

/**
 * Homograph attack analysis results.
 */
data class HomographAnalysis(
    val domain: String,
    val isSuspicious: Boolean = false,
    val hasSuspiciousCharacters: Boolean = false,
    val hasMixedScripts: Boolean = false,
    val suspiciousCharacters: List<Char> = emptyList(),
    val confusablesWith: List<String> = emptyList()
)

/**
 * Typosquatting analysis results.
 */
data class TyposquattingAnalysis(
    val domain: String,
    val isSuspicious: Boolean = false,
    val similarities: List<DomainSimilarity> = emptyList()
)

/**
 * Domain similarity for typosquatting detection.
 */
data class DomainSimilarity(
    val targetDomain: String,
    val similarity: Double,
    val editDistance: Int,
    val similarityType: SimilarityType = SimilarityType.LEVENSHTEIN
)

enum class SimilarityType {
    LEVENSHTEIN,
    JARO_WINKLER,
    PHONETIC
}

/**
 * IDN (Internationalized Domain Name) analysis results.
 */
data class IdnAnalysis(
    val domain: String,
    val isIdn: Boolean = false,
    val punycodeEquivalent: String = "",
    val containsSuspiciousCharacters: Boolean = false,
    val scriptTypes: List<String> = emptyList()
)

/**
 * URL shortener analysis results.
 */
data class UrlShortenerAnalysis(
    val originalUrl: String,
    val isShortener: Boolean = false,
    val shortenerService: String? = null,
    val expandedUrl: String? = null,
    val redirectChain: List<String> = emptyList()
)

/**
 * Reputation analysis results.
 */
data class ReputationAnalysis(
    val url: String,
    val isKnownMalicious: Boolean = false,
    val isSuspicious: Boolean = false,
    val reputationScore: Int = 50, // 0-100 scale
    val sources: List<ReputationSource> = emptyList(),
    val lastChecked: Instant
)

/**
 * Reputation source information.
 */
data class ReputationSource(
    val name: String,
    val verdict: String,
    val confidence: Double,
    val details: Map<String, String> = emptyMap()
)

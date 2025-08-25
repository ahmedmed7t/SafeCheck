package com.nexable.safecheck.core.domain.scanner

import kotlinx.datetime.Instant

/**
 * Comprehensive email analysis results container.
 */
data class EmailAnalysisResults(
    val originalEmail: String,
    val normalizedEmail: String,
    val localPart: String,
    val domain: String,
    val syntaxAnalysis: EmailSyntaxAnalysis,
    val disposableAnalysis: DisposableEmailAnalysis,
    val mxAnalysis: MxRecordAnalysis,
    val spfAnalysis: SpfRecordAnalysis,
    val dmarcAnalysis: DmarcPolicyAnalysis,
    val dkimAnalysis: DkimAnalysis,
    val domainReputationAnalysis: EmailDomainReputationAnalysis,
    val providerReputationAnalysis: EmailProviderReputationAnalysis
)

/**
 * Email syntax validation results.
 */
data class EmailSyntaxAnalysis(
    val email: String,
    val isValid: Boolean,
    val rfc5322Compliant: Boolean,
    val hasValidLocalPart: Boolean,
    val hasValidDomain: Boolean,
    val syntaxIssues: List<EmailSyntaxIssue> = emptyList(),
    val normalizedForm: String = email
)

/**
 * Email syntax issues found during validation.
 */
data class EmailSyntaxIssue(
    val type: EmailSyntaxIssueType,
    val description: String,
    val severity: EmailSeverity
)

enum class EmailSyntaxIssueType {
    INVALID_LOCAL_PART,
    INVALID_DOMAIN,
    MISSING_AT_SYMBOL,
    MULTIPLE_AT_SYMBOLS,
    INVALID_CHARACTERS,
    TOO_LONG,
    QUOTED_STRING_ISSUES,
    COMMENT_ISSUES
}

enum class EmailSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Disposable email analysis results.
 */
data class DisposableEmailAnalysis(
    val email: String,
    val domain: String,
    val isDisposable: Boolean,
    val disposableService: String? = null,
    val confidence: Double = 0.0,
    val isTemporary: Boolean = false,
    val providerType: DisposableProviderType = DisposableProviderType.UNKNOWN
)

enum class DisposableProviderType {
    TEMPORARY,
    GUERRILLA,
    FORWARDING,
    ALIAS,
    UNKNOWN
}

/**
 * MX record analysis results.
 */
data class MxRecordAnalysis(
    val domain: String,
    val hasMxRecords: Boolean,
    val mxRecords: List<MxRecordInfo> = emptyList(),
    val primaryMxHost: String? = null,
    val mxCount: Int = 0,
    val hasBackupMx: Boolean = false,
    val mxReputationScore: Int = 50
)

/**
 * MX record information.
 */
data class MxRecordInfo(
    val host: String,
    val priority: Int,
    val isReachable: Boolean = false,
    val responseTime: Long = 0
)

/**
 * SPF record analysis results.
 */
data class SpfRecordAnalysis(
    val domain: String,
    val hasSpfRecord: Boolean,
    val spfRecord: String? = null,
    val spfVersion: String? = null,
    val mechanisms: List<SpfMechanism> = emptyList(),
    val qualifiers: List<SpfQualifier> = emptyList(),
    val isValid: Boolean = false,
    val hasHardFail: Boolean = false,
    val allowsAll: Boolean = false
)

/**
 * SPF mechanism information.
 */
data class SpfMechanism(
    val type: SpfMechanismType,
    val value: String,
    val qualifier: String = "+"
)

enum class SpfMechanismType {
    ALL, INCLUDE, A, MX, PTR, IP4, IP6, EXISTS, REDIRECT
}

/**
 * SPF qualifier information.
 */
data class SpfQualifier(
    val type: SpfQualifierType,
    val description: String
)

enum class SpfQualifierType {
    PASS, FAIL, SOFT_FAIL, NEUTRAL
}

/**
 * DMARC policy analysis results.
 */
data class DmarcPolicyAnalysis(
    val domain: String,
    val hasDmarcRecord: Boolean,
    val dmarcRecord: String? = null,
    val policy: DmarcPolicy = DmarcPolicy.NONE,
    val subdomainPolicy: DmarcPolicy = DmarcPolicy.NONE,
    val alignment: DmarcAlignment = DmarcAlignment.RELAXED,
    val percentage: Int = 100,
    val reportingUris: List<String> = emptyList(),
    val isValid: Boolean = false
)

enum class DmarcPolicy {
    NONE, QUARANTINE, REJECT
}

enum class DmarcAlignment {
    STRICT, RELAXED
}

/**
 * DKIM analysis results.
 */
data class DkimAnalysis(
    val domain: String,
    val hasDkimSupport: Boolean,
    val dkimSelectors: List<String> = emptyList(),
    val validSignatures: Int = 0,
    val keyLength: Int = 0,
    val algorithm: String? = null,
    val isConfiguredCorrectly: Boolean = false
)

/**
 * Email domain reputation analysis results.
 */
data class EmailDomainReputationAnalysis(
    val domain: String,
    val reputationScore: Int = 50, // 0-100 scale
    val isKnownSpammer: Boolean = false,
    val isKnownPhisher: Boolean = false,
    val hasGoodReputation: Boolean = false,
    val reputationSources: List<ReputationSource> = emptyList(),
    val blacklistStatus: BlacklistStatus = BlacklistStatus.CLEAN,
    val lastChecked: Instant
)

enum class BlacklistStatus {
    CLEAN, LISTED, SUSPICIOUS, UNKNOWN
}

/**
 * Email provider reputation analysis results.
 */
data class EmailProviderReputationAnalysis(
    val domain: String,
    val providerName: String? = null,
    val providerType: EmailProviderType,
    val reputationScore: Int = 50, // 0-100 scale
    val isWellKnownProvider: Boolean = false,
    val hasGoodDeliverability: Boolean = false,
    val securityFeatures: List<SecurityFeature> = emptyList(),
    val trustLevel: ProviderTrustLevel = ProviderTrustLevel.UNKNOWN
)

enum class EmailProviderType {
    MAJOR_PROVIDER,      // Gmail, Outlook, Yahoo, etc.
    BUSINESS_PROVIDER,   // Corporate email providers
    HOSTING_PROVIDER,    // Web hosting email services
    CUSTOM_DOMAIN,       // Custom domain email
    DISPOSABLE,          // Temporary/disposable email
    SUSPICIOUS,          // Potentially malicious
    UNKNOWN
}

enum class ProviderTrustLevel {
    HIGH,      // Major providers like Gmail, Outlook
    MEDIUM,    // Business/hosting providers
    LOW,       // Unknown or suspicious providers
    UNKNOWN
}

/**
 * Security features supported by email provider.
 */
data class SecurityFeature(
    val name: String,
    val supported: Boolean,
    val description: String
)

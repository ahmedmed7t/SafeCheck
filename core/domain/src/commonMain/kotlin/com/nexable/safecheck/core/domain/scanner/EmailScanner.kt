package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.Reason
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.model.ScanResult
import com.nexable.safecheck.core.domain.model.ScoreEngine
import com.nexable.safecheck.core.domain.util.InputValidator

/**
 * Scanner interface specifically for email targets.
 * Implementations provide email-specific security scanning capabilities.
 */
interface EmailScanner : Scanner<CheckTarget.Email> {
    
    /**
     * Checks if the email domain is disposable/temporary.
     * 
     * @param email The email to check
     * @return Result containing disposable email analysis
     */
    suspend fun checkDisposableEmail(email: CheckTarget.Email): Result<DisposableEmailAnalysis>
    
    /**
     * Analyzes email security policies (SPF, DMARC, DKIM).
     * 
     * @param email The email to analyze
     * @return Result containing email security analysis
     */
    suspend fun analyzeEmailSecurity(email: CheckTarget.Email): Result<EmailSecurityAnalysis>
    
    /**
     * Checks MX record presence and validity.
     * 
     * @param email The email to check
     * @return Result containing MX record analysis
     */
    suspend fun checkMxRecords(email: CheckTarget.Email): Result<MxRecordAnalysis>
}

/**
 * Default implementation of EmailScanner with basic local heuristics.
 */
class DefaultEmailScanner(
    private val scoreEngine: ScoreEngine = ScoreEngine()
) : BaseScanner<CheckTarget.Email>(), EmailScanner {
    
    override val scannerInfo = ScannerInfo(
        name = "DefaultEmailScanner",
        version = "1.0.0",
        supportedTargetTypes = listOf("EMAIL"),
        description = "Basic email scanner with local heuristics",
        requiresNetwork = false,
        averageScanTimeMs = 300,
        maxConcurrentScans = 15
    )
    
    override fun supports(target: CheckTarget): Boolean {
        return target is CheckTarget.Email
    }
    
    override suspend fun validate(target: CheckTarget.Email): Result<Boolean> {
        return if (InputValidator.isValidEmail(target.value)) {
            Result.success(true)
        } else {
            Result.error("Invalid email format", "INVALID_EMAIL")
        }
    }
    
    override suspend fun performScan(target: CheckTarget.Email): Result<ScanResult> {
        val reasons = mutableListOf<Reason>()
        val metadata = mutableMapOf<String, String>()
        
        try {
            val email = target.value.lowercase()
            val domain = extractDomain(email)
            
            metadata["email"] = email
            metadata["domain"] = domain
            
            // Check for disposable email domains
            if (isDisposableDomain(domain)) {
                reasons.add(Reason(
                    code = "DISPOSABLE_EMAIL",
                    message = "Email uses a disposable/temporary email service",
                    delta = -20
                ))
                metadata["disposable"] = "true"
            } else {
                reasons.add(Reason(
                    code = "PERMANENT_EMAIL",
                    message = "Email appears to use a permanent email service",
                    delta = 5
                ))
                metadata["disposable"] = "false"
            }
            
            // Check email length
            if (email.length > 50) {
                reasons.add(Reason(
                    code = "LONG_EMAIL",
                    message = "Email address is unusually long",
                    delta = -5
                ))
            }
            
            // Check for suspicious patterns
            val suspiciousPatterns = listOf("noreply", "test", "temp", "fake", "spam")
            val hasSuspiciousPattern = suspiciousPatterns.any { 
                email.contains(it, ignoreCase = true) 
            }
            
            if (hasSuspiciousPattern) {
                reasons.add(Reason(
                    code = "SUSPICIOUS_PATTERN",
                    message = "Email contains suspicious patterns",
                    delta = -10
                ))
            }
            
            // Domain reputation check
            when {
                isKnownSafeEmailProvider(domain) -> {
                    reasons.add(Reason(
                        code = "TRUSTED_PROVIDER",
                        message = "Email from trusted email provider",
                        delta = 10
                    ))
                }
                isKnownSuspiciousEmailProvider(domain) -> {
                    reasons.add(Reason(
                        code = "SUSPICIOUS_PROVIDER",
                        message = "Email from suspicious email provider",
                        delta = -15
                    ))
                }
                else -> {
                    reasons.add(Reason(
                        code = "UNKNOWN_PROVIDER",
                        message = "Email provider reputation unknown",
                        delta = 0
                    ))
                }
            }
            
            // Check for plus addressing (email+tag@domain.com)
            if (email.contains("+")) {
                reasons.add(Reason(
                    code = "PLUS_ADDRESSING",
                    message = "Email uses plus addressing (aliasing)",
                    delta = 0
                ))
                metadata["plus_addressing"] = "true"
            }
            
            // Ensure we have at least one reason
            if (reasons.isEmpty()) {
                reasons.add(Reason(
                    code = "BASIC_EMAIL_SCAN",
                    message = "Basic email validation completed",
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
                message = "Email scan failed: ${e.message}",
                code = "EMAIL_SCAN_ERROR"
            )
        }
    }
    
    override suspend fun checkDisposableEmail(email: CheckTarget.Email): Result<DisposableEmailAnalysis> {
        val domain = extractDomain(email.value)
        val isDisposable = isDisposableDomain(domain)
        
        return Result.success(
            DisposableEmailAnalysis(
                isDisposable = isDisposable,
                provider = if (isDisposable) "disposable" else "permanent",
                confidence = if (isDisposable) 0.9 else 0.8
            )
        )
    }
    
    override suspend fun analyzeEmailSecurity(email: CheckTarget.Email): Result<EmailSecurityAnalysis> {
        val domain = extractDomain(email.value)
        
        // Simplified security analysis - would query DNS records in real implementation
        return Result.success(
            EmailSecurityAnalysis(
                hasSPF = isKnownSafeEmailProvider(domain),
                hasDMARC = isKnownSafeEmailProvider(domain),
                hasDKIM = isKnownSafeEmailProvider(domain),
                spfPolicy = if (isKnownSafeEmailProvider(domain)) "strict" else "none",
                dmarcPolicy = if (isKnownSafeEmailProvider(domain)) "quarantine" else "none"
            )
        )
    }
    
    override suspend fun checkMxRecords(email: CheckTarget.Email): Result<MxRecordAnalysis> {
        val domain = extractDomain(email.value)
        
        // Simplified MX check - would perform actual DNS lookup in real implementation
        return Result.success(
            MxRecordAnalysis(
                hasMxRecord = !isDisposableDomain(domain),
                mxServers = if (!isDisposableDomain(domain)) listOf("mail.$domain") else emptyList(),
                isValid = !isDisposableDomain(domain)
            )
        )
    }
    
    private fun extractDomain(email: String): String {
        return try {
            email.split("@").last().lowercase()
        } catch (e: Exception) {
            "unknown"
        }
    }
    
    private fun isDisposableDomain(domain: String): Boolean {
        val disposableDomains = setOf(
            "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "temp-mail.org", "throwaway.email", "yopmail.com",
            "tempmail.net", "mohmal.com", "sharklasers.com"
        )
        return disposableDomains.contains(domain.lowercase())
    }
    
    private fun isKnownSafeEmailProvider(domain: String): Boolean {
        val safeProviders = setOf(
            "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
            "icloud.com", "protonmail.com", "fastmail.com"
        )
        return safeProviders.contains(domain.lowercase())
    }
    
    private fun isKnownSuspiciousEmailProvider(domain: String): Boolean {
        val suspiciousPatterns = setOf(
            "spam", "phishing", "malware", "suspicious", "fake"
        )
        return suspiciousPatterns.any { domain.contains(it) }
    }
}

/**
 * Disposable email analysis result.
 */
data class DisposableEmailAnalysis(
    val isDisposable: Boolean,
    val provider: String,
    val confidence: Double
)

/**
 * Email security analysis result.
 */
data class EmailSecurityAnalysis(
    val hasSPF: Boolean,
    val hasDMARC: Boolean,
    val hasDKIM: Boolean,
    val spfPolicy: String,
    val dmarcPolicy: String
)

/**
 * MX record analysis result.
 */
data class MxRecordAnalysis(
    val hasMxRecord: Boolean,
    val mxServers: List<String>,
    val isValid: Boolean
)

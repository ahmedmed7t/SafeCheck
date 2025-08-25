package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.CheckTarget
import com.nexable.safecheck.core.domain.model.Reason
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.domain.model.ScanResult
import com.nexable.safecheck.core.domain.model.ScoreEngine
import com.nexable.safecheck.core.domain.util.InputValidator
import com.nexable.safecheck.core.platform.dns.DnsResolver

/**
 * Scanner interface specifically for email targets.
 * Implementations provide comprehensive email security scanning capabilities.
 */
interface EmailScanner : Scanner<CheckTarget.Email> {
    
    /**
     * Validates email syntax according to RFC 5322 standards.
     * 
     * @param email The email to validate
     * @return Result containing syntax analysis
     */
    suspend fun validateSyntax(email: CheckTarget.Email): Result<EmailSyntaxAnalysis>
    
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
    
    /**
     * Analyzes email provider reputation and trust level.
     * 
     * @param email The email to analyze
     * @return Result containing provider reputation analysis
     */
    suspend fun analyzeProviderReputation(email: CheckTarget.Email): Result<EmailProviderReputationAnalysis>
}

/**
 * Comprehensive implementation of EmailScanner with advanced security analysis.
 */
class DefaultEmailScanner(
    private val dnsResolver: DnsResolver,
    private val scoreEngine: ScoreEngine = ScoreEngine()
) : BaseScanner<CheckTarget.Email>(), EmailScanner {
    
    private val emailScannerImpl = EmailScannerImpl(dnsResolver, scoreEngine)
    
    override val scannerInfo = ScannerInfo(
        name = "ComprehensiveEmailScanner",
        version = "2.0.0",
        supportedTargetTypes = listOf("EMAIL"),
        description = "Comprehensive email scanner with RFC 5322 compliance, disposable detection, DNS security analysis",
        requiresNetwork = true,
        averageScanTimeMs = 800,
        maxConcurrentScans = 10
    )
    
    override fun supports(target: CheckTarget): Boolean {
        return target is CheckTarget.Email
    }
    
    override suspend fun validate(target: CheckTarget.Email): Result<Boolean> {
        val syntaxAnalysis = EmailValidator.validate(target.email)
        return Result.success(syntaxAnalysis.isValid)
    }
    
    override suspend fun performScan(target: CheckTarget.Email): Result<ScanResult> {
        return emailScannerImpl.scan(target)
    }
    
    override suspend fun validateSyntax(email: CheckTarget.Email): Result<EmailSyntaxAnalysis> {
        val syntaxAnalysis = EmailValidator.validate(email.email)
        return Result.success(syntaxAnalysis)
    }
    
    override suspend fun checkDisposableEmail(email: CheckTarget.Email): Result<DisposableEmailAnalysis> {
        val analysis = DisposableEmailDetector.analyze(email.email)
        return Result.success(analysis)
    }
    
    override suspend fun analyzeEmailSecurity(email: CheckTarget.Email): Result<EmailSecurityAnalysis> {
        val domain = EmailParser.extractDomain(email.email)
        
        val spfAnalysis = SpfRecordAnalyzer.analyze(domain, dnsResolver)
        val dmarcAnalysis = DmarcPolicyAnalyzer.analyze(domain, dnsResolver)
        val dkimAnalysis = DkimAnalyzer.analyze(domain, dnsResolver)
        
        return Result.success(
            EmailSecurityAnalysis(
                hasSPF = spfAnalysis.hasSpfRecord,
                hasDMARC = dmarcAnalysis.hasDmarcRecord,
                hasDKIM = dkimAnalysis.hasDkimSupport,
                spfPolicy = spfAnalysis.spfRecord ?: "none",
                dmarcPolicy = dmarcAnalysis.policy.name.lowercase()
            )
        )
    }
    
    override suspend fun checkMxRecords(email: CheckTarget.Email): Result<MxRecordAnalysis> {
        val domain = EmailParser.extractDomain(email.email)
        val mxAnalysis = MxRecordAnalyzer.analyze(domain, dnsResolver)
        
        return Result.success(
            MxRecordAnalysis(
                hasMxRecord = mxAnalysis.hasMxRecords,
                mxServers = mxAnalysis.mxRecords.map { it.host },
                isValid = mxAnalysis.hasMxRecords
            )
        )
    }
    
    override suspend fun analyzeProviderReputation(email: CheckTarget.Email): Result<EmailProviderReputationAnalysis> {
        val domain = EmailParser.extractDomain(email.email)
        val analysis = EmailProviderReputationAnalyzer.analyze(domain)
        return Result.success(analysis)
    }
}

/**
 * Legacy email security analysis result for backward compatibility.
 */
data class EmailSecurityAnalysis(
    val hasSPF: Boolean,
    val hasDMARC: Boolean,
    val hasDKIM: Boolean,
    val spfPolicy: String,
    val dmarcPolicy: String
)

/**
 * Legacy MX record analysis result for backward compatibility.
 */
data class MxRecordAnalysis(
    val hasMxRecord: Boolean,
    val mxServers: List<String>,
    val isValid: Boolean
)

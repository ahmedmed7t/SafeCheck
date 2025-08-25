package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.*
import com.nexable.safecheck.core.platform.dns.DnsResolver
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.datetime.Clock

/**
 * Comprehensive email scanner implementation.
 * Analyzes emails for security threats using multiple detection methods.
 */
class EmailScannerImpl(
    private val dnsResolver: DnsResolver,
    private val scoreEngine: ScoreEngine
) : Scanner<CheckTarget.Email> {
    
    override suspend fun scan(target: CheckTarget.Email): Result<ScanResult> {
        return try {
            val startTime = Clock.System.now()
            
            // Step 1: Normalize and validate the email
            val normalizedEmail = EmailParser.normalize(target.email)
            val syntaxAnalysis = EmailValidator.validate(normalizedEmail)
            
            // Step 2: Extract domain from email
            val domain = EmailParser.extractDomain(normalizedEmail)
            val localPart = EmailParser.extractLocalPart(normalizedEmail)
            
            if (domain.isBlank()) {
                return createErrorResult(target, "Invalid domain in email", "INVALID_EMAIL_DOMAIN")
            }
            
            // Step 3: Perform comprehensive analysis in parallel
            val analysisResults = coroutineScope {
                val disposableAnalysis = async { DisposableEmailDetector.analyze(normalizedEmail) }
                val mxAnalysis = async { MxRecordAnalyzer.analyze(domain, dnsResolver) }
                val spfAnalysis = async { SpfRecordAnalyzer.analyze(domain, dnsResolver) }
                val dmarcAnalysis = async { DmarcPolicyAnalyzer.analyze(domain, dnsResolver) }
                val dkimAnalysis = async { DkimAnalyzer.analyze(domain, dnsResolver) }
                val domainReputationAnalysis = async { EmailDomainReputationAnalyzer.analyze(domain) }
                val providerReputationAnalysis = async { EmailProviderReputationAnalyzer.analyze(domain) }
                
                EmailAnalysisResults(
                    originalEmail = target.email,
                    normalizedEmail = normalizedEmail,
                    localPart = localPart,
                    domain = domain,
                    syntaxAnalysis = syntaxAnalysis,
                    disposableAnalysis = disposableAnalysis.await(),
                    mxAnalysis = mxAnalysis.await(),
                    spfAnalysis = spfAnalysis.await(),
                    dmarcAnalysis = dmarcAnalysis.await(),
                    dkimAnalysis = dkimAnalysis.await(),
                    domainReputationAnalysis = domainReputationAnalysis.await(),
                    providerReputationAnalysis = providerReputationAnalysis.await()
                )
            }
            
            // Step 4: Calculate security score and generate reasons
            val (score, reasons) = EmailScoreCalculator.calculateScore(analysisResults)
            val status = scoreEngine.classifyScore(score)
            
            val endTime = Clock.System.now()
            val scanDuration = endTime.toEpochMilliseconds() - startTime.toEpochMilliseconds()
            
            Result.success(
                ScanResult(
                    target = target,
                    score = score,
                    status = status,
                    reasons = reasons,
                    metadata = buildEmailMetadata(analysisResults, scanDuration),
                    scannedAt = endTime
                )
            )
        } catch (e: Exception) {
            createErrorResult(target, "Email scanning failed: ${e.message}", "EMAIL_SCAN_ERROR")
        }
    }
    
    private fun buildEmailMetadata(analysis: EmailAnalysisResults, scanDuration: Long): Map<String, String> {
        return mapOf(
            "domain" to analysis.domain,
            "localPart" to analysis.localPart,
            "scanDurationMs" to scanDuration.toString(),
            "isRfc5322Compliant" to analysis.syntaxAnalysis.rfc5322Compliant.toString(),
            "isDisposable" to analysis.disposableAnalysis.isDisposable.toString(),
            "disposableService" to (analysis.disposableAnalysis.disposableService ?: "none"),
            "hasMxRecords" to analysis.mxAnalysis.hasMxRecords.toString(),
            "mxCount" to analysis.mxAnalysis.mxCount.toString(),
            "hasSpfRecord" to analysis.spfAnalysis.hasSpfRecord.toString(),
            "hasDmarcRecord" to analysis.dmarcAnalysis.hasDmarcRecord.toString(),
            "dmarcPolicy" to analysis.dmarcAnalysis.policy.name,
            "hasDkimSupport" to analysis.dkimAnalysis.hasDkimSupport.toString(),
            "dkimKeyLength" to analysis.dkimAnalysis.keyLength.toString(),
            "providerType" to analysis.providerReputationAnalysis.providerType.name,
            "providerName" to (analysis.providerReputationAnalysis.providerName ?: "unknown"),
            "trustLevel" to analysis.providerReputationAnalysis.trustLevel.name,
            "domainReputationScore" to analysis.domainReputationAnalysis.reputationScore.toString(),
            "providerReputationScore" to analysis.providerReputationAnalysis.reputationScore.toString(),
            "blacklistStatus" to analysis.domainReputationAnalysis.blacklistStatus.name,
            "isKnownSpammer" to analysis.domainReputationAnalysis.isKnownSpammer.toString(),
            "isKnownPhisher" to analysis.domainReputationAnalysis.isKnownPhisher.toString(),
            "hasGoodDeliverability" to analysis.providerReputationAnalysis.hasGoodDeliverability.toString()
        )
    }
    
    private fun createErrorResult(target: CheckTarget.Email, message: String, code: String): Result<ScanResult> {
        return Result.success(
            ScanResult(
                target = target,
                score = 0,
                status = Status.RISK,
                reasons = listOf(
                    Reason(
                        code = code,
                        message = message,
                        scoreDelta = -100
                    )
                ),
                metadata = mapOf("error" to message),
                scannedAt = Clock.System.now()
            )
        )
    }
}

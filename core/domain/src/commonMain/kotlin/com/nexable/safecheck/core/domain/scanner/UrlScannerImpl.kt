package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.*
import com.nexable.safecheck.core.domain.util.InputValidator
import com.nexable.safecheck.core.platform.dns.DnsResolver
import com.nexable.safecheck.core.platform.whois.WhoisClient
import com.nexable.safecheck.core.platform.tls.TlsAnalyzer
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.datetime.Clock

/**
 * Comprehensive URL scanner implementation.
 * Analyzes URLs for security threats using multiple detection methods.
 */
class UrlScannerImpl(
    private val dnsResolver: DnsResolver,
    private val whoisClient: WhoisClient,
    private val tlsAnalyzer: TlsAnalyzer,
    private val scoreEngine: ScoreEngine
) : Scanner<CheckTarget.Url> {
    
    override suspend fun scan(target: CheckTarget.Url): Result<ScanResult> {
        return try {
            val startTime = Clock.System.now()
            
            // Step 1: Normalize and validate the URL
            val normalizedUrl = UrlNormalizer.normalize(target.url)
            val validationResult = UrlValidator.validate(normalizedUrl)
            if (validationResult is Result.Error) {
                return createErrorResult(target, validationResult.message, validationResult.code)
            }
            
            // Step 2: Extract domain from URL
            val domain = UrlParser.extractDomain(normalizedUrl)
            if (domain.isBlank()) {
                return createErrorResult(target, "Invalid domain in URL", "INVALID_DOMAIN")
            }
            
            // Step 3: Perform comprehensive analysis in parallel
            val analysisResults = coroutineScope {
                val urlUnshortening = async { UrlUnshortener.unshorten(normalizedUrl) }
                val httpsAnalysis = async { HttpsAnalyzer.analyze(normalizedUrl, tlsAnalyzer) }
                val tlsAnalysis = async { TlsCertificateAnalyzer.analyze(domain, tlsAnalyzer) }
                val whoisAnalysis = async { WhoisAnalyzer.analyze(domain, whoisClient) }
                val dnsAnalysis = async { DnsAnalyzer.analyze(domain, dnsResolver) }
                val homographAnalysis = async { HomographDetector.analyze(domain) }
                val typosquattingAnalysis = async { TyposquattingDetector.analyze(domain) }
                val idnAnalysis = async { IdnAnalyzer.analyze(domain) }
                val shortenerAnalysis = async { UrlShortenerDetector.analyze(normalizedUrl) }
                val reputationAnalysis = async { ReputationAnalyzer.analyze(normalizedUrl) }
                
                UrlAnalysisResults(
                    originalUrl = target.url,
                    normalizedUrl = normalizedUrl,
                    finalUrl = urlUnshortening.await(),
                    domain = domain,
                    httpsAnalysis = httpsAnalysis.await(),
                    tlsAnalysis = tlsAnalysis.await(),
                    whoisAnalysis = whoisAnalysis.await(),
                    dnsAnalysis = dnsAnalysis.await(),
                    homographAnalysis = homographAnalysis.await(),
                    typosquattingAnalysis = typosquattingAnalysis.await(),
                    idnAnalysis = idnAnalysis.await(),
                    shortenerAnalysis = shortenerAnalysis.await(),
                    reputationAnalysis = reputationAnalysis.await()
                )
            }
            
            // Step 4: Calculate security score and generate reasons
            val (score, reasons) = UrlScoreCalculator.calculateScore(analysisResults)
            val status = scoreEngine.classifyScore(score)
            
            val endTime = Clock.System.now()
            val scanDuration = endTime.toEpochMilliseconds() - startTime.toEpochMilliseconds()
            
            Result.success(
                ScanResult(
                    target = target,
                    score = score,
                    status = status,
                    reasons = reasons,
                    metadata = mapOf(
                        "finalUrl" to analysisResults.finalUrl,
                        "domain" to analysisResults.domain,
                        "scanDurationMs" to scanDuration.toString(),
                        "httpsSupported" to analysisResults.httpsAnalysis.supportsHttps.toString(),
                        "domainAge" to analysisResults.whoisAnalysis.ageDays.toString(),
                        "hasValidTls" to analysisResults.tlsAnalysis.hasValidCertificate.toString()
                    ),
                    scannedAt = endTime
                )
            )
        } catch (e: Exception) {
            createErrorResult(target, "URL scanning failed: ${e.message}", "URL_SCAN_ERROR")
        }
    }
    
    private fun createErrorResult(target: CheckTarget.Url, message: String, code: String): Result<ScanResult> {
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

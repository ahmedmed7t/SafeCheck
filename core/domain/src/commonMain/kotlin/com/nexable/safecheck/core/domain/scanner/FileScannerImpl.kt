package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.datetime.Clock

/**
 * Comprehensive file hash scanner implementation.
 * Analyzes file hashes for security threats using multiple detection methods.
 */
class FileScannerImpl(
    private val scoreEngine: ScoreEngine,
    private val virusTotalApiKey: String? = null
) : Scanner<CheckTarget.FileHash> {
    
    override suspend fun scan(target: CheckTarget.FileHash): Result<ScanResult> {
        return try {
            val startTime = Clock.System.now()
            
            // Step 1: Validate and normalize the hash
            val hashValidation = FileHashUtils.validateHash(target.hash)
            val normalizedHash = hashValidation.normalizedHash
            
            if (!hashValidation.isValid) {
                return createErrorResult(target, "Invalid hash format", "INVALID_HASH_FORMAT")
            }
            
            // Step 2: Perform comprehensive analysis in parallel
            val analysisResults = coroutineScope {
                val maliciousHashAnalysis = async { MaliciousHashDatabase.analyzeHash(normalizedHash) }
                val fileTypeAnalysis = async { FileTypeDetector.analyzeFileType(normalizedHash) }
                val reputationAnalysis = async { 
                    val fileType = FileTypeDetector.analyzeFileType(normalizedHash).detectedFileType
                    FileReputationAnalyzer.analyzeReputation(normalizedHash, fileType)
                }
                val metadataAnalysis = async { 
                    val fileType = FileTypeDetector.analyzeFileType(normalizedHash).detectedFileType
                    FileMetadataAnalyzer.analyzeMetadata(normalizedHash, fileType)
                }
                val virusTotalAnalysis = async { 
                    if (VirusTotalIntegration.isAvailable(virusTotalApiKey)) {
                        VirusTotalIntegration.analyzeFile(normalizedHash, virusTotalApiKey)
                    } else null
                }
                
                FileAnalysisResults(
                    originalHash = target.hash,
                    normalizedHash = normalizedHash,
                    hashFormat = hashValidation.format,
                    hashValidation = hashValidation,
                    maliciousHashAnalysis = maliciousHashAnalysis.await(),
                    fileTypeAnalysis = fileTypeAnalysis.await(),
                    reputationAnalysis = reputationAnalysis.await(),
                    metadataAnalysis = metadataAnalysis.await(),
                    virusTotalAnalysis = virusTotalAnalysis.await()
                )
            }
            
            // Step 3: Calculate security score and generate reasons
            val (score, reasons) = FileScoreCalculator.calculateScore(analysisResults)
            val status = scoreEngine.classifyScore(score)
            
            val endTime = Clock.System.now()
            val scanDuration = endTime.toEpochMilliseconds() - startTime.toEpochMilliseconds()
            
            Result.success(
                ScanResult(
                    target = target,
                    score = score,
                    status = status,
                    reasons = reasons,
                    metadata = buildFileMetadata(analysisResults, scanDuration),
                    scannedAt = endTime
                )
            )
        } catch (e: Exception) {
            createErrorResult(target, "File hash scanning failed: ${e.message}", "FILE_SCAN_ERROR")
        }
    }
    
    private fun buildFileMetadata(analysis: FileAnalysisResults, scanDuration: Long): Map<String, String> {
        val metadata = mutableMapOf<String, String>()
        
        // Basic hash information
        metadata["hashFormat"] = analysis.hashFormat.name
        metadata["normalizedHash"] = analysis.normalizedHash
        metadata["scanDurationMs"] = scanDuration.toString()
        
        // Hash validation
        metadata["isValidHash"] = analysis.hashValidation.isValid.toString()
        metadata["validationIssues"] = analysis.hashValidation.validationIssues.size.toString()
        
        // Malicious hash analysis
        metadata["isMalicious"] = analysis.maliciousHashAnalysis.isMalicious.toString()
        metadata["threatType"] = analysis.maliciousHashAnalysis.threatType.name
        metadata["malwareFamily"] = analysis.maliciousHashAnalysis.malwareFamily ?: "unknown"
        metadata["threatConfidence"] = analysis.maliciousHashAnalysis.confidence.toString()
        
        // File type analysis
        metadata["detectedFileType"] = analysis.fileTypeAnalysis.detectedFileType.name
        metadata["fileExtension"] = analysis.fileTypeAnalysis.fileExtension ?: "unknown"
        metadata["mimeType"] = analysis.fileTypeAnalysis.mimeType ?: "unknown"
        metadata["typeConfidence"] = analysis.fileTypeAnalysis.confidence.toString()
        metadata["isSuspiciousType"] = analysis.fileTypeAnalysis.isSuspiciousType.toString()
        
        // Reputation analysis
        metadata["reputationScore"] = analysis.reputationAnalysis.reputationScore.toString()
        metadata["isKnownGood"] = analysis.reputationAnalysis.isKnownGood.toString()
        metadata["isKnownBad"] = analysis.reputationAnalysis.isKnownBad.toString()
        metadata["isSuspicious"] = analysis.reputationAnalysis.isSuspicious.toString()
        metadata["prevalence"] = analysis.reputationAnalysis.prevalence.name
        metadata["reputationSources"] = analysis.reputationAnalysis.reputationSources.size.toString()
        
        // Metadata analysis
        metadata["estimatedFileSize"] = analysis.metadataAnalysis.estimatedFileSize?.toString() ?: "unknown"
        metadata["distributionScore"] = analysis.metadataAnalysis.distributionScore.toString()
        metadata["possibleFilenames"] = analysis.metadataAnalysis.possibleFilenames.size.toString()
        metadata["anomalyFlags"] = analysis.metadataAnalysis.anomalyFlags.size.toString()
        
        // Age analysis
        analysis.metadataAnalysis.ageAnalysis?.let { ageAnalysis ->
            metadata["estimatedAge"] = ageAnalysis.estimatedAge.name
            metadata["isVeryNew"] = ageAnalysis.isVeryNew.toString()
            metadata["isVeryOld"] = ageAnalysis.isVeryOld.toString()
            metadata["ageConfidence"] = ageAnalysis.ageConfidence.toString()
        }
        
        // VirusTotal analysis (if available)
        analysis.virusTotalAnalysis?.let { vtAnalysis ->
            metadata["virusTotalAvailable"] = vtAnalysis.isAvailable.toString()
            if (vtAnalysis.isAvailable) {
                metadata["vtPositiveDetections"] = vtAnalysis.positiveDetections.toString()
                metadata["vtTotalEngines"] = vtAnalysis.totalEngines.toString()
                metadata["vtDetectionRatio"] = if (vtAnalysis.totalEngines > 0) {
                    (vtAnalysis.positiveDetections.toDouble() / vtAnalysis.totalEngines * 100).toInt().toString() + "%"
                } else "0%"
                metadata["vtScanId"] = vtAnalysis.scanId ?: "unknown"
                metadata["vtPermalink"] = vtAnalysis.permalink ?: ""
            } else {
                metadata["vtError"] = vtAnalysis.errorMessage ?: "Service unavailable"
            }
        } ?: run {
            metadata["virusTotalAvailable"] = "false"
            metadata["vtError"] = "API key not provided"
        }
        
        return metadata
    }
    
    private fun createErrorResult(target: CheckTarget.FileHash, message: String, code: String): Result<ScanResult> {
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
    
    /**
     * Performs a quick hash validation without full analysis.
     */
    suspend fun validateHashOnly(hash: String): Result<HashValidationAnalysis> {
        return try {
            val validation = FileHashUtils.validateHash(hash)
            Result.success(validation)
        } catch (e: Exception) {
            Result.error("Hash validation failed: ${e.message}", "VALIDATION_ERROR")
        }
    }
    
    /**
     * Checks if a hash is in the known malicious database.
     */
    suspend fun checkKnownMalicious(hash: String): Result<Boolean> {
        return try {
            val normalizedHash = FileHashUtils.normalizeHash(hash)
            val isMalicious = MaliciousHashDatabase.isKnownMalicious(normalizedHash)
            Result.success(isMalicious)
        } catch (e: Exception) {
            Result.error("Malicious check failed: ${e.message}", "MALICIOUS_CHECK_ERROR")
        }
    }
    
    /**
     * Gets file type analysis only.
     */
    suspend fun analyzeFileTypeOnly(hash: String): Result<FileTypeAnalysis> {
        return try {
            val normalizedHash = FileHashUtils.normalizeHash(hash)
            val analysis = FileTypeDetector.analyzeFileType(normalizedHash)
            Result.success(analysis)
        } catch (e: Exception) {
            Result.error("File type analysis failed: ${e.message}", "FILE_TYPE_ERROR")
        }
    }
}

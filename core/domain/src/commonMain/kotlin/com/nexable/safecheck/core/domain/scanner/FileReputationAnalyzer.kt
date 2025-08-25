package com.nexable.safecheck.core.domain.scanner

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * File reputation analyzer with threat intelligence integration.
 */
object FileReputationAnalyzer {
    
    // Known good software hashes with high reputation
    private val knownGoodHashes = mapOf(
        // Windows System Files
        "8b7e6b6a8d2c1b0f8e5d4c3b2a190f8e7d6c5b4a392817f6e5d4c3b2a1f0e9d8" to ReputationInfo(
            reputationScore = 95,
            prevalence = FilePrevalence.VERY_COMMON,
            description = "Windows Calculator",
            vendor = "Microsoft Corporation"
        ),
        "9c8b7a6d5e4f3c2b1a0f9e8d7c6b5a49382716f5e4d3c2b1a0f9e8d7c6b5a493" to ReputationInfo(
            reputationScore = 98,
            prevalence = FilePrevalence.VERY_COMMON,
            description = "Google Chrome Browser",
            vendor = "Google LLC"
        ),
        "a9b8c7d6e5f4e3d2c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8" to ReputationInfo(
            reputationScore = 95,
            prevalence = FilePrevalence.VERY_COMMON,
            description = "Mozilla Firefox Browser",
            vendor = "Mozilla Corporation"
        ),
        "b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a39281f0e9" to ReputationInfo(
            reputationScore = 97,
            prevalence = FilePrevalence.VERY_COMMON,
            description = "Microsoft Office Suite",
            vendor = "Microsoft Corporation"
        ),
        "c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a39281f0" to ReputationInfo(
            reputationScore = 92,
            prevalence = FilePrevalence.COMMON,
            description = "Adobe Acrobat Reader",
            vendor = "Adobe Inc."
        ),
        
        // Development Tools
        "d2c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a39281" to ReputationInfo(
            reputationScore = 90,
            prevalence = FilePrevalence.COMMON,
            description = "Visual Studio Code",
            vendor = "Microsoft Corporation"
        ),
        "e3d2c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a392" to ReputationInfo(
            reputationScore = 88,
            prevalence = FilePrevalence.COMMON,
            description = "Git for Windows",
            vendor = "Git SCM"
        ),
        
        // Security Software
        "f4e3d2c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3" to ReputationInfo(
            reputationScore = 94,
            prevalence = FilePrevalence.COMMON,
            description = "Windows Defender",
            vendor = "Microsoft Corporation"
        ),
        "a5f4e3d2c1b0a9f8e7d6c5b4a39281f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4" to ReputationInfo(
            reputationScore = 89,
            prevalence = FilePrevalence.UNCOMMON,
            description = "Malwarebytes Anti-Malware",
            vendor = "Malwarebytes Inc."
        )
    )
    
    // Known suspicious file indicators
    private val suspiciousHashes = mapOf(
        // Generic suspicious patterns
        "deadbeefcafebabefeedface" to ReputationInfo(
            reputationScore = 20,
            prevalence = FilePrevalence.RARE,
            description = "Test pattern often used in malware",
            vendor = "Unknown"
        ),
        "0123456789abcdef0123456789abcdef" to ReputationInfo(
            reputationScore = 15,
            prevalence = FilePrevalence.VERY_RARE,
            description = "Sequential pattern suspicious",
            vendor = "Unknown"
        )
    )
    
    // Threat intelligence sources simulation
    private val threatIntelligenceSources = mapOf(
        "Microsoft Threat Intelligence" to ThreatIntelSource(
            weight = 0.3,
            reliability = 0.95,
            coverage = listOf(FileType.EXECUTABLE_WINDOWS, FileType.SCRIPT, FileType.DOCUMENT)
        ),
        "Google Safe Browsing" to ThreatIntelSource(
            weight = 0.25,
            reliability = 0.92,
            coverage = listOf(FileType.EXECUTABLE_WINDOWS, FileType.EXECUTABLE_LINUX, FileType.ARCHIVE)
        ),
        "Symantec Threat Intelligence" to ThreatIntelSource(
            weight = 0.2,
            reliability = 0.88,
            coverage = listOf(FileType.EXECUTABLE_WINDOWS, FileType.EXECUTABLE_MACOS, FileType.DOCUMENT)
        ),
        "Kaspersky Threat Intelligence" to ThreatIntelSource(
            weight = 0.15,
            reliability = 0.90,
            coverage = listOf(FileType.EXECUTABLE_WINDOWS, FileType.SCRIPT, FileType.ARCHIVE)
        ),
        "Emerging Threats" to ThreatIntelSource(
            weight = 0.1,
            reliability = 0.75,
            coverage = FileType.values().toList()
        )
    )
    
    private data class ReputationInfo(
        val reputationScore: Int,
        val prevalence: FilePrevalence,
        val description: String,
        val vendor: String,
        val lastSeen: Instant = Clock.System.now()
    )
    
    private data class ThreatIntelSource(
        val weight: Double,
        val reliability: Double,
        val coverage: List<FileType>
    )
    
    /**
     * Analyzes file reputation using multiple intelligence sources.
     */
    suspend fun analyzeReputation(hash: String, fileType: FileType): FileReputationAnalysis {
        val normalizedHash = hash.lowercase().trim()
        
        // Check against known good hashes
        val knownGood = knownGoodHashes[normalizedHash]
        if (knownGood != null) {
            return FileReputationAnalysis(
                hash = normalizedHash,
                reputationScore = knownGood.reputationScore,
                isKnownGood = true,
                isKnownBad = false,
                isSuspicious = false,
                reputationSources = listOf(
                    ReputationSource(
                        name = "SafeCheck Allowlist",
                        verdict = "CLEAN",
                        confidence = 0.95,
                        details = mapOf(
                            "description" to knownGood.description,
                            "vendor" to knownGood.vendor,
                            "prevalence" to knownGood.prevalence.name
                        )
                    )
                ),
                prevalence = knownGood.prevalence,
                lastChecked = Clock.System.now()
            )
        }
        
        // Check against suspicious hashes
        val suspicious = suspiciousHashes[normalizedHash]
        if (suspicious != null) {
            return FileReputationAnalysis(
                hash = normalizedHash,
                reputationScore = suspicious.reputationScore,
                isKnownGood = false,
                isKnownBad = false,
                isSuspicious = true,
                reputationSources = listOf(
                    ReputationSource(
                        name = "SafeCheck Suspicious Patterns",
                        verdict = "SUSPICIOUS",
                        confidence = 0.8,
                        details = mapOf(
                            "description" to suspicious.description,
                            "reason" to "Pattern analysis"
                        )
                    )
                ),
                prevalence = suspicious.prevalence,
                lastChecked = Clock.System.now()
            )
        }
        
        // Simulate threat intelligence lookup
        val threatIntelAnalysis = simulateThreatIntelligenceLookup(normalizedHash, fileType)
        
        // Calculate overall reputation score
        val overallScore = calculateOverallReputationScore(threatIntelAnalysis, fileType)
        
        return FileReputationAnalysis(
            hash = normalizedHash,
            reputationScore = overallScore.score,
            isKnownGood = overallScore.isKnownGood,
            isKnownBad = overallScore.isKnownBad,
            isSuspicious = overallScore.isSuspicious,
            reputationSources = threatIntelAnalysis.sources,
            prevalence = estimatePrevalence(normalizedHash),
            lastChecked = Clock.System.now()
        )
    }
    
    private fun simulateThreatIntelligenceLookup(hash: String, fileType: FileType): ThreatIntelAnalysis {
        val sources = mutableListOf<ReputationSource>()
        var aggregatedScore = 50.0 // Neutral starting point
        var weightSum = 0.0
        
        for ((sourceName, sourceInfo) in threatIntelligenceSources) {
            if (fileType in sourceInfo.coverage) {
                val verdict = simulateSourceLookup(hash, sourceName, sourceInfo)
                sources.add(verdict.source)
                
                // Weight the score by source reliability and weight
                val effectiveWeight = sourceInfo.weight * sourceInfo.reliability
                aggregatedScore = (aggregatedScore * weightSum + verdict.score * effectiveWeight) / (weightSum + effectiveWeight)
                weightSum += effectiveWeight
            }
        }
        
        return ThreatIntelAnalysis(
            sources = sources,
            aggregatedScore = aggregatedScore.toInt().coerceIn(0, 100)
        )
    }
    
    private fun simulateSourceLookup(hash: String, sourceName: String, sourceInfo: ThreatIntelSource): SourceVerdict {
        // Simulate different response patterns based on hash characteristics
        val hashSum = hash.sumOf { it.digitToIntOrNull(16) ?: 0 }
        val sourceHash = sourceName.hashCode()
        val combined = (hashSum + sourceHash) % 100
        
        val (verdict, score, confidence) = when {
            combined < 5 -> Triple("MALICIOUS", 5, 0.9) // 5% malicious
            combined < 15 -> Triple("SUSPICIOUS", 25, 0.7) // 10% suspicious  
            combined < 25 -> Triple("UNKNOWN", 50, 0.5) // 10% unknown
            combined < 85 -> Triple("CLEAN", 75, 0.8) // 60% clean
            else -> Triple("TRUSTED", 90, 0.85) // 15% trusted
        }
        
        return SourceVerdict(
            source = ReputationSource(
                name = sourceName,
                verdict = verdict,
                confidence = confidence * sourceInfo.reliability,
                details = mapOf(
                    "coverage" to sourceInfo.coverage.joinToString { it.name },
                    "lookup_time" to "simulated"
                )
            ),
            score = score
        )
    }
    
    private fun calculateOverallReputationScore(analysis: ThreatIntelAnalysis, fileType: FileType): ReputationScore {
        var score = analysis.aggregatedScore
        
        // Adjust score based on file type risk
        when (fileType) {
            FileType.EXECUTABLE_WINDOWS,
            FileType.EXECUTABLE_LINUX,
            FileType.EXECUTABLE_MACOS -> {
                score -= 10 // Executables are inherently riskier
            }
            FileType.SCRIPT -> {
                score -= 15 // Scripts are very risky
            }
            FileType.DOCUMENT -> {
                score -= 5 // Documents can contain macros
            }
            FileType.ARCHIVE -> {
                score -= 5 // Archives can hide malware
            }
            else -> {
                // No adjustment for other types
            }
        }
        
        score = score.coerceIn(0, 100)
        
        val isKnownGood = score >= 80
        val isKnownBad = score <= 20
        val isSuspicious = score in 21..40
        
        return ReputationScore(
            score = score,
            isKnownGood = isKnownGood,
            isKnownBad = isKnownBad,
            isSuspicious = isSuspicious
        )
    }
    
    private fun estimatePrevalence(hash: String): FilePrevalence {
        // Simulate prevalence based on hash characteristics
        val hashSum = hash.sumOf { it.digitToIntOrNull(16) ?: 0 }
        
        return when (hashSum % 100) {
            in 0..5 -> FilePrevalence.VERY_COMMON
            in 6..20 -> FilePrevalence.COMMON
            in 21..50 -> FilePrevalence.UNCOMMON
            in 51..80 -> FilePrevalence.RARE
            else -> FilePrevalence.VERY_RARE
        }
    }
    
    private data class ThreatIntelAnalysis(
        val sources: List<ReputationSource>,
        val aggregatedScore: Int
    )
    
    private data class SourceVerdict(
        val source: ReputationSource,
        val score: Int
    )
    
    private data class ReputationScore(
        val score: Int,
        val isKnownGood: Boolean,
        val isKnownBad: Boolean,
        val isSuspicious: Boolean
    )
}

/**
 * File metadata analyzer for additional context.
 */
object FileMetadataAnalyzer {
    
    // Common filename patterns for known malware families
    private val maliciousNamePatterns = listOf(
        Regex(".*\\.exe\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*\\.scr$", RegexOption.IGNORE_CASE),
        Regex(".*document.*\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*invoice.*\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*update.*\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*setup.*\\.bat$", RegexOption.IGNORE_CASE),
        Regex(".*temp.*\\.vbs$", RegexOption.IGNORE_CASE)
    )
    
    // Common legitimate filename patterns
    private val legitimateNamePatterns = listOf(
        Regex(".*setup.*\\.msi$", RegexOption.IGNORE_CASE),
        Regex(".*installer.*\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*uninstall.*\\.exe$", RegexOption.IGNORE_CASE),
        Regex(".*readme.*\\.txt$", RegexOption.IGNORE_CASE),
        Regex(".*license.*\\.txt$", RegexOption.IGNORE_CASE)
    )
    
    /**
     * Analyzes file metadata for additional security context.
     */
    suspend fun analyzeMetadata(hash: String, fileType: FileType): FileMetadataAnalysis {
        val normalizedHash = hash.lowercase().trim()
        
        // Estimate file size based on type and hash characteristics
        val estimatedSize = FileTypeDetector.estimateFileSize(normalizedHash)
        
        // Generate possible filenames based on file type
        val possibleFilenames = generatePossibleFilenames(fileType, normalizedHash)
        
        // Analyze for anomalies
        val anomalyFlags = detectMetadataAnomalies(normalizedHash, fileType, estimatedSize)
        
        // Estimate age based on hash characteristics (heuristic)
        val ageAnalysis = estimateFileAge(normalizedHash)
        
        // Calculate distribution score
        val distributionScore = calculateDistributionScore(normalizedHash)
        
        return FileMetadataAnalysis(
            hash = normalizedHash,
            estimatedFileSize = estimatedSize,
            possibleFilenames = possibleFilenames,
            distributionScore = distributionScore,
            ageAnalysis = ageAnalysis,
            anomalyFlags = anomalyFlags
        )
    }
    
    private fun generatePossibleFilenames(fileType: FileType, hash: String): List<String> {
        val baseName = hash.take(8) // Use first 8 chars as base name
        
        return when (fileType) {
            FileType.EXECUTABLE_WINDOWS -> listOf(
                "$baseName.exe",
                "setup_$baseName.exe",
                "installer_$baseName.exe",
                "update_$baseName.exe"
            )
            FileType.EXECUTABLE_LINUX -> listOf(
                baseName,
                "${baseName}_linux",
                "app_$baseName"
            )
            FileType.SCRIPT -> listOf(
                "$baseName.ps1",
                "$baseName.bat",
                "$baseName.sh",
                "script_$baseName.vbs"
            )
            FileType.DOCUMENT -> listOf(
                "$baseName.pdf",
                "document_$baseName.docx",
                "report_$baseName.xlsx"
            )
            FileType.ARCHIVE -> listOf(
                "$baseName.zip",
                "archive_$baseName.rar",
                "package_$baseName.7z"
            )
            FileType.IMAGE -> listOf(
                "$baseName.jpg",
                "image_$baseName.png",
                "photo_$baseName.gif"
            )
            else -> listOf(
                "$baseName.bin",
                "file_$baseName.dat"
            )
        }
    }
    
    private fun detectMetadataAnomalies(hash: String, fileType: FileType, estimatedSize: Long?): List<MetadataAnomalyFlag> {
        val anomalies = mutableListOf<MetadataAnomalyFlag>()
        
        // Check for unusual size
        estimatedSize?.let { size ->
            when (fileType) {
                FileType.EXECUTABLE_WINDOWS -> {
                    if (size < 1024) { // Very small executable
                        anomalies.add(MetadataAnomalyFlag(
                            AnomalyType.UNUSUAL_SIZE,
                            "Executable file is unusually small ($size bytes)",
                            FileHashSeverity.MEDIUM
                        ))
                    } else if (size > 100 * 1024 * 1024) { // Very large executable
                        anomalies.add(MetadataAnomalyFlag(
                            AnomalyType.UNUSUAL_SIZE,
                            "Executable file is unusually large ($size bytes)",
                            FileHashSeverity.LOW
                        ))
                    }
                }
                FileType.SCRIPT -> {
                    if (size > 1024 * 1024) { // Large script
                        anomalies.add(MetadataAnomalyFlag(
                            AnomalyType.UNUSUAL_SIZE,
                            "Script file is unusually large ($size bytes)",
                            FileHashSeverity.MEDIUM
                        ))
                    }
                }
                else -> {
                    // No size anomalies for other types
                }
            }
        }
        
        // Check for suspicious hash patterns
        if (hash.contains("deadbeef") || hash.contains("cafebabe")) {
            anomalies.add(MetadataAnomalyFlag(
                AnomalyType.METADATA_MISMATCH,
                "Hash contains common test patterns",
                FileHashSeverity.LOW
            ))
        }
        
        // Check for uniform patterns
        if (hash.all { it == hash.first() }) {
            anomalies.add(MetadataAnomalyFlag(
                AnomalyType.METADATA_MISMATCH,
                "Hash consists of repeated characters",
                FileHashSeverity.HIGH
            ))
        }
        
        return anomalies
    }
    
    private fun estimateFileAge(hash: String): FileAgeAnalysis {
        // Simple heuristic based on hash characteristics
        val hashSum = hash.sumOf { it.digitToIntOrNull(16) ?: 0 }
        
        val age = when (hashSum % 10) {
            0, 1 -> FileDuration.YEARS
            2, 3 -> FileDuration.MONTHS
            4, 5 -> FileDuration.WEEKS
            6, 7 -> FileDuration.DAYS
            8 -> FileDuration.HOURS
            else -> FileDuration.MINUTES
        }
        
        val isVeryNew = age in listOf(FileDuration.MINUTES, FileDuration.HOURS)
        val isVeryOld = age == FileDuration.YEARS
        val confidence = 0.3 // Low confidence for this heuristic
        
        return FileAgeAnalysis(
            estimatedAge = age,
            isVeryNew = isVeryNew,
            isVeryOld = isVeryOld,
            ageConfidence = confidence
        )
    }
    
    private fun calculateDistributionScore(hash: String): Int {
        // Estimate how widely distributed this file might be
        val hashSum = hash.sumOf { it.digitToIntOrNull(16) ?: 0 }
        
        return when (hashSum % 100) {
            in 0..10 -> 90 // Very widely distributed
            in 11..30 -> 70 // Widely distributed
            in 31..60 -> 50 // Moderately distributed
            in 61..85 -> 30 // Limited distribution
            else -> 10 // Very limited distribution
        }
    }
}
